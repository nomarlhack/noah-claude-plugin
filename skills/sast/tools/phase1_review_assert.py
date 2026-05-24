#!/usr/bin/env python3
"""
Step 8-1 (동적 분석 정보 요청) 진입 가드.

phase1-review이 모든 후보에 대해 완료되었는지, eval MD 고아 상태가 없는지,
C1 lint (Phase 1 원본 직접 참조) 위반이 없는지 검증한다.

Usage:
  python3 phase1_review_assert.py <master-list.json> <phase1_results_dir>

Exit code (sub-skills/scan-report-review/_contracts.md §2 Exit Code 통일 테이블):
  0: 통과
  1: 평가 미완료 또는 eval MD 고아 상태
  5: C1 lint 실패 (Phase 1 원본 직접 참조 탐지)
  7: 커버리지 감사(§6-A-2) 또는 의무 감사(§2-D, capability 스캐너 능력형 토큰 미처리) 실패. --index-dir 제공 시에만 검사.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


C1_LINT_TARGETS = [
    # 보고서 조립·리뷰의 "다운스트림 소비자" 프롬프트만 검사한다.
    # - ai-discovery-agent.md: ai-discovery.md의 "생산자"이므로 제외
    # - chain-analysis/SKILL.md: master-list.json만 소비, MD 원본 참조 안 함 → 제외
    # - phase2-agent.md: Phase 2 실행 주체로서 Phase 1 원본을 합법 참조 → 제외
    "sub-skills/scan-report/SKILL.md",  # 보고서 조립은 eval MD를 참조
]

# Phase 1 원본 MD만 금지 대상으로 제한 (<scanner>-scanner.md, <scanner-name>.md, ai-discovery.md).
# 변수 플레이스홀더(<...>) 표기도 함께 검사한다.
# 연계 분석 산출물(chain-analysis.md 등)이나 master-list.json은 제외.
# 허용 경로는 별도로 C1_LINT_ALLOWED_PATTERN 에서 명시한다.
C1_LINT_BAD_PATTERN = re.compile(
    r"PHASE1_RESULTS_DIR[^\s\"'`]*/"
    r"(?:<[^>\s/]+>|[a-z0-9_-]+-scanner|ai-discovery)\.md",
    re.IGNORECASE,
)

# 의도된 허용 경로: evaluation/ 하위의 *-eval.md 참조.
# 매치된 violation 후보 중 같은 '라인'에 이 패턴이 함께 있으면 허용으로 간주한다.
C1_LINT_ALLOWED_PATTERN = re.compile(
    r"PHASE1_RESULTS_DIR[^\s\"'`]*/evaluation/[^\s\"'`]+-eval\.md",
    re.IGNORECASE,
)

# 라인에 아래 토큰이 함께 있으면 lint 제외 (의도된 fallback 참조)
C1_LINT_WHITELIST_TOKENS = ("fallback", "부재 시", "화이트리스트", "원본 fallback")

# 커버리지 감사 (§6-A-2): 고볼륨 스캐너는 결과 MD에 COVERAGE 주석으로
# "모든 매치를 설명했다(account for all)"를 증빙해야 한다. 조용한 sampling 누락 방지.
COVERAGE_VOL_THRESHOLD = 200   # 총 매치 이 값 초과 시 감사 필수
COVERAGE_TAINT_THRESHOLD = 50  # taint 매치 이 값 초과 시 전수 ledger 권고 (메시지 강조)
# method 값에 escape된 따옴표(\")가 들어갈 수 있어, 닫는 `" -->`를 앵커로 greedy 매칭한다.
COVERAGE_RE = re.compile(
    r'<!--\s*COVERAGE\s+matches=(\d+)\s+accounted=(\d+)\s+method="(.*)"\s*-->',
    re.IGNORECASE,
)
INCOMPLETE_RE = re.compile(r"\[INCOMPLETE", re.IGNORECASE)

# 의무 감사 (decision-framework §2-D, Safe-by-Proof): exclusion_policy=capability 스캐너는
# 능력형 sink(ast-tier)를 클래스로 뭉개지 못한다. ast 매치 전수가 dispositioned 되어야 한다.
OBLIGATION_RE = re.compile(
    r'<!--\s*OBLIGATION\s+(?:ast_matches|capability_matches)=(\d+)\s+dispositioned=(\d+)\s+method="(.*)"\s*-->',
    re.IGNORECASE,
)
EXCLUSION_POLICY_RE = re.compile(r'^\s*exclusion_policy\s*:\s*([a-z_-]+)', re.MULTILINE)
# capability_via_sink_rule: true → 능력형 매치를 ast 전체가 아니라 `-sink` 고정밀 룰 매치로
# 집계한다(broad-pattern ast 노이즈가 큰 스캐너용 — xss 등). 미설정이면 ast 전체(code-inj/deser).
VIA_SINK_RULE_RE = re.compile(r'^\s*capability_via_sink_rule\s*:\s*true', re.MULTILINE | re.IGNORECASE)
SINK_RULE_ID_RE = re.compile(r'-sink$', re.IGNORECASE)

# 고신뢰-safe tripwire (decision-framework §2-D 원칙 2, rank-don't-drop):
# taint-tier(dataflow가 source→sink+sanitizer부재를 확정한 최고 신뢰)인데 safe로 분류된 후보는
# 가장 위험한 FN(정탐을 안전으로 떨굼)이다. 정당한 사유 카테고리 + 증거 없이는 차단한다.
TAINT_SAFE_JUSTIFIED = {"false_positive", "defense_verified", "platform_default_defense"}


def _candidate_tier(index_dir: Path, scanner: str, file: str, line) -> str | None:
    """후보 file:line의 locindex tier를 조회한다."""
    locindex = index_dir / f"{scanner}.locindex.json"
    if not (file and line and locindex.is_file()):
        return None
    try:
        d = json.loads(locindex.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    meta = d.get("locations", {}).get(f"{file}:{line}")
    if isinstance(meta, dict):
        return meta.get("tier")
    return None


def _taint_safe_tripwire(index_dir: Path, candidates: list) -> list[str]:
    """taint-tier 확정 흐름인데 safe로 분류된 후보가 정당한 입증을 갖췄는지 검증.

    taint는 §1에서 자동 후보다. 그것이 safe가 되는 정당한 경우는 (a) 룰이 sink 의미론을
    잘못 매치(false_positive), (b) 룰이 모델링 못 한 sanitizer 존재(defense_verified),
    (c) 플랫폼 기본 방어(platform_default_defense)뿐이며, 각각 사유/증거가 필요하다.
    그 외(no_external_path 등 taint와 모순되는 카테고리, 사유 부재)는 FN 의심 → 차단.
    """
    violations: list[str] = []
    for c in candidates:
        is_safe = c.get("status") == "safe" or not c.get("phase1_validated")
        if not is_safe:
            continue
        scanner = c.get("scanner", "")
        if not scanner or scanner == "ai-discovery":
            continue
        tier = _candidate_tier(index_dir, scanner, c.get("file"), c.get("line"))
        if tier != "taint":
            continue
        cat = c.get("safe_category")
        has_reason = bool(c.get("phase1_discarded_reason")) or bool(c.get("verified_defense"))
        if cat not in TAINT_SAFE_JUSTIFIED or not has_reason:
            violations.append(
                f"{c.get('id')} ({scanner}): taint-tier 확정 흐름인데 safe 분류 — "
                f"safe_category={cat!r}, 사유/verified_defense={'있음' if has_reason else '없음'}. "
                f"taint→safe는 false_positive/defense_verified/platform_default_defense + 증거만 정당 (FN 의심)"
            )
    return violations


def _scanner_exclusion_policy(scanners_root: Path, scanner: str) -> str | None:
    """스캐너 phase1.md frontmatter의 exclusion_policy 태그를 읽는다."""
    md = scanners_root / scanner / "phase1.md"
    if not md.is_file():
        return None
    head = md.read_text(encoding="utf-8", errors="replace")[:600]
    m = EXCLUSION_POLICY_RE.search(head)
    return m.group(1) if m else None


def _count_sink_matches(locations: dict) -> int:
    """rule_ids에 `-sink` 고정밀 능력형 룰을 포함하는 위치 수."""
    n = 0
    for meta in locations.values():
        if isinstance(meta, dict) and any(SINK_RULE_ID_RE.search(r) for r in meta.get("rule_ids", [])):
            n += 1
    return n


def _obligation_audit(
    index_dir: Path, phase1_dir: Path, scanners_root: Path, analyzed: set[str]
) -> list[str]:
    """capability 정책 스캐너가 능력형 매치를 전수 disposition 했는지 검증.

    능력형 매치 수(target)는 locindex를 진실값으로 사용한다(에이전트 선언값에 의존하지 않아
    과소신고 우회 불가). 두 모드:
    - 기본(code-inj/deser): ast-tier 전체가 능력형 → target = tier_counts.ast
    - `capability_via_sink_rule: true`(xss 등 broad-pattern 노이즈 스캐너): target = `-sink`
      고정밀 룰 매치 수만 (ast 노이즈 제외). 0이면 능력형 sink 없음 → 의무 대상 아님.
    클래스 일괄 제외로 위험 토큰을 조용히 누락하는 FN(실측: PHP eval→"클라JS")을 차단한다.
    """
    violations: list[str] = []
    for scanner in sorted(analyzed):
        md_fm = scanners_root / scanner / "phase1.md"
        if _scanner_exclusion_policy(scanners_root, scanner) != "capability":
            continue
        locindex = index_dir / f"{scanner}.locindex.json"
        if not locindex.is_file():
            continue
        try:
            d = json.loads(locindex.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        via_sink = bool(md_fm.is_file() and VIA_SINK_RULE_RE.search(
            md_fm.read_text(encoding="utf-8", errors="replace")[:600]))
        if via_sink:
            target = _count_sink_matches(d.get("locations", {}))
            target_desc = f"{target} 고정밀 sink"
        else:
            target = int(d.get("_scanner", {}).get("tier_counts", {}).get("ast", 0))
            target_desc = f"{target} ast 능력형"
        if target == 0:
            continue  # 능력형 매치 없으면 의무 대상 아님
        md = phase1_dir / f"{scanner}.md"
        if not md.is_file():
            violations.append(f"{scanner}: capability 정책인데 결과 MD 부재 ({target_desc})")
            continue
        text = md.read_text(encoding="utf-8", errors="replace")
        m = OBLIGATION_RE.search(text)
        if not m:
            violations.append(
                f"{scanner}: capability 정책 + 능력형 매치 {target_desc}건인데 "
                f"OBLIGATION 마커 부재 — 능력형 토큰 클래스 일괄 제외 위험 (§2-D)"
            )
            continue
        declared = int(m.group(1))
        dispositioned = int(m.group(2))
        if declared < target:
            violations.append(
                f"{scanner}: OBLIGATION 선언={declared} < locindex 능력형={target} "
                f"(과소신고) — 능력형 매치 누락"
            )
            continue
        if dispositioned < target and not INCOMPLETE_RE.search(text):
            violations.append(
                f"{scanner}: OBLIGATION dispositioned={dispositioned} < 능력형={target}, "
                f"[INCOMPLETE] 표기도 없음 — 능력형 매치 {target - dispositioned}건 미처리 (조용한 누락)"
            )
    return violations


def _coverage_audit(index_dir: Path, phase1_dir: Path, analyzed: set[str]) -> list[str]:
    """분석된 고볼륨 스캐너가 커버리지 감사를 갖췄는지 검증.

    실제 총 매치 수는 locindex `_scanner.tier_counts` 합을 진실값으로 사용한다
    (에이전트가 선언한 matches에 의존하지 않아 과소신고로 우회 불가).
    """
    violations: list[str] = []
    for scanner in sorted(analyzed):
        locindex = index_dir / f"{scanner}.locindex.json"
        if not locindex.is_file():
            continue
        try:
            d = json.loads(locindex.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        tc = d.get("_scanner", {}).get("tier_counts", {})
        total = sum(int(v) for v in tc.values())
        if total <= COVERAGE_VOL_THRESHOLD:
            continue
        taint = int(tc.get("taint", 0))
        md = phase1_dir / f"{scanner}.md"
        if not md.is_file():
            violations.append(
                f"{scanner}: 고볼륨({total}건)인데 분석 결과 MD 부재"
            )
            continue
        text = md.read_text(encoding="utf-8", errors="replace")
        m = COVERAGE_RE.search(text)
        if not m:
            violations.append(
                f"{scanner}: 고볼륨({total}건, taint={taint})인데 COVERAGE 감사 주석 부재 "
                f"— 조용한 누락 위험 (§6-A-2)"
            )
            continue
        accounted = int(m.group(2))
        if accounted < total and not INCOMPLETE_RE.search(text):
            extra = " [taint 고신뢰 — 전수 ledger 필요]" if taint > COVERAGE_TAINT_THRESHOLD else ""
            violations.append(
                f"{scanner}: COVERAGE accounted={accounted} < 실제 총매치={total}, "
                f"[INCOMPLETE] 표기도 없음 — 미설명 {total - accounted}건 (조용한 누락){extra}"
            )
    return violations


def _file_sha256(path: Path) -> str:
    if not path.is_file():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _extract_eval_md_source_hash(eval_md: Path) -> str | None:
    if not eval_md.is_file():
        return None
    text = eval_md.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"<!-- SOURCE_HASH:\s*sha256:([0-9a-f]+)\s*-->", text)
    return m.group(1) if m else None


def _c1_lint(skills_root: Path) -> list[str]:
    violations: list[str] = []
    for rel in C1_LINT_TARGETS:
        target = skills_root / rel
        if not target.is_file():
            continue
        text = target.read_text(encoding="utf-8", errors="replace")
        for m in C1_LINT_BAD_PATTERN.finditer(text):
            # 화이트리스트: 같은 라인에 fallback 토큰이 있으면 의도된 참조로 제외
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end]
            if any(tok in line for tok in C1_LINT_WHITELIST_TOKENS):
                continue
            # 허용 경로(evaluation/*-eval.md)가 같은 매치 지점이면 제외.
            # 같은 라인에 허용 경로와 금지 경로가 공존할 수 있으므로, 매치 자체가 허용 패턴에
            # 해당하는지 확인한다.
            if C1_LINT_ALLOWED_PATTERN.fullmatch(m.group(0)):
                continue
            violations.append(f"{rel}: {m.group(0)}")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("master_list")
    parser.add_argument("phase1_dir")
    parser.add_argument(
        "--skip-lint",
        action="store_true",
        help="C1 lint를 건너뛴다 (개발 시 임시 사용).",
    )
    parser.add_argument(
        "--index-dir",
        default=None,
        help="locindex 디렉토리. 제공 시 고볼륨 스캐너 커버리지 감사(§6-A-2)를 검사한다.",
    )
    args = parser.parse_args()

    master_list = Path(args.master_list)
    phase1_dir = Path(args.phase1_dir)
    eval_dir = phase1_dir / "evaluation"

    with master_list.open() as f:
        m = json.load(f)
    candidates = m.get("candidates", [])
    if not candidates:
        print("FAIL: candidates 배열이 비어 있음")
        return 1

    # 1) 모든 후보에 phase1_validated 필드 존재 (하위 호환: 부재 시 false)
    missing_validated = [
        c["id"]
        for c in candidates
        if not c.get("phase1_validated")
        and c.get("status") != "safe"  # Source 도달성 폐기로 safe 처리된 건 예외
    ]
    if missing_validated:
        print(
            f"FAIL: {len(missing_validated)}개 후보의 phase1_validated=false: "
            f"{missing_validated[:10]}"
            f"{' ...' if len(missing_validated) > 10 else ''}"
        )
        print("phase1-review이 완료되지 않았거나 갱신에 실패했다.")
        return 1

    # 2) eval MD 파일 존재 + 해시 일치 (§12-G)
    orphan: list[str] = []
    hash_mismatch: list[str] = []
    for c in candidates:
        if not c.get("phase1_validated"):
            continue  # safe 분류된 건 eval MD 불요
        scanner = c.get("scanner", "")
        if not scanner:
            continue
        eval_md = eval_dir / f"{scanner}-eval.md"
        if not eval_md.is_file():
            orphan.append(c["id"])
            continue
        phase1_md = phase1_dir / f"{scanner}.md"
        if phase1_md.is_file():
            actual_hash = _file_sha256(phase1_md)
            recorded_hash = _extract_eval_md_source_hash(eval_md)
            if recorded_hash and actual_hash and recorded_hash != actual_hash:
                hash_mismatch.append(c["id"])

    if orphan:
        print(f"FAIL: {len(orphan)}개 후보의 eval MD 파일 부재(고아): {orphan[:10]}")
        return 1
    if hash_mismatch:
        print(
            f"FAIL: {len(hash_mismatch)}개 후보의 eval MD SOURCE_HASH가 Phase 1 원본과 불일치: "
            f"{hash_mismatch[:10]}"
        )
        print("Phase 1 MD가 변경되었거나 eval MD가 구버전이다. phase1-review 재호출 필요.")
        return 1

    # 3) C1 lint: Phase 1 원본 직접 참조 금지 (checklist §12-H)
    if not args.skip_lint:
        skills_root = Path(__file__).resolve().parent.parent
        violations = _c1_lint(skills_root)
        if violations:
            print(f"FAIL: C1 lint 위반 {len(violations)}건:")
            for v in violations[:20]:
                print(f"  {v}")
            print("Phase 1 원본 직접 참조 금지. evaluation/*-eval.md로 전환하라.")
            return 5

    # 4) 커버리지 감사 (§6-A-2) + 의무 감사 (§2-D): --index-dir 제공 시에만.
    if args.index_dir:
        index_dir = Path(args.index_dir)
        skills_root = Path(__file__).resolve().parent.parent
        scanners_root = skills_root / "scanners"
        analyzed = {c.get("scanner", "") for c in candidates if c.get("scanner")}
        analyzed |= {s for s in m.get("clean_scanners", []) if s}
        cov_violations = _coverage_audit(index_dir, phase1_dir, analyzed)
        if cov_violations:
            print(f"FAIL: 커버리지 감사 위반 {len(cov_violations)}건 (고볼륨 스캐너 §6-A-2):")
            for v in cov_violations[:20]:
                print(f"  {v}")
            print(
                "고볼륨 스캐너는 결과 MD에 "
                "`<!-- COVERAGE matches=<총> accounted=<설명> method=\"...\" -->` 주석으로 "
                "모든 매치를 설명해야 한다(account for all). 클래스 단위 제외도 설명에 포함."
            )
            return 7
        obl_violations = _obligation_audit(index_dir, phase1_dir, scanners_root, analyzed)
        if obl_violations:
            print(f"FAIL: 의무 감사 위반 {len(obl_violations)}건 (capability 스캐너 §2-D):")
            for v in obl_violations[:20]:
                print(f"  {v}")
            print(
                "capability 정책 스캐너는 결과 MD에 "
                "`<!-- OBLIGATION ast_matches=<ast수> dispositioned=<처리수> method=\"...\" -->` 주석으로 "
                "능력형(ast-tier) 매치 전수를 disposition 해야 한다. 능력형 토큰 클래스 일괄 제외 금지."
            )
            return 7
        trip_violations = _taint_safe_tripwire(index_dir, candidates)
        if trip_violations:
            print(f"FAIL: 고신뢰-safe tripwire 위반 {len(trip_violations)}건 (§2-D 원칙 2):")
            for v in trip_violations[:20]:
                print(f"  {v}")
            print(
                "taint-tier 확정 흐름을 safe로 분류하려면 정당한 사유(false_positive/defense_verified/"
                "platform_default_defense) + 증거(phase1_discarded_reason 또는 verified_defense)가 필요하다. "
                "그 외는 정탐 누락(FN) 의심 — phase1-review 재검토."
            )
            return 7

    # 통과 요약
    dist = {"SAFE": 0, "VALIDATED": 0}
    for c in candidates:
        if c.get("status") == "safe":
            dist["SAFE"] += 1
        elif c.get("phase1_validated"):
            dist["VALIDATED"] += 1
    cov_note = " 커버리지+의무 감사 통과," if args.index_dir else ""
    print(
        f"OK: phase1_validated 완결, eval MD 해시 일치, C1 lint 통과,{cov_note} "
        f"분포 {dist}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
