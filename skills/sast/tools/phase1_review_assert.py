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
  7: 감사군 위반(--index-dir 제공 시에만 검사). 커버리지(§6-A-2)·의무(§2-D)·고신뢰-safe tripwire·
     IDOR FN 방지 게이트(session-override 미등록 / 무인증 중첩 자원 미해소) 중 하나.
     조치는 위반 유형별 출력 메시지를 따른다.
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

# session-override 등록 감사: 고신뢰 신원-폴백 룰(클라이언트↔세션 elvis/ternary) 매치는
# 반드시 후보로 등록(또는 명시 폐기)돼야 한다. 매치가 어떤 후보와도 대응되지 않으면
# 예산 압박 등으로 조용히 누락되는 FN이다(고정밀 시그널이라 미등록 시 차단). 룰 id는 언어 불문 공통 접미사.
SESSION_OVERRIDE_RULE_RE = re.compile(r'idor-session-identity-override')
SESSION_OVERRIDE_WINDOW = 20  # 매치 라인과 후보 라인 간 허용 오프셋(메서드 본문 크기)

# 파일 단위 disposition 감사 (FILE-PRESENCE): 결정/방어 계열 스캐너는 ast/generic 매치를
# 클래스 일괄 제외로 뭉개지 못한다. 이 계열은 sink가 분석 범위 밖이거나 결함이 "오염 데이터
# 도달"이 아니라 "방어 결정 자체의 오류"인 경우가 흔해 taint로 표현되지 않는다. 그러면 §6-A-2가
# 일괄 제외를 허용하는 ast/generic 칸에 진짜 취약점이 숨고 파일명조차 MD에 안 남은 채 흡수된다.
# 따라서 인덱스가 매치한 파일 수(files)와 에이전트가 개별 명시한 파일 수(accounted)가
# FILE_PRESENCE 주석으로 증빙돼야 한다. COVERAGE/OBLIGATION과 동일한 숫자 기반 강제 구조.
# 게이트는 "이름조차 안 적고 묶어 사라지는 것"만 기계적으로 막는다.
FILE_PRESENCE_RE = re.compile(
    r'<!--\s*FILE_PRESENCE\s+files=(\d+)\s+accounted=(\d+)\s+method="(.*)"\s*-->',
    re.IGNORECASE,
)
DECISION_DEFENSE_SCANNERS = {
    "ssrf-scanner", "open-redirect-scanner", "path-traversal-scanner",
    "ssti-scanner", "idor-scanner", "business-logic-scanner",
    "validation-logic-scanner", "host-header-scanner", "csrf-scanner",
    "file-upload-scanner", "xxe-scanner", "command-injection-scanner",
    "code-injection-scanner", "deserialization-scanner", "xpath-injection-scanner",
    "ldap-injection-scanner", "prototype-pollution-scanner", "pdf-generation-scanner",
}

# 무인증 중첩 자원 등록 감사 (session-override와 공통 계약: IDOR FN 미등록 차단):
# idor_inventory.py 인벤토리에서 인증 미경유(`[제외]`) + path-variable 2개 이상
# (중첩 자원 `/{parent}/.../{child}`) 진입점이 [검증](안전)으로 닫히지도 master-list에 등록되지도
# 않으면(즉 [미확인]/[부재]/[부분] + 미등록), 상위↔하위 식별자 매핑 미검증 BOLA의 조용한 누락이다.
# phase1.md §159("인증 미경유 [미확인] 종결 금지")의 기계적 최소 강제선(floor) —
# 트리거를 중첩(≥2)으로 좁혀 [제외] 전체(저신호 대량)가 아닌 고신호 슬라이스만 강제한다.
INVENTORY_HEADER_RE = re.compile(r'###\s*IDOR\s*검토\s*인벤토리')
NESTED_MIN_PATHVARS = 2
AUTH_EXCLUDED_TOKEN = "[제외]"
GATE_UNVERIFIED_TOKEN = "[미확인]"
GATE_SAFE_TOKEN = "[검증]"  # 안전 판정만 인벤토리 텍스트로 해소 인정 ([부재]/[부분]은 등록 요구)


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


# --- IDOR FN 방지 게이트 (고신뢰 시그널 미등록 차단) — 공유 커버리지 계약 ---
# 두 게이트(_session_override_audit, _unauth_nested_resource_audit)가 동일한 "위치가
# master-list 후보와 라인 근접하는가"(register-or-discard) 의미를 공유한다. file 매칭 방식만
# 시그널별로 다르므로(전체 경로 동일 vs basename 접미사) predicate로 주입한다.
def _same_file_path(a: str, b: str) -> bool:
    """경로 포맷(절대/상대) 무관 동일 파일 판정: 한쪽이 다른 쪽의 경로-suffix(컴포넌트 경계)면 동일.

    locindex는 절대경로, master-list 후보 file은 상대경로일 수 있다(build_master_list 출력).
    정확매칭(`a == b`)에 의존하면 포맷 차이만으로 누락 감사가 거짓 발화한다 —
    _unauth_nested_resource_audit과 동일한 경로-견고 매칭을 공유해 재빌드/포맷에 안정적으로 만든다.
    """
    if not a or not b:
        return False
    a2, b2 = a.lstrip("/"), b.lstrip("/")
    return a2 == b2 or a2.endswith("/" + b2) or b2.endswith("/" + a2)


def _near_candidate(candidates: list, file_pred, line: int,
                    window: int = SESSION_OVERRIDE_WINDOW) -> bool:
    """후보 중 file_pred(file)이 참이고 |line - 후보라인| <= window 인 것이 있으면 True."""
    for c in candidates:
        f = c.get("file")
        ln = c.get("line")
        if f and isinstance(ln, int) and file_pred(f) and abs(ln - line) <= window:
            return True
    return False


def _parse_location(loc: str):
    """'<파일>:<라인>' 형태를 (basename, line)으로 분해한다. 파싱 실패 시 (None, None)."""
    if not loc:
        return None, None
    try:
        path, lpart = loc.rsplit(":", 1)
        line = int(lpart.strip())
    except ValueError:
        return None, None
    return path.strip().split("/")[-1], line


def _count_path_vars(endpoint: str) -> int:
    """엔드포인트 경로의 path-variable 개수를 프레임워크 비종속으로 센다.

    세그먼트가 변수 표기면 카운트: `{var}`(Spring/FastAPI/chi) · `<var>`/`<int:var>`(Flask/Django) ·
    `:var`(Express/Rails/Gin/Echo) · `(?P<var>...)`(Django regex). 라우트 문법에 의존하지 않도록
    세 표기를 모두 인식한다(특정 프레임워크/프로젝트에 편향되지 않게).
    """
    parts = endpoint.strip().split(None, 1)
    path = parts[1] if len(parts) == 2 and parts[0].isalpha() else endpoint
    n = 0
    for seg in path.split("/"):
        seg = seg.strip()
        if not seg:
            continue
        if (seg[0] == "{" and seg[-1] == "}") \
           or (seg[0] == "<" and seg[-1] == ">") \
           or (seg[0] == "(" and "<" in seg) \
           or (seg[0] == ":" and len(seg) > 1):
            n += 1
    return n


def _session_override_audit(index_dir: Path, candidates: list) -> list[str]:
    """고신뢰 session-identity-override 룰 매치가 후보로 등록됐는지 검증(조용한 누락 차단).

    이 룰(①)은 '클라이언트 입력 ↔ 세션 입력' 신원 폴백이라는 고정밀 IDOR 시그널이다.
    매치가 master-list 후보 중 어디에도 대응되지 않으면(같은 파일 + 라인 근접) 등록 누락 →
    예산 압박 등으로 조용히 사라지는 FN이다. 등록 여부만 검증한다(safe 정당성은
    _taint_safe_tripwire가 별도 검증). 후보 file/line 표현은 _candidate_tier와 동일 계약.
    """
    locindex = index_dir / "idor-scanner.locindex.json"
    if not locindex.is_file():
        return []
    try:
        d = json.loads(locindex.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    violations: list[str] = []
    for loc, meta in d.get("locations", {}).items():
        if not isinstance(meta, dict):
            continue
        if not any(SESSION_OVERRIDE_RULE_RE.search(r) for r in meta.get("rule_ids", [])):
            continue
        try:
            fpart, lpart = loc.rsplit(":", 1)
            oline = int(lpart)
        except ValueError:
            continue
        # 경로-견고 매칭(절대/상대 무관): locindex loc는 절대, 후보 file은 상대일 수 있다.
        if not _near_candidate(candidates, lambda f, fp=fpart: _same_file_path(f, fp), oline):
            violations.append(
                f"{loc}: session-identity-override 고신뢰 매치인데 대응 후보 없음 — "
                f"클라이언트↔세션 신원 폴백 IDOR가 후보 등록 없이 누락됨(FN). "
                f"후보로 등록하거나 명시 폐기(사유 기재)하라"
            )
    return violations


def _find_inventory_text(phase1_dir: Path):
    """idor_inventory.py 인벤토리(`### IDOR 검토 인벤토리`)를 담은 파일 텍스트를 찾는다.

    idor-scanner.md(임베드) 우선, 그다음 _idor_inventory*.{md,txt}(별도 저장). 미발견 시 None.
    """
    cands: list[Path] = []
    p = phase1_dir / "idor-scanner.md"
    if p.is_file():
        cands.append(p)
    cands += sorted(phase1_dir.glob("_idor_inventory*.md"))
    cands += sorted(phase1_dir.glob("_idor_inventory*.txt"))
    for f in cands:
        try:
            t = f.read_text(encoding="utf-8")
        except OSError:
            continue
        if INVENTORY_HEADER_RE.search(t):
            return t
    return None


def _parse_inventory_rows(text: str):
    """인벤토리 표를 파싱. 헤더명 기준 컬럼 매핑(순서 변경 내성). (col_map, rows) 반환.

    파일 단위 체크리스트 포맷(파일별 `#### <파일>` 섹션 + 섹션마다 표 헤더 반복)과
    단일 표 포맷을 모두 처리한다: `|`로 시작하지 않는 줄(`####`·빈 줄·설명)은 건너뛰고,
    표 헤더를 만날 때마다 컬럼 매핑을 갱신하며, 데이터 행을 누적한다(조기 종료 없음).
    """
    col = None
    rows: list[list[str]] = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s.startswith("|"):
            continue  # #### 파일 헤더 / 빈 줄 / 설명 → 무시 (다중 파일 섹션 허용)
        cells = [c.strip() for c in s.strip("|").split("|")]
        if "엔드포인트" in s and "인증" in s and "소유권게이트" in s:
            col = {}
            for i, c in enumerate(cells):
                if "엔드포인트" in c:
                    col["endpoint"] = i
                elif "위치" in c:
                    col["loc"] = i
                elif "출처" in c:
                    col["det"] = i
                elif "인증" in c:
                    col["auth"] = i
                elif "소유권게이트" in c:
                    col["gate"] = i
            continue
        if col is None:
            continue  # 표 시작 전
        if cells and set("".join(cells)) <= set("-: "):
            continue  # |---|---| 구분 행
        rows.append(cells)
    return col, rows


def _unauth_nested_resource_audit(phase1_dir: Path, candidates: list) -> list[str]:
    """무인증 직접 객체참조(중첩 path-var≥2, 또는 단일 path-var+taint)가 안전 확정·등록 없이
    ([검증] 아님 + 미등록) 방치됐는지 검증(BOLA/IDOR 조용한 누락 차단).

    대상 path-var 정책(공개 카탈로그 오탐 회피):
    - path-var≥2(중첩 자원 `/{parent}/.../{child}`): 구조 신호만으로 강제. 상위↔하위
      식별자 매핑 미검증은 그 자체로 BOLA 신호.
    - path-var==1(단일 객체참조 `/{id}`): 단일 ID 무인증 조회는 IDOR의 표준형이나 공개
      카탈로그(`/products/{id}` 등)도 많아, 인벤토리 `출처`에 고정밀 taint(missing-owner-gate
      흐름)가 있을 때만 강제한다. scan-only 약신호와 path-var==0(객체참조 아님)은 제외.

    session-override(①)와 공통 계약이나 입력 소스가 다르다: auth=[제외] 신호는
    excludePathPatterns(교차 파일 설정) 기반이라 locindex(semgrep)에 없고 인벤토리 도구만
    계산하므로 인벤토리 MD를 읽는다. 해소 인정(OR): 인벤토리 소유권게이트가 [검증](안전 판정)이거나
    master-list에 등록. [부재]/[부분](취약/부분 판정)·[미확인]은 등록 없이는 미해소로 본다
    (phase1.md "[부재]→후보 승격" 및 _session_override_audit과 일관 — 미등록 발견은 보고서 누락).
    """
    text = _find_inventory_text(phase1_dir)
    if not text:
        return []
    col, rows = _parse_inventory_rows(text)
    if not col or "endpoint" not in col or "auth" not in col or "gate" not in col:
        return []

    def cell(cells: list[str], key: str) -> str:
        i = col.get(key)
        return cells[i] if i is not None and i < len(cells) else ""

    violations: list[str] = []
    for cells in rows:
        auth = cell(cells, "auth")
        endpoint = cell(cells, "endpoint")
        gate = cell(cells, "gate")
        loc = cell(cells, "loc")
        if AUTH_EXCLUDED_TOKEN not in auth:
            continue
        pv = _count_path_vars(endpoint)
        det = cell(cells, "det")
        is_taint = "taint" in det.lower()
        # pv>=2(중첩 자원): 구조 신호만으로 강제. pv==1(단일 객체참조): 공개 카탈로그 오탐을
        # 피하기 위해 고정밀 missing-owner-gate 흐름(출처=taint)이 있을 때만 강제. pv==0(객체참조
        # 아님)·pv==1 scan-only(약신호)는 제외.
        if not (pv >= NESTED_MIN_PATHVARS or (pv == 1 and is_taint)):
            continue
        # 안전 판정([검증])만 인벤토리 텍스트로 해소 인정한다. [미확인](미판정)·[부재]·[부분]
        # (취약/부분 판정)은 phase1.md "[부재]→후보 승격" 정책 및 sibling _session_override_audit과
        # 일관되게 master-list 등록을 요구한다 — 등록 없이 [부재]만 적으면 보고서에서 누락(FN)된다.
        if GATE_SAFE_TOKEN in gate:
            continue  # 안전 판정 → 후보 등록 불요
        base, line = _parse_location(loc)
        if line is not None and _near_candidate(
            candidates,
            lambda f, b=base: bool(b) and (f == b or f.endswith("/" + b) or f.split("/")[-1] == b),
            line,
        ):
            continue  # master-list 등록으로 해소됨
        state = "미판정([미확인])" if GATE_UNVERIFIED_TOKEN in gate else f"취약 판정({gate})"
        kind = (f"중첩 자원(path-var {pv}≥2)" if pv >= NESTED_MIN_PATHVARS
                else "단일 객체참조(path-var 1, 출처=taint)")
        violations.append(
            f"{endpoint} ({loc}): 무인증(`[제외]`) {kind}인데 "
            f"소유권게이트 {state} + master-list 미등록 — 직접 객체참조 소유권 미검증 BOLA/IDOR 누락(FN). "
            f"안전이면 [검증] 확정, 취약/미판정이면 후보 등록하라"
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
    클래스 일괄 제외로 위험 토큰을 조용히 누락하는 FN을 차단한다.
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


def _file_disposition_audit(
    index_dir: Path, phase1_dir: Path, analyzed: set[str]
) -> list[str]:
    """결정/방어 스캐너: FILE_PRESENCE 주석으로 파일 전수 명시를 증빙했는지 검증 (FILE-PRESENCE).

    COVERAGE/OBLIGATION과 동일한 구조:
      <!-- FILE_PRESENCE files=<총파일수> accounted=<명시한파일수> method="..." -->
    files = locindex distinct 파일 수 (스크립트가 직접 계산 — 에이전트 선언 불신).
    accounted = 에이전트가 개별 명시했다고 선언한 파일 수.
    accounted < files이면 조용한 누락 → FAIL.
    """
    violations: list[str] = []
    for scanner in sorted(analyzed):
        if scanner not in DECISION_DEFENSE_SCANNERS:
            continue
        locindex = index_dir / f"{scanner}.locindex.json"
        if not locindex.is_file():
            continue
        try:
            d = json.loads(locindex.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        total_files = len({k.rsplit(":", 1)[0] for k in d.get("locations", {})})
        if total_files == 0:
            continue
        md = phase1_dir / f"{scanner}.md"
        if not md.is_file():
            violations.append(
                f"{scanner}: 결정/방어 스캐너인데 결과 MD 부재 (FILE-PRESENCE)"
            )
            continue
        md_text = md.read_text(encoding="utf-8", errors="replace")
        m = FILE_PRESENCE_RE.search(md_text)
        if not m:
            violations.append(
                f"{scanner}: FILE_PRESENCE 주석 부재 (FILE-PRESENCE) — "
                f"인덱스 매치 파일 {total_files}건. "
                f'결과 MD에 `<!-- FILE_PRESENCE files={total_files} accounted=<N> method="..." -->`'
                f" 주석으로 전수 명시를 증빙하라."
            )
            continue
        accounted = int(m.group(2))
        if accounted < total_files and not INCOMPLETE_RE.search(md_text):
            violations.append(
                f"{scanner}: FILE_PRESENCE accounted={accounted} < "
                f"실제 파일={total_files}, [INCOMPLETE] 표기도 없음 — "
                f"미명시 {total_files - accounted}건 (조용한 누락)"
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
    if not args.index_dir:
        print(
            "WARNING: --index-dir 미제공 — 커버리지·FN방지·taint-safe 감사가 생략됩니다.\n"
            "  다음 명령으로 전체 감사를 실행하세요:\n"
            "    python3 phase1_review_assert.py <master_list> <phase1_dir> --index-dir <PATTERN_INDEX_DIR>",
            file=sys.stderr,
        )
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
        so_violations = _session_override_audit(index_dir, candidates)
        if so_violations:
            print(f"FAIL: session-override 등록 감사 위반 {len(so_violations)}건 (고신뢰 IDOR 누락):")
            for v in so_violations[:20]:
                print(f"  {v}")
            print(
                "session-identity-override 룰은 클라이언트↔세션 신원 폴백이라는 고정밀 IDOR 시그널이다. "
                "모든 매치를 후보로 등록하거나, 후보 폐기 시 사유를 기재하라(조용한 누락 금지)."
            )
            return 7
        nested_violations = _unauth_nested_resource_audit(phase1_dir, candidates)
        if nested_violations:
            print(f"FAIL: 무인증 직접 객체참조 미해소 {len(nested_violations)}건 (BOLA/IDOR 누락):")
            for v in nested_violations[:20]:
                print(f"  {v}")
            print(
                "인증 미경유(`[제외]`) 진입점 중 (a) path-variable 2개 이상(중첩 자원, 상위↔하위 "
                "매핑 미검증) 또는 (b) path-variable 1개 + 출처=taint(missing-owner-gate 흐름, 단일 "
                "객체 IDOR)는 소유권 미강제 시 BOLA/IDOR다. 이는 phase1.md §159 '인증 미경유 [미확인] "
                "종결 금지'의 최소 강제선(floor)이다 — service Read로 [검증]/[부재] 확정 후 후보 "
                "등록 또는 status=safe+safe_category 기재. ([제외] 행 전체의 §159 의무는 동일하게 유효.)"
            )
            return 7
        fd_violations = _file_disposition_audit(index_dir, phase1_dir, analyzed)
        if fd_violations:
            print(f"FAIL: 파일단위 disposition 위반 {len(fd_violations)}건 (결정/방어 스캐너 FILE-PRESENCE):")
            for v in fd_violations[:20]:
                print(f"  {v}")
            print(
                "결정/방어 스캐너는 ast/generic 매치를 클래스로 뭉개지 못한다. 이 계열은 sink가 "
                "분석 범위 밖이거나 결함이 '방어 결정 자체의 오류'라 taint로 표현되지 않는 경우가 "
                "흔해, 일괄 제외가 허용되는 칸에 진짜 취약점이 숨는다. 인덱스가 매치한 *모든 파일*은 "
                "각각 결과 MD에 파일명을 적고 개별 disposition(후보/안전/무관 + 근거)하라 — 경로/내용 "
                "패턴으로 미리 거르지 말고 파일명만 빠짐없이 남겨라. 비용은 매치 수가 아니라 파일 수다."
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
