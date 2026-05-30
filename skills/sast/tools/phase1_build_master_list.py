#!/usr/bin/env python3
"""
Phase 1 결과 파일(markdown + manifest)에서 후보 메타데이터를 추출하여
master-list.json을 생성한다.

Usage:
  phase1_build_master_list.py <phase1_dir> <output_json> [--merge]

옵션:
  --merge: 기존 master-list.json이 존재하면 각 후보 id 기준으로 병합.
           phase2-review 결과 필드(status, tag, evidence_summary, verified_defense,
           rederivation_performed, safe_category, phase1_*, phase1_eval_state)를
           보존하고, Phase 1 파싱은 새로 수행한다. 사라진 후보는 삭제,
           신규 후보는 추가, 동명 후보는 메타데이터만 갱신 + phase2-review 필드 보존.

검증 기능:
- manifest JSON 파싱 실패 시 ERROR
- manifest declared_count와 실제 candidates 수 불일치 시 ERROR
- manifest ID와 prose ## <ID>: 헤더 불일치 시 ERROR
- 필수 섹션(Code, Source→Sink Flow 등) 누락/빈약 시 WARNING
- 동일 file:line 후보 자동 그룹핑 (DUPLICATE SINK)
"""
import argparse
import re
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

parser = argparse.ArgumentParser()
parser.add_argument("phase1_dir")
parser.add_argument("output_json")
parser.add_argument(
    "--merge",
    action="store_true",
    help="기존 master-list.json이 존재하면 phase2-review 결과 필드를 보존하며 병합",
)
args = parser.parse_args()

phase1_dir = Path(args.phase1_dir)
out_path = Path(args.output_json)

# 병합 모드: 기존 master-list.json 로드 (phase2-review 결과 보존용)
EVAL_FIELDS = {
    "status", "tag", "evidence_summary", "verified_defense", "rederivation_performed",
    "safe_category", "phase1_validated", "phase1_discarded_reason", "phase1_eval_state",
}
existing_by_id = {}
# 게이트/외부 추가 후보(소스 MD에 없음)는 재빌드 시 통째로 보존한다. `manual_addition: true`
# 플래그가 있는 후보만 보존 — 플래그 없는 고아(=진짜 누락)는 보존하지 않아 "재생성 가능" 안전성 유지.
manual_additions = {}
if args.merge and out_path.is_file():
    try:
        prev = json.loads(out_path.read_text(encoding="utf-8"))
        for c in prev.get("candidates", []):
            cid = c.get("id")
            if cid:
                snapshot = {k: c[k] for k in EVAL_FIELDS if k in c}
                snapshot["__prev_file"] = c.get("file")
                snapshot["__prev_line"] = c.get("line")
                existing_by_id[cid] = snapshot
                if c.get("manual_addition") is True:
                    manual_additions[cid] = dict(c)  # 전체 dict 보존(소스 MD 없음)
        print(
            f"INFO: --merge 모드, 기존 {len(existing_by_id)}건의 phase2-review 결과 필드를 보존합니다"
            f"(manual_addition {len(manual_additions)}건 통째 보존).",
            file=sys.stderr,
        )
    except (json.JSONDecodeError, OSError) as e:
        print(f"WARNING: --merge 실패, 새로 생성: {e}", file=sys.stderr)
        existing_by_id = {}
        manual_additions = {}

def _same_path(a, b):
    """경로 포맷(절대/상대) 무관 동일 파일 판정: 한쪽이 다른 쪽의 경로-suffix(컴포넌트 경계)면 동일.

    스캐너마다 결과 MD에 절대/상대경로를 섞어 쓰므로, false-carryover 가드가 포맷 차이만으로
    "sink 이동"을 오판해 eval 필드를 버리던 문제를 막는다(phase1_review_assert._same_file_path와 동일 계약).
    """
    if not a or not b:
        return a == b
    a2, b2 = a.lstrip("/"), b.lstrip("/")
    return a2 == b2 or a2.endswith("/" + b2) or b2.endswith("/" + a2)


def _build_candidate_dict(cid, scanner, cand, md, existing_by_id, prereq_group=None):
    base = {
        "id": cid,
        "scanner": scanner,
        "prereq_group": prereq_group,
        "title": cand.get("title", ""),
        "file": cand.get("file", ""),
        "line": cand.get("line", 0),
        "url_path": cand.get("url_path", ""),
        "source": cand.get("source", ""),
        "sink": cand.get("sink", ""),
        "test_prereq": cand.get("test_prereq", ""),
        "phase1_path": str(md),
        "status": "candidate",
        "phase1_validated": False,
        "phase1_discarded_reason": None,
        "phase1_eval_state": {
            "reopen": False,
            "retries": 0,
            "conflicts": [],
        },
        "safe_category": None,
    }
    preserved = existing_by_id.get(cid)
    if preserved:
        # 레거시 필드 마이그레이션: phase1_eval_state에서 폐기된 키 제거
        legacy_state = preserved.get("phase1_eval_state")
        if isinstance(legacy_state, dict):
            for legacy_key in ("requires_human_review",):
                legacy_state.pop(legacy_key, None)
        # M3 가드: 동일 ID여도 (file, line)이 바뀌면 다른 sink로 간주하여 eval 필드 보존하지 않는다.
        # 과거 safe/confirmed 판정이 새 위치의 다른 취약점으로 잘못 전이되는 false-carryover를 차단.
        prev_file = preserved.pop("__prev_file", None)
        prev_line = preserved.pop("__prev_line", None)
        if prev_file is not None and prev_line is not None and (
            not _same_path(prev_file, base["file"]) or prev_line != base["line"]
        ):
            print(
                f"WARNING: --merge {cid} (file,line) 변경 "
                f"({prev_file}:{prev_line} → {base['file']}:{base['line']}) — "
                f"eval 필드 보존하지 않음",
                file=sys.stderr,
            )
        else:
            base.update(preserved)
    return base


MANIFEST_RE = re.compile(
    r"<!-- NOAH-SAST MANIFEST v1 -->\s*```json\s*(\{.*?\})\s*```\s*<!-- /NOAH-SAST MANIFEST -->",
    re.S,
)
CANDIDATE_HEADER_RE = re.compile(r"^## ([A-Z][A-Z0-9_]*-\d+):\s*", re.M)
ID_PREFIX_RE = re.compile(r"^id_prefix:\s*([A-Z][A-Z0-9_]*)\s*$", re.M)
PREREQ_GROUP_RE = re.compile(r"^prereq_group:\s*([a-z][a-z0-9_-]*)\s*$", re.M)


def _scanner_phase1_path(scanner_name: str) -> Path | None:
    import os as _os
    here = Path(_os.path.dirname(_os.path.abspath(__file__))).parent
    p = here / "scanners" / scanner_name / "phase1.md"
    return p if p.is_file() else None


def _read_scanner_prefix(scanner_name: str) -> str | None:
    """스캐너의 phase1.md frontmatter에서 id_prefix를 읽는다.
    ai-discovery 등 스캐너가 아닌 결과 파일은 None 반환."""
    phase1_md = _scanner_phase1_path(scanner_name)
    if phase1_md is None:
        return None
    try:
        m = ID_PREFIX_RE.search(phase1_md.read_text(encoding="utf-8"))
        return m.group(1) if m else None
    except OSError:
        return None


def _read_scanner_prereq_group(scanner_name: str) -> str | None:
    """스캐너의 phase1.md frontmatter에서 prereq_group을 읽는다.
    선언이 없으면 None 반환 (사전 단계 불필요)."""
    phase1_md = _scanner_phase1_path(scanner_name)
    if phase1_md is None:
        return None
    try:
        m = PREREQ_GROUP_RE.search(phase1_md.read_text(encoding="utf-8"))
        return m.group(1) if m else None
    except OSError:
        return None

# Source→Sink Flow / Vulnerability Flow 섹션이 선택적인 스캐너 (설정/구성 기반)
FLOW_OPTIONAL_SCANNERS = {
    "business-logic-scanner",
    "validation-logic-scanner",
    "security-headers-scanner",
    "cookie-security-scanner",
    "springboot-hardening-scanner",
    "tls-scanner",
    # Android config-archetype 발견(WebSettings 플래그 / PendingIntent 플래그 / 매니페스트 속성)은
    # source→sink dataflow가 없으므로 Flow 섹션을 면제한다.
    "android-webview-scanner",
    "android-ipc-scanner",
    "android-manifest-scanner",
    # iOS config-archetype: ios-storage(저장 설정)·ios-crypto(알고리즘/모드)는
    # 설정값 자체가 취약점이므로 source→sink Flow 섹션을 면제한다.
    # ios-webview는 taint 룰이 있어 Flow 섹션 작성 가능 — 면제 대상 아님.
    "ios-storage-scanner",
    "ios-crypto-scanner",
}

REQUIRED_SECTIONS = [
    ("### Code", 20),
    ("### Source→Sink Flow|### Vulnerability Flow", 50),
    ("### Validation Logic", 80),
    ("### Trigger Conditions", 80),
    ("### Decision", 40),
]

errors = []
warnings = []
candidates = []
candidate_bodies = {}  # cid -> prose 본문 (진입점 묶음 검사용)
clean_scanners = []
skipped_scanners = []

EXCLUDE_STEMS = {"chain-analysis"}  # Phase 1 manifest 형식이 아닌 파일 제외
md_files = sorted(
    f for f in phase1_dir.glob("*.md")
    if not f.name.startswith("_")  # _ 접두사 = 보조/메타 산출물(예: _idor_inventory_raw) — 후보 manifest 아님
    and not f.stem.endswith("-phase2") and f.stem not in EXCLUDE_STEMS
)
if not md_files:
    print(f"ERROR: No .md files found in {phase1_dir}")
    sys.exit(1)

# 예상 스캐너 목록 로드 (select_scanners.py --write-expected-file 결과)
_expected_file = phase1_dir / "_expected_scanners.json"
expected_scanner_set: set[str] | None = None
if _expected_file.is_file():
    try:
        expected_scanner_set = set(json.loads(_expected_file.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError) as e:
        print(f"WARNING: _expected_scanners.json 파싱 실패 — {e}", file=sys.stderr)

for md in md_files:
    try:
        text = md.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as e:
        errors.append(f"{md.stem}: READ_FAIL — {e}")
        continue
    scanner = md.stem

    # 1. Manifest 추출
    m = MANIFEST_RE.search(text)
    if not m:
        errors.append(f"{scanner}: NO_MANIFEST — manifest 블록이 파일에 없음")
        continue
    try:
        manifest = json.loads(m.group(1))
    except json.JSONDecodeError as e:
        errors.append(f"{scanner}: INVALID_JSON — {e}")
        continue

    declared = manifest.get("declared_count", -1)
    cands = manifest.get("candidates", [])

    # 2. declared_count vs actual count
    if declared != len(cands):
        errors.append(
            f"{scanner}: COUNT_MISMATCH — declared {declared} but manifest has {len(cands)} candidates"
        )
        continue

    if declared == 0:
        clean_scanners.append(scanner)
        continue

    # 3. 각 후보: manifest ID ↔ prose header 대조 + 섹션 품질 검증 + id_prefix 검증
    prose_ids = set(CANDIDATE_HEADER_RE.findall(text))
    expected_prefix = _read_scanner_prefix(scanner)
    prefix_re = (
        re.compile(rf"^{re.escape(expected_prefix)}-\d+$") if expected_prefix else None
    )
    scanner_prereq_group = _read_scanner_prereq_group(scanner)

    for cand in cands:
        cid = cand.get("id", "UNKNOWN")

        # id_prefix 규약 검증 (phase1.md frontmatter의 id_prefix와 일치해야 함)
        if prefix_re and not prefix_re.match(cid):
            errors.append(
                f"{scanner}/{cid}: ID_PREFIX_MISMATCH — 기대 `{expected_prefix}-N`, "
                f"실제 `{cid}`. phase1.md frontmatter의 id_prefix를 따르세요."
            )
            continue

        # manifest ID가 prose에도 있는지
        if cid not in prose_ids:
            errors.append(
                f"{scanner}/{cid}: NO_PROSE_SECTION — manifest에는 있으나 ## {cid}: 헤더가 파일에 없음"
            )
            continue

        # 해당 후보의 prose 섹션 추출
        sect_start_re = re.compile(rf"^## {re.escape(cid)}:\s*(.+?)$", re.M)
        h = sect_start_re.search(text)
        if not h:
            errors.append(f"{scanner}/{cid}: HEADER_PARSE_FAIL")
            continue

        # 다음 ## 또는 manifest 시작까지
        next_h = re.search(r"^## ", text[h.end() :], re.M)
        mf_start = text.find("<!-- NOAH-SAST MANIFEST v1 -->")
        end = h.end() + (next_h.start() if next_h else len(text) - h.end())
        if 0 < mf_start < end:
            end = mf_start
        section = text[h.end() : end]
        candidate_bodies[cid] = section

        # 필수 섹션 품질 검증
        for sub_name, min_len in REQUIRED_SECTIONS:
            # 복수 헤더 허용 ("|"로 구분)
            sub_headers = sub_name.split("|")
            sub_header_pattern = "|".join(re.escape(h) for h in sub_headers)
            sub_re = re.compile(
                rf"^(?:{sub_header_pattern})\s*\n(.*?)(?=^### |\Z)", re.M | re.S
            )
            sm = sub_re.search(section)
            if not sm:
                # 설정 기반 스캐너에서 Source→Sink Flow/Vulnerability Flow 누락은 정상
                is_flow_section = "Source→Sink Flow" in sub_name or "Vulnerability Flow" in sub_name
                if is_flow_section and scanner in FLOW_OPTIONAL_SCANNERS:
                    pass  # 경고 생략
                else:
                    warnings.append(f"{scanner}/{cid}: MISSING_SECTION:{sub_headers[0]}")
            elif len(sm.group(1).strip()) < min_len:
                warnings.append(
                    f"{scanner}/{cid}: SHORT_SECTION:{sub_headers[0]} ({len(sm.group(1).strip())} chars < {min_len})"
                )

        candidates.append(
            _build_candidate_dict(
                cid=cid,
                scanner=scanner,
                cand=cand,
                md=md,
                existing_by_id=existing_by_id,
                prereq_group=scanner_prereq_group,
            )
        )

    # prose에는 있으나 manifest에 없는 ID
    manifest_ids = {c.get("id") for c in cands}
    orphan_ids = prose_ids - manifest_ids
    for oid in orphan_ids:
        errors.append(
            f"{scanner}/{oid}: ORPHAN_PROSE — ## {oid}: 헤더가 있으나 manifest에 없음"
        )

# 4. 동일 file:line 후보 그룹핑 (dedup 힌트)
from collections import defaultdict

loc_groups = defaultdict(list)
for c in candidates:
    if c["file"] and c["line"]:
        loc_groups[(c["file"], c["line"])].append(c["id"])
duplicates = {loc: ids for loc, ids in loc_groups.items() if len(ids) > 1}

# 4-B. 진입점 묶음 감지 (BUNDLED) — 진입점 통합은 금지(decision-framework §5)이므로,
#   한 후보 본문에 서로 다른 route 어노테이션이 2개 이상이면 신호. §5 규약상 형제 route
#   어노테이션은 본문에 붙이지 않고 메서드명으로 인용하므로, 잘 작성된 후보는 route 1개만
#   갖는다 → route ≥2는 (a) 진입점 과대통합 또는 (b) 형제 route를 붙인 규약 위반 신호.
#   IDOR 검토 인벤토리의 `GET /path` 행은 어노테이션 형태가 아니라 매치되지 않는다.
ROUTE_ANNOT_RE = re.compile(
    r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*[^)]*?[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
for cid, body in candidate_bodies.items():
    routes = sorted({r.strip() for r in ROUTE_ANNOT_RE.findall(body)})
    if len(routes) >= 2:
        warnings.append(
            f"{cid}: BUNDLED_ENTRYPOINTS — 후보 본문에 route 어노테이션 {len(routes)}개 "
            f"({', '.join(routes)}). 진입점이 둘 이상이면 각각 별도 후보로 분리하라. 형제 deviance "
            f"비교면 형제 route 어노테이션을 붙이지 말고 메서드명으로 인용하라 (decision-framework §5)."
        )

# 4-b. manual_addition 후보 보존: 소스 MD에서 재생성되지 않은(=ID 미존재) 플래그 후보를 통째로 append.
#      게이트(FN 방지)나 외부 증거로 추가된 후보가 재빌드에 소멸하던 모순을 차단한다.
_built_ids = {c["id"] for c in candidates}
for cid, full in manual_additions.items():
    if cid not in _built_ids:
        candidates.append(full)
        print(f"INFO: manual_addition 후보 보존: {cid} ({full.get('file', '')}:{full.get('line', '')})",
              file=sys.stderr)

# 5. master-list.json 출력
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(
    json.dumps(
        {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "candidates": candidates,
            "clean_scanners": sorted(clean_scanners),
        },
        indent=2,
        ensure_ascii=False,
    )
)

# 6. MISSING_FILE 검사 (예상 스캐너 중 MD 파일이 없는 것)
if expected_scanner_set is not None:
    actual_stems = {md.stem for md in md_files}
    for scanner in sorted(expected_scanner_set):
        if scanner not in actual_stems:
            errors.append(
                f"{scanner}: MISSING_FILE — Phase 1 결과 파일이 생성되지 않음 "
                f"(예상: {phase1_dir / (scanner + '.md')})"
            )

# 7. stdout 출력
if errors:
    for e in errors:
        print(f"ERROR: {e}")

if warnings:
    for w in warnings:
        print(f"WARNING: {w}")

if duplicates:
    for loc, ids in duplicates.items():
        print(f"DUPLICATE SINK at {loc[0]}:{loc[1]}: {', '.join(ids)}")

print(
    f"\nMaster list: {len(candidates)} candidates / {len(clean_scanners)} clean"
)
for c in candidates:
    print(f"- {c['id']}: {c['title']} @ {c['file']}:{c['line']}")

if errors:
    print(f"\n*** {len(errors)} ERROR(s) detected — 메인 에이전트는 해당 스캐너를 재실행해야 합니다 ***")
    sys.exit(1)
if warnings:
    print(f"\n*** {len(warnings)} WARNING(s) detected — 해당 후보의 파일 품질을 확인하세요 ***")
