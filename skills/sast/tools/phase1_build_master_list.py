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
parser.add_argument(
    "--idor-shards-merged",
    metavar="SHARD_DIR",
    default=None,
    help="idor 샤딩 deep-read 산출물(SHARD_DIR/idor_shards_manifest.json + idor_shard_*_result.md)을 "
    "검증하고, 통과 시에만 게이트 해제 sentinel(idor-scanner.shard-merged)을 발급한다. "
    "단순 touch로는 게이트를 풀 수 없다.",
)
args = parser.parse_args()

phase1_dir = Path(args.phase1_dir)
out_path = Path(args.output_json)

# === [v11 강제 게이트] auth-boundary.json sentinel 검증 ===
# Step 3-1 lint(auth-boundary.lint-passed sentinel)를 통과하지 않으면 진입 차단.
# select_scanners.py와 동일 검증 — 이중 안전망.
_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))
try:
    from _validate_auth_boundary import check_sentinel as _check_auth_sentinel
    _AUTH_BOUNDARY_PATH = phase1_dir / "auth-boundary.json"
    _AUTH_SENTINEL_PATH = phase1_dir / "auth-boundary.lint-passed"
    _ok, _msg = _check_auth_sentinel(_AUTH_BOUNDARY_PATH, _AUTH_SENTINEL_PATH)
    if not _ok:
        print(
            f"ERROR: auth-boundary.json lint sentinel 검증 실패 — {_msg}\n"
            f"  → Step 3-1 절차 (SKILL.md)를 재수행하고 다음을 실행하라:\n"
            f"    python3 {_TOOLS_DIR}/lint_auth_boundary.py {_AUTH_BOUNDARY_PATH}\n"
            f"  → lint PASS 후 sentinel({_AUTH_SENTINEL_PATH})이 발급되어야 본 스크립트 진입 가능",
            file=sys.stderr,
        )
        sys.exit(1)
except ImportError:
    # _validate_auth_boundary 모듈 부재는 SAST 스킬 손상 상태 — 경고만 출력하고 진행 (호환성).
    print(
        "WARNING: _validate_auth_boundary 모듈을 import할 수 없음. "
        "lint 강제 게이트 비활성 — SAST 스킬 설치 상태 점검 필요.",
        file=sys.stderr,
    )

# 병합 모드: 기존 master-list.json 로드 (phase2-review 결과 보존용)
EVAL_FIELDS = {
    "status", "tag", "evidence_summary", "verified_defense", "rederivation_performed",
    "safe_category", "phase1_validated", "phase1_discarded_reason", "phase1_eval_state",
    "auth_boundary",  # 메타데이터 필드 — auth-boundary.json 없는 --merge 시 기존 값 보존
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

# === 인증경계(auth_boundary) 파생 ===
# auth-boundary.json의 routes[]를 분석하여 각 후보의 url_path 기반으로
# 외부망.무인증 / 외부망.인증 / 내부망.무인증 / 내부망.인증 4분류를 파생한다.
_AUTH_BOUNDARY_DATA = None
_AB_ROUTES = []  # [(surface_key, identity_source, is_external)]
_AB_FALLBACK_LOG = []  # url_path 매칭 실패로 file_path 폴백 사용된 항목 로그

def _load_auth_boundary_routes(phase1_dir: Path):
    global _AUTH_BOUNDARY_DATA, _AB_ROUTES
    ab_path = phase1_dir / "auth-boundary.json"
    if not ab_path.is_file():
        return
    try:
        _AUTH_BOUNDARY_DATA = json.loads(ab_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    if not isinstance(_AUTH_BOUNDARY_DATA, dict):
        return

    # 외부망 게이트웨이 판별: host_pattern에 공개 도메인 패턴이 있으면 외부망
    external_gw_ids = set()
    for gw in _AUTH_BOUNDARY_DATA.get("gateways", []):
        hp = gw.get("host_pattern", "")
        gid = gw.get("id", "")
        # 카카오 내부망(.onkakao.net) 전용이 아닌 패턴 = 외부망
        # gift-link.kakao.com, *.kakao.com 등은 외부망
        # *.gift-affiliate-management 등 내부 서비스 이름만 있으면 내부망
        if any(x in hp for x in ["kakao.com", "kakao.net", "gift-link", "gift-affiliate-monitor",
                                   "gift-affiliate-front-api", "gift-affiliate-integration"]):
            external_gw_ids.add(gid)

    for route in _AUTH_BOUNDARY_DATA.get("routes", []):
        surface = route.get("surface_key", "")
        identity = route.get("identity_source", "")
        gw_id = route.get("gateway_id", "")
        is_external = (gw_id in external_gw_ids) if gw_id else False
        # 경로 패턴 추출 (METHOD prefix 제거)
        path = re.sub(r"^[A-Z*]+ ", "", surface).strip()
        _AB_ROUTES.append((path, identity, is_external))


def _normalize_path(p: str) -> str:
    """{id}, {id:\\d+} 등 path variable을 * 로 정규화하고 /** /* 접미사 제거."""
    p = re.sub(r'\{[^}]+\}', '*', p)   # {id}, {orderId:\d+} → *
    p = re.sub(r'/\*+$', '', p)         # /** 또는 /* 접미사 제거
    p = p.rstrip('/')                   # trailing slash 제거
    return p


def _derive_auth_boundary_from_file(file_path: str) -> str:
    """file_path 기반 폴백: url_path가 없을 때 소스 파일 경로로 인증경계를 파생한다.

    규칙:
    - loco-web-jude-dkos: 공개 웹서버 → 외부망.무인증
    - loco-bo-jude-admin: 어드민 패널 → 내부망.인증
    - lazenca + GroupAlarm/GroupAction/RoomChatbot/SecureImage: talk-user 헤더 → 내부망.인증
    - lazenca 나머지: 내부망 무인증
    - jude-misc-api: KakaotalkGateway 인증 → 내부망.인증
    - loco-api-jude + gift/kids/profile/moim: 인증 있음 → 내부망.인증
    - loco-api-jude 나머지(/jude/**): 무인증 → 내부망.무인증
    - 하드코딩 시크릿 계열: 코드에서 직접 노출 → 내부망.무인증
    - 기타: 내부망.무인증 (보수적 기본값)
    """
    f = file_path or ""
    if "loco-web-jude-dkos" in f:
        return "외부망.무인증"
    if "loco-bo-jude-admin" in f:
        return "내부망.인증"
    if "lazenca" in f:
        # GroupAlarm, GroupAction 등은 talk-user 헤더 인증 경유
        for kw in ("GroupAlarm", "GroupAction", "RoomChatbot", "SecureImage",
                   "GroupChat", "GroupSubscription"):
            if kw in f:
                return "내부망.인증"
        return "내부망.무인증"
    if "jude-misc-api" in f:
        return "내부망.인증"
    if "loco-api-jude" in f or "loco-bo-jude" in f or "loco-bo-common" in f:
        # gift/kids/profile/moim 계열은 oauthToken 또는 serviceId 인증
        for kw in ("gift", "Gift", "kids", "Kids", "profile", "Profile",
                   "moim", "Moim", "Schedule", "Poll"):
            if kw in f:
                return "내부망.인증"
        return "내부망.무인증"
    return "내부망.무인증"


def _derive_auth_boundary(url_path: str, file_path: str = "") -> str:
    """url_path를 auth-boundary.json routes와 매칭하여 인증경계 4분류 반환.

    url_path가 없거나 routes 매칭에 실패하면 file_path 기반 폴백을 사용한다.
    이를 통해 스캐너 에이전트가 url_path를 채우지 않아도 인증경계가 자동 파생된다.
    """
    if _AB_ROUTES and url_path:
        norm_candidate = _normalize_path(url_path)
        best_score = -1
        best_is_ext = False
        best_identity = ""
        for route_path, identity, is_ext in _AB_ROUTES:
            rp_clean = _normalize_path(route_path)
            if not rp_clean:
                continue
            # 후보 경로가 route prefix로 시작하거나, route가 후보 prefix로 시작하면 매칭
            if norm_candidate.startswith(rp_clean) or rp_clean.startswith(norm_candidate):
                score = len(rp_clean)
                if score > best_score:
                    best_score = score
                    best_is_ext = is_ext
                    best_identity = identity

        if best_score >= 0:
            is_auth = best_identity not in ("없음(익명)", "")
            if best_is_ext:
                return "외부망.인증" if is_auth else "외부망.무인증"
            else:
                return "내부망.인증" if is_auth else "내부망.무인증"

    # routes 매칭 실패 또는 url_path 없음 → file_path 기반 폴백
    # 폴백 사용 여부를 WARNING으로 노출: 인증경계가 자동 파생된 항목을 식별 가능하게 함
    reason = "url_path 없음" if not url_path else f"url_path='{url_path}' routes 매칭 실패"
    result = _derive_auth_boundary_from_file(file_path)
    _AB_FALLBACK_LOG.append(f"{reason} → file_path='{file_path}' → {result}")
    return result


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
        "auth_boundary": _derive_auth_boundary(cand.get("url_path", ""), cand.get("file", "")),
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
            # auth_boundary 보호: preserved에 빈/null값이 들어있으면 base에서 재파생한 값을 복원.
            # phase2-review 등 다른 에이전트가 JSON 재직렬화 시 auth_boundary를 '' 로 교체하는
            # 버그(writer 권한 밖 필드 덮어쓰기)를 방어한다.
            _VALID_AB = {'외부망.무인증', '외부망.인증', '내부망.무인증', '내부망.인증'}
            if base.get("auth_boundary", "") not in _VALID_AB:
                recovered = _derive_auth_boundary(
                    cand.get("url_path", ""), cand.get("file", "")
                )
                base["auth_boundary"] = recovered
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


IDOR_SENTINEL_NAME = "idor-scanner.shard-merged"
_IDOR_RESULT_MIN_BYTES = 200


_SHARD_MANIFEST_RE = re.compile(
    r'<!--\s*NOAH-SAST MANIFEST v1\s*-->\s*```json\s*(\{.*?\})\s*```\s*<!--\s*/NOAH-SAST MANIFEST\s*-->',
    re.DOTALL,
)
_IDOR_ID_RE = re.compile(r'^IDOR-\d+$')
_IDOR_HEADER_RE = re.compile(r'^##\s+(IDOR-\d+)\s*:', re.MULTILINE)
_MIN_CANDIDATE_BODY_BYTES = 200


def _validate_idor_shard_artifacts(shard_dir: Path, idor_md: Path):
    """idor 샤딩 deep-read 산출물을 검증한다. 게이트 해제(sentinel 발급)의 유일한 정당 경로.

    검증 항목 (하나라도 실패하면 게이트 해제 불가):
      1. SHARD_DIR/idor_shards_manifest.json 존재 + K(shards) 파싱.
      1-a. shards 카운트 vs files 배열 길이 일치.
      2. 각 샤드 result.md 존재 + >200B + MANIFEST JSON 실제 파싱 성공.
      3. 각 샤드 result.md 후보 ID가 IDOR-\\d+ 형식인지.
      4. 샤드 간 ID 중복 없는지.
      5. 각 샤드 후보 ID가 idor-scanner.md에 ## <ID>: 헤더 + 최소 본문(200B)으로 존재
         (idor_shard_merge.py가 병합을 수행했음을 확인).
      6. idor-scanner.md에 [INCOMPLETE] 마커 없음.

    반환: (ok: bool, detail: str, evidence: dict)
    """
    manifest_path = shard_dir / "idor_shards_manifest.json"
    if not manifest_path.is_file():
        return False, f"샤드 manifest 없음: {manifest_path}", {}
    try:
        man = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return False, f"샤드 manifest 파싱 실패: {e}", {}

    declared_shards = man.get("shards") or len(man.get("files", []))
    if not declared_shards:
        return False, "샤드 manifest에 shards 수가 없음", {}
    shard_files = man.get("files", [])
    # 1-a: shards 카운트 vs files 배열 길이 일치
    if len(shard_files) != declared_shards:
        return False, (
            f"샤드 manifest의 shards={declared_shards}와 files 배열 길이={len(shard_files)} 불일치 "
            f"— 일부 샤드가 manifest에서 누락됨"
        ), {}

    idor_md_text = idor_md.read_text(encoding="utf-8", errors="ignore") if idor_md.is_file() else ""
    existing_ids_in_source: set[str] = set(_IDOR_HEADER_RE.findall(idor_md_text))

    validated = []
    seen_ids: dict[str, int] = {}  # id -> shard_n (샤드 간 중복 탐지)
    all_shard_candidate_ids: list[str] = []

    for entry in shard_files:
        n = entry.get("shard")
        id_start = entry.get("id_start")
        id_end = entry.get("id_end")
        shard_path = Path(entry.get("path", ""))
        result_path = shard_path.with_name(shard_path.stem + "_result.md")

        if not result_path.is_file():
            return False, f"샤드 {n} 결과 파일 없음: {result_path}", {}
        body = result_path.read_text(encoding="utf-8", errors="ignore")
        if len(body.encode("utf-8")) < _IDOR_RESULT_MIN_BYTES:
            return False, f"샤드 {n} 결과 파일이 비정상적으로 작음({result_path})", {}

        # MANIFEST JSON 실제 파싱 (단순 문자열 포함 검사 대체)
        mj = _SHARD_MANIFEST_RE.search(body)
        if not mj:
            return False, f"샤드 {n} 결과 파일에 유효한 MANIFEST JSON 블록 없음({result_path})", {}
        try:
            shard_meta = json.loads(mj.group(1))
        except json.JSONDecodeError as e:
            return False, f"샤드 {n} MANIFEST JSON 파싱 실패: {e}", {}

        for cand in shard_meta.get("candidates", []):
            cid = cand.get("id", "")
            if not _IDOR_ID_RE.match(cid):
                return False, f"샤드 {n}: ID '{cid}'가 IDOR-\\d+ 형식 위반", {}
            num = int(cid.split("-")[1])
            if id_start is not None and id_end is not None:
                if not (id_start <= num <= id_end):
                    return False, (
                        f"샤드 {n}: ID '{cid}'가 할당 범위 IDOR-{id_start}~IDOR-{id_end} 밖 "
                        f"— idor_shard.py 재실행 필요"
                    ), {}
            if cid in seen_ids:
                return False, (
                    f"ID '{cid}'가 샤드 {seen_ids[cid]}와 샤드 {n}에서 중복 "
                    f"— idor_shard_merge.py를 먼저 실행하라"
                ), {}
            seen_ids[cid] = n
            all_shard_candidate_ids.append(cid)

        validated.append(str(result_path))

    if len(validated) != len(shard_files):
        return False, "검증된 결과 파일 수가 샤드 수와 불일치", {}

    # 5: 각 샤드 후보 ID가 idor-scanner.md에 헤더 + 최소 본문으로 존재하는지 확인
    # (idor_shard_merge.py가 실제로 병합했음을 검증)
    missing_merge: list[str] = []
    thin_merge: list[str] = []
    for cid in all_shard_candidate_ids:
        if f"## {cid}:" not in idor_md_text:
            missing_merge.append(cid)
            continue
        # 본문 최소 길이: 헤더부터 다음 ## 또는 끝까지 추출
        pat = re.compile(
            rf'^(##\s+{re.escape(cid)}\s*:.*?)(?=^##\s+IDOR-|\Z)',
            re.MULTILINE | re.DOTALL,
        )
        m2 = pat.search(idor_md_text)
        section = m2.group(1) if m2 else ""
        if len(section.encode("utf-8")) < _MIN_CANDIDATE_BODY_BYTES:
            thin_merge.append(cid)

    if missing_merge:
        return False, (
            f"샤드 후보 {missing_merge}가 idor-scanner.md에 병합되지 않음 "
            f"— python3 <NOAH_SAST_DIR>/tools/idor_shard_merge.py <idor_scanner_md> <shard_dir> 실행 필요"
        ), {}
    if thin_merge:
        return False, (
            f"샤드 후보 {thin_merge}의 idor-scanner.md 내 섹션이 너무 짧음 (껍데기 헤더 의심) "
            f"— idor_shard_merge.py 재실행 또는 수동 확인 필요"
        ), {}

    # 6: [INCOMPLETE] 마커 해소
    if idor_md.is_file() and "[INCOMPLETE" in idor_md_text:
        return False, (
            "idor-scanner.md에 [INCOMPLETE] 마커가 여전히 존재 "
            f"— idor_shard_merge.py 실행 후 마커 해소 여부 확인"
        ), {}

    return True, f"{declared_shards}개 샤드 결과 검증 통과 (신규 후보 {len(all_shard_candidate_ids)}건 병합 확인)", {
        "shards": declared_shards,
        "shard_dir": str(shard_dir),
        "result_files": validated,
        "merged_candidate_ids": all_shard_candidate_ids,
    }


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

# auth-boundary.json 로드 (인증경계 파생용) — 함수 정의 이후 호출
_load_auth_boundary_routes(phase1_dir)
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

    # manifest 필드 품질 경고 (WARNING — 차단하지 않고 알림만)
    for cand in cands:
        cid = cand.get("id", "?")
        # url_path 형식 검증: "METHOD /path" 포맷이어야 함
        up = cand.get("url_path", "")
        if up and not re.match(r'^[A-Z*]+\s+/', up) and not up.startswith('/'):
            warnings.append(
                f"{scanner}/{cid}: INVALID_URL_PATH — url_path='{up[:60]}' 는 "
                f"'METHOD /경로' 또는 '/경로' 형식이 아닙니다. "
                f"컨트롤러 @RequestMapping에서 실제 경로를 확인하세요."
            )
        # source/sink 비어있을 때 경고
        if not cand.get("source") and not cand.get("sink"):
            warnings.append(
                f"{scanner}/{cid}: EMPTY_MANIFEST_FIELD — source/sink가 모두 비어 있습니다. "
                f"phase1.md의 Source→Sink Flow를 manifest에 요약하세요."
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

# 6.5 IDOR 샤딩 게이트 — idor 인벤토리가 임계 초과거나 [INCOMPLETE]면 샤드 deep-read를 강제한다.
#      메인 에이전트의 판단으로 AI 자율 탐색/단일 에이전트로 대체하는 것을 기계적으로 차단한다.
#      게이트 해제는 오직 검증된 sentinel로만 가능하다 — 단순 touch·환경 면제 같은 예외 경로는 없다.
IDOR_SHARD_THRESHOLD_FILES = 40
IDOR_SHARD_THRESHOLD_ROWS = 120
_idor_md = phase1_dir / "idor-scanner.md"
_idor_sentinel = phase1_dir / IDOR_SENTINEL_NAME


def _idor_sentinel_is_valid(sentinel: Path, idor_md: Path) -> bool:
    """sentinel이 검증 경로(--idor-shards-merged)로 발급되었고 지금도 유효한지 재확인한다.
    빈 파일/수기 touch/forged 플래그를 거른다: JSON 구조 + 결과 파일 실재 + [INCOMPLETE] 해소를 재검증."""
    if not sentinel.is_file():
        return False
    try:
        meta = json.loads(sentinel.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False  # 빈 touch/비정형 → 무효
    if not isinstance(meta, dict) or meta.get("gate") != "idor-sharding" or not meta.get("validated"):
        return False
    result_files = meta.get("result_files") or []
    if not result_files or not all(Path(p).is_file() for p in result_files):
        return False  # 산출물이 사라졌으면 무효
    if idor_md.is_file():
        idor_text = idor_md.read_text(encoding="utf-8", errors="ignore")
        if "[INCOMPLETE" in idor_text:
            return False  # 병합이 되돌려졌으면 무효
        # 병합 확인: sentinel에 기록된 merged_candidate_ids가 여전히 idor-scanner.md에 존재하는지
        merged_ids = meta.get("merged_candidate_ids") or []
        for cid in merged_ids:
            if f"## {cid}:" not in idor_text:
                return False  # 병합된 후보가 사라졌으면 무효
    return True


# 6.5-a: --idor-shards-merged 가 주어지면 산출물을 검증하고 통과 시에만 sentinel을 발급한다.
if args.idor_shards_merged is not None:
    _ok, _detail, _evidence = _validate_idor_shard_artifacts(
        Path(args.idor_shards_merged), _idor_md
    )
    if _ok:
        _evidence.update({
            "gate": "idor-sharding",
            "validated": True,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        })
        _idor_sentinel.write_text(
            json.dumps(_evidence, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"INFO: IDOR 샤딩 검증 통과 — sentinel 발급({_detail}).", file=sys.stderr)
    else:
        errors.append(
            f"IDOR_SHARDS_INVALID — 샤딩 산출물 검증 실패: {_detail}. "
            "샤드 deep-read를 실제로 완료하고 결과를 idor-scanner.md에 병합한 뒤 다시 실행하라. "
            "게이트는 검증 통과 없이 해제되지 않는다."
        )

# 6.5-b: 게이트 판정 — 트리거 조건(임계 초과/[INCOMPLETE])이면 유효 sentinel이 있어야만 통과.
if _idor_md.is_file() and not _idor_sentinel_is_valid(_idor_sentinel, _idor_md):
    _t = _idor_md.read_text(encoding="utf-8", errors="ignore")
    _has_incomplete = "[INCOMPLETE" in _t
    _inv = _t.split("### IDOR 검토 인벤토리", 1)
    _files = _rows = 0
    if len(_inv) > 1:
        _region = _inv[1]
        # 인라인 인벤토리: #### 파일 섹션 수 / 표 행 수
        _files = _region.count("\n#### ")
        _rows = _region.count("\n| ")
        # 외부 인벤토리 참조: "1116 진입점 / 196 파일" 같은 명시 수치도 인정
        _m = re.search(r"(\d[\d,]*)\s*진입점\s*[/·]\s*(\d[\d,]*)\s*파일", _region)
        if _m:
            _rows = max(_rows, int(_m.group(1).replace(",", "")))
            _files = max(_files, int(_m.group(2).replace(",", "")))
    _over = _files > IDOR_SHARD_THRESHOLD_FILES or _rows > IDOR_SHARD_THRESHOLD_ROWS
    _sentinel_present_but_invalid = _idor_sentinel.exists()
    if _has_incomplete or _over:
        _why = []
        if _has_incomplete:
            _why.append("idor-scanner.md에 [INCOMPLETE] 마커 존재(소유권 게이트 deep-read 미완)")
        if _over:
            _why.append(
                f"인벤토리 {_files}파일/{_rows}행 > 임계"
                f"({IDOR_SHARD_THRESHOLD_FILES}파일/{IDOR_SHARD_THRESHOLD_ROWS}행)"
            )
        if _sentinel_present_but_invalid:
            _why.append(
                "sentinel 파일이 존재하나 무효(수기 touch/빈 파일/산출물 소실/병합 미해소) — "
                "검증 경로로만 발급된 sentinel만 인정"
            )
        errors.append(
            "IDOR_SHARDING_REQUIRED — " + "; ".join(_why) + ". "
            "AI 자율 탐색이나 단일 에이전트로 대체 금지(메인 에이전트 임의 판단으로 생략 불가, 예외 없음). "
            "tools/idor_shard.py로 인벤토리를 샤딩 → 샤드당 1개 서브에이전트로 파일 단위 deep-read 병렬 수행 → "
            "각 샤드 결과를 idor-scanner.md에 병합(=[INCOMPLETE] 해소)한 뒤, "
            "phase1_build_master_list.py --merge --idor-shards-merged <SHARD_DIR> 를 실행하라. "
            "이 검증 플래그가 산출물(샤드 결과 파일·병합 상태)을 확인한 경우에만 게이트가 해제된다 — "
            "sentinel을 손으로 만들어 우회할 수 없다."
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

if _AB_FALLBACK_LOG:
    print(
        f"\nINFO: 인증경계 {len(_AB_FALLBACK_LOG)}건이 url_path 매칭 실패로 파일경로 기반 자동 파생됨 "
        f"(스캐너 에이전트가 url_path를 비워두면 오판 가능):"
    )
    for msg in _AB_FALLBACK_LOG[:10]:   # 최대 10건만 출력
        print(f"  {msg}")
    if len(_AB_FALLBACK_LOG) > 10:
        print(f"  ... 외 {len(_AB_FALLBACK_LOG) - 10}건")

if errors:
    print(f"\n*** {len(errors)} ERROR(s) detected — 메인 에이전트는 해당 스캐너를 재실행해야 합니다 ***")
    sys.exit(1)
if warnings:
    print(f"\n*** {len(warnings)} WARNING(s) detected — 해당 후보의 파일 품질을 확인하세요 ***")
