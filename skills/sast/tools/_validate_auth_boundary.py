"""_validate_auth_boundary.py — 인증 경계 검증 공통 모듈

이 모듈은 다음 세 곳에서 import해 동일 검증 로직을 재사용한다:
  - tools/lint_auth_boundary.py (단독 실행 lint)
  - tools/select_scanners.py (Step 4 진입 시 입력 의존성 검증)
  - tools/phase1_build_master_list.py (Step 5 마지막 이중 안전망)

핵심 함수:
  - validate_auth_boundary(data) -> list[str]  # 위반 목록
  - check_sentinel(boundary_path, sentinel_path) -> tuple[bool, str]
    : sentinel 파일이 존재 + 해시 일치 + 버전 일치 + 매직 마커 일치하면 (True, "")

LINT_VERSION을 변경하면 기존 sentinel은 모두 무효화되어 lint 재실행이 강제된다.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Tuple

# Lint 버전: 검증 로직을 깰 변경마다 bump.
LINT_VERSION = "v11.0"

# Sentinel 매직 마커: idor sentinel 패턴과 동일하게 "수기 touch 우회 불가" 명시.
SENTINEL_MAGIC = "NOAH-SAST AUTH-BOUNDARY LINT SENTINEL v1"

# Schema enum 값
VALID_REASONS = {
    "no_auth_layer_detected",
    "topology_unresolved",
    "user_skip",
}

VALID_FAILURE_MODES = {
    "gateway_basepath_mismatch",
    "credential_mismatch",
    "missing_auth_header",
    "downstream_propagation",
}

VALID_ESCALATION_BASIS = {
    "shared_jwt_passthrough",
    "service_account_token",
    "mtls_trust",
    "internal_network_implicit",
    "header_injection",
    "unauthenticated_internal",
    "api_key_shared",
    "oauth_token_delegation",
    "kerberos_delegation",
    "spiffe_identity",
    "other",
}


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_auth_boundary(data: dict) -> list[str]:
    """auth-boundary.json 데이터에 대한 schema + 무결성 검증. 위반 목록 반환."""
    failures: list[str] = []

    if not isinstance(data, dict):
        return ["root: 객체가 아님"]

    if "applicable" not in data:
        failures.append("L11-0: 'applicable' 필드 부재")
        return failures  # 다음 검증 진행 불가

    applicable = data["applicable"]
    if not isinstance(applicable, bool):
        failures.append(f"L11-0: 'applicable'는 bool이어야 함 (실제 {type(applicable).__name__})")
        return failures

    if applicable is False:
        # reason 필수 + enum
        reason = data.get("reason")
        if reason is None:
            failures.append("L11-0: applicable=false인데 'reason' 필드 부재")
        elif reason not in VALID_REASONS:
            failures.append(
                f"L11-0: 'reason' enum 위반: '{reason}' (허용: {sorted(VALID_REASONS)})"
            )
        elif reason == "topology_unresolved":
            # FAIL — 미확정 우회 차단
            failures.append(
                "L11-0: reason=topology_unresolved는 진행 무효. Step 3-1 재실행 필요."
            )
        return failures  # applicable=false면 더 이상 검증 안 함

    # applicable=true 경로
    gateways = data.get("gateways") or []
    clients = data.get("clients") or []
    routes = data.get("routes") or []
    unknowns = data.get("unknowns") or []

    # L11-0: gateways OR unknowns 중 하나는 non-empty
    if not gateways and not unknowns:
        failures.append(
            "L11-0: applicable=true인데 gateways·unknowns 모두 비어있음"
        )

    # 참조 무결성
    gw_ids = {g.get("id") for g in gateways if isinstance(g, dict)}
    cl_ids = {c.get("id") for c in clients if isinstance(c, dict)}

    for i, rt in enumerate(routes):
        if not isinstance(rt, dict):
            failures.append(f"routes[{i}]: 객체가 아님")
            continue
        if "surface_key" not in rt:
            failures.append(f"routes[{i}]: 'surface_key' 필드 부재")
        # client_ids 참조 무결성
        for cid in rt.get("client_ids") or []:
            if cid not in cl_ids:
                failures.append(
                    f"routes[{i}].client_ids: '{cid}' 미정의 (clients에 없음)"
                )
        # gateway_id 참조 무결성 (None 허용)
        gid = rt.get("gateway_id")
        if gid is not None and gid not in gw_ids:
            failures.append(
                f"routes[{i}].gateway_id: '{gid}' 미정의 (gateways에 없음)"
            )
        # failure_modes enum
        for mode in rt.get("failure_modes") or []:
            if mode not in VALID_FAILURE_MODES:
                failures.append(
                    f"routes[{i}].failure_modes: '{mode}' enum 위반 (허용: {sorted(VALID_FAILURE_MODES)})"
                )

    return failures


# surface_key 정규화 (M5 매칭 알고리즘)
_PATH_VAR_RE = re.compile(r"\{[^}]*\}")  # {id}, {id:\\d+}, {id?} 모두 매칭


def normalize_surface_key(surface_key: str) -> str:
    """METHOD path 정규형:
    - METHOD 대문자
    - {...} → *
    - ** → * (연속 *)
    - trailing slash 제거 (단 루트 / 유지)
    """
    if not surface_key:
        return surface_key
    parts = surface_key.strip().split(None, 1)
    if len(parts) != 2:
        return surface_key
    method, path = parts
    method = method.upper()
    # path variable 정규화
    path = _PATH_VAR_RE.sub("*", path)
    # ** → *
    while "**" in path:
        path = path.replace("**", "*")
    # trailing slash
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return f"{method} {path}"


def match_surface_key(reported: str, expected: str) -> bool:
    """정규화 후 정확 일치."""
    return normalize_surface_key(reported) == normalize_surface_key(expected)


def write_sentinel(boundary_path: Path, sentinel_path: Path, timestamp: str) -> None:
    """lint PASS 시 sentinel 파일 발급. boundary 파일의 SHA256 + lint 버전 + 타임스탬프 + 매직 마커.
    수기 touch 우회 불가 (해시 일치 검증).
    """
    h = file_sha256(boundary_path)
    payload = {
        "magic": SENTINEL_MAGIC,
        "lint_version": LINT_VERSION,
        "boundary_sha256": h,
        "boundary_path": str(boundary_path),
        "issued_at": timestamp,
    }
    sentinel_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def check_sentinel(boundary_path: Path, sentinel_path: Path) -> Tuple[bool, str]:
    """sentinel 유효성 검증. (True, "") 또는 (False, 사유).

    실패 사유:
      - sentinel 파일 없음 → "lint 미실행"
      - 매직 마커 불일치 → "수기 touch 우회 시도"
      - lint 버전 불일치 → "lint 도구 갱신, 재실행 필요"
      - 해시 불일치 → "auth-boundary.json 변경됨, 재 lint 필요"
    """
    if not boundary_path.is_file():
        return (False, f"auth-boundary.json 부재: {boundary_path}")
    if not sentinel_path.is_file():
        return (
            False,
            f"sentinel 파일 부재: {sentinel_path} — lint_auth_boundary.py를 실행하지 않았거나 lint FAIL 상태",
        )
    try:
        payload = json.loads(sentinel_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return (False, f"sentinel 파일 손상 (JSON 파싱 실패): {e}")
    if not isinstance(payload, dict):
        return (False, "sentinel 파일 내용이 객체가 아님")
    if payload.get("magic") != SENTINEL_MAGIC:
        return (
            False,
            "sentinel 매직 마커 불일치 — 수기 touch 시도 또는 sentinel 손상",
        )
    if payload.get("lint_version") != LINT_VERSION:
        return (
            False,
            f"sentinel lint 버전 불일치: {payload.get('lint_version')} vs 현재 {LINT_VERSION} — lint 재실행 필요",
        )
    expected_hash = file_sha256(boundary_path)
    if payload.get("boundary_sha256") != expected_hash:
        return (
            False,
            "sentinel SHA256 불일치 — auth-boundary.json이 lint 이후 변경됨, lint 재실행 필요",
        )
    return (True, "")
