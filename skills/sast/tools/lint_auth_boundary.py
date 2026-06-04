#!/usr/bin/env python3
"""lint_auth_boundary.py — auth-boundary.json lint + sentinel 발급

Step 3-1 산출물(auth-boundary.json)을 검증한다. PASS 시 별도 sentinel 파일
(`auth-boundary.lint-passed`)을 발급한다. 후속 단계(`select_scanners.py`,
`phase1_build_master_list.py`)는 sentinel을 입력 의존성으로 검증한다.

검증 항목 (L11-0 ~ L11-5):
  L11-0: schema 형식 (applicable, reason enum, gateways/unknowns 비어있지 않음)
  L11-1: routes의 client_ids/gateway_id 참조 무결성
  L11-2: failure_modes enum
  L11-3: 흐름도 게이팅 정보성 출력 (routes/clients/gateways ≥2면 흐름도 권고)
  (L11-4: 후보-routes 매칭 강제는 보고서 lint 단계에서 수행 — validate_report.py)

사용:
  python3 lint_auth_boundary.py <auth-boundary.json 경로> \
    [--sentinel <sentinel 경로>] [--quiet]

Exit code:
  0: 검증 통과 + sentinel 발급
  1: 검증 실패 (sentinel 미발급 or 기존 sentinel 제거)
  2: 입력 오류 (파일 없음·JSON 파싱 실패)
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# 같은 디렉터리의 _validate_auth_boundary 모듈 import
_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from _validate_auth_boundary import (  # noqa: E402
    LINT_VERSION,
    validate_auth_boundary,
    write_sentinel,
)

DEFAULT_SENTINEL_NAME = "auth-boundary.lint-passed"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("boundary_path", help="auth-boundary.json 경로")
    p.add_argument(
        "--sentinel",
        default=None,
        help="sentinel 발급 경로 (기본: <boundary_path 디렉터리>/auth-boundary.lint-passed)",
    )
    p.add_argument(
        "--quiet", action="store_true", help="PASS 시 출력 최소화"
    )
    args = p.parse_args()

    boundary_path = Path(args.boundary_path)
    if not boundary_path.is_file():
        print(f"FAIL: auth-boundary.json 파일 없음: {boundary_path}", file=sys.stderr)
        return 2

    try:
        data = json.loads(boundary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"FAIL: JSON 파싱 실패: {e}", file=sys.stderr)
        return 2

    sentinel_path = (
        Path(args.sentinel)
        if args.sentinel
        else boundary_path.parent / DEFAULT_SENTINEL_NAME
    )

    failures = validate_auth_boundary(data)

    if failures:
        # 기존 sentinel이 있으면 제거 (FAIL 상태에서 stale sentinel 잔존 방지)
        if sentinel_path.is_file():
            try:
                sentinel_path.unlink()
            except OSError:
                pass
        print(f"FAIL: lint 위반 {len(failures)}건")
        for f in failures:
            print(f"  - {f}")
        return 1

    # PASS — sentinel 발급 (atomic write: .tmp 후 rename)
    timestamp = datetime.now(timezone.utc).isoformat()
    tmp = sentinel_path.with_suffix(sentinel_path.suffix + ".tmp")
    write_sentinel(boundary_path, tmp, timestamp)
    tmp.replace(sentinel_path)

    # 흐름도 게이팅 정보성 출력 (L11-3)
    n_routes = len(data.get("routes") or [])
    n_clients = len(data.get("clients") or [])
    n_gateways = len(data.get("gateways") or [])
    needs_flowchart = (
        n_routes >= 2 or n_clients >= 2 or n_gateways >= 2
    )

    if not args.quiet:
        print(f"OK: lint 통과 (lint_version={LINT_VERSION})")
        print(f"  gateways={n_gateways}, clients={n_clients}, routes={n_routes}")
        if needs_flowchart:
            print(
                f"  → mermaid 흐름도 필수 (routes/clients/gateways 중 ≥2)"
            )
        else:
            print(
                f"  → mermaid 흐름도 선택 (routes/clients/gateways 모두 단일)"
            )
        print(f"  sentinel 발급: {sentinel_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
