#!/usr/bin/env python3
"""v11a_fixture_validator.py — V11A-a fixture 자체 정합성 검증

`tests/fixtures/<project-id>/expected-auth-boundary.json`의 모든 evidence_paths가
실제 코드에 존재하는지(파일 + 라인) 검증한다.

본 스크립트는 fixture가 다이어그램과 코드 사이에서 잘못 작성된 경우(예: line 번호 stale)를
검출한다. v11 구현 PR과 무관하게 fixture 자체 회귀 검증용.

사용:
  python3 v11a_fixture_validator.py <fixture-path> --project-root <project-root>

Exit code:
  0: 모든 evidence_paths 검증 통과
  1: 하나 이상의 evidence_paths가 실제 파일/라인과 불일치
"""
import argparse
import json
import sys
from pathlib import Path


def validate_evidence_paths(fixture: dict, project_root: Path) -> list[str]:
    """모든 evidence_paths의 file:line이 실재하는지 확인. 위반 사항을 반환."""
    failures: list[str] = []

    def check_path(ev: str, ctx: str) -> None:
        # `path:line` 또는 `path` 형식
        if ":" in ev:
            path_str, _, line_str = ev.rpartition(":")
            try:
                line = int(line_str)
            except ValueError:
                # 콜론이 line이 아닌 경우 (드물지만)
                path_str = ev
                line = None
        else:
            path_str = ev
            line = None

        full = (project_root / path_str).resolve()
        if not full.is_file():
            failures.append(f"{ctx}: 파일 없음 — {ev}")
            return
        if line is None:
            return
        try:
            text = full.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            failures.append(f"{ctx}: 파일 읽기 실패 — {ev} ({e})")
            return
        line_count = len(text.splitlines())
        if line < 1 or line > line_count:
            failures.append(
                f"{ctx}: 라인 번호 범위 초과 — {ev} (실제 {line_count}줄)"
            )

    for gw in fixture.get("gateways", []):
        for ev in gw.get("evidence_paths", []):
            check_path(ev, f"gateways[id={gw.get('id')}]")
    for cl in fixture.get("clients", []):
        for ev in cl.get("evidence_paths", []):
            check_path(ev, f"clients[id={cl.get('id')}]")
    for rt in fixture.get("routes", []):
        for ev in rt.get("evidence_paths", []):
            check_path(ev, f"routes[surface_key={rt.get('surface_key')}]")
    return failures


def validate_schema_basic(fixture: dict) -> list[str]:
    """fixture가 schema의 최소 형식을 따르는지 확인."""
    failures: list[str] = []
    if "applicable" not in fixture:
        failures.append("최상위 'applicable' 필드 부재")
    if fixture.get("applicable") is True:
        if not fixture.get("gateways") and not fixture.get("unknowns"):
            failures.append(
                "applicable=true인데 gateways/unknowns 모두 비어있음"
            )
    elif fixture.get("applicable") is False:
        if "reason" not in fixture:
            failures.append("applicable=false인데 reason 필드 부재")
        elif fixture["reason"] not in {
            "no_auth_layer_detected",
            "topology_unresolved",
            "user_skip",
        }:
            failures.append(f"reason enum 위반: {fixture['reason']}")

    # routes의 client_ids 참조 무결성
    client_ids = {c.get("id") for c in fixture.get("clients", [])}
    for rt in fixture.get("routes", []):
        for cid in rt.get("client_ids") or []:
            if cid not in client_ids:
                failures.append(
                    f"routes[surface_key={rt.get('surface_key')}].client_ids 참조 무결성 위반: '{cid}'가 clients에 없음"
                )

    # routes의 gateway_id 참조 무결성 (None 허용)
    gateway_ids = {g.get("id") for g in fixture.get("gateways", [])}
    for rt in fixture.get("routes", []):
        gid = rt.get("gateway_id")
        if gid is not None and gid not in gateway_ids:
            failures.append(
                f"routes[surface_key={rt.get('surface_key')}].gateway_id 참조 무결성 위반: '{gid}'가 gateways에 없음"
            )

    # failure_modes enum
    valid_modes = {
        "gateway_basepath_mismatch",
        "credential_mismatch",
        "missing_auth_header",
        "downstream_propagation",
    }
    for rt in fixture.get("routes", []):
        for mode in rt.get("failure_modes") or []:
            if mode not in valid_modes:
                failures.append(
                    f"routes[surface_key={rt.get('surface_key')}].failure_modes enum 위반: '{mode}'"
                )

    return failures


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("fixture_path", help="expected-auth-boundary.json 경로")
    p.add_argument(
        "--project-root",
        required=True,
        help="evidence_paths가 가리키는 프로젝트 루트",
    )
    args = p.parse_args()

    fixture_path = Path(args.fixture_path)
    project_root = Path(args.project_root).resolve()

    if not fixture_path.is_file():
        print(f"FAIL: fixture 파일 없음: {fixture_path}", file=sys.stderr)
        return 1

    try:
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"FAIL: fixture JSON 파싱 실패: {e}", file=sys.stderr)
        return 1

    schema_failures = validate_schema_basic(fixture)
    evidence_failures = validate_evidence_paths(fixture, project_root)

    all_failures = schema_failures + evidence_failures
    if all_failures:
        print(f"FAIL: fixture 검증 위반 {len(all_failures)}건")
        for f in all_failures:
            print(f"  - {f}")
        return 1

    n_gw = len(fixture.get("gateways", []))
    n_cl = len(fixture.get("clients", []))
    n_rt = len(fixture.get("routes", []))
    print(
        f"OK: fixture 검증 통과 (gateways={n_gw}, clients={n_cl}, routes={n_rt})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
