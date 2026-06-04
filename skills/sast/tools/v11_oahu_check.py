#!/usr/bin/env python3
"""v11_oahu_check.py — V11A-a oahu-feed 회귀 검증 (정량 기준)

`tests/fixtures/oahu-feed/expected-auth-boundary.json`(ground truth)과
실제 산출물(`<PHASE1_RESULTS_DIR>/auth-boundary.json`)을 비교한다.

V11A-a 정량 기준 (6개, expected fixture의 `_v11a_acceptance_criteria`에 정의):
  1. surface_key 집합 일치율 ≥ 95%
  2. gateway_id 매핑 100% (각 surface가 올바른 gateway에 연결)
  3. cross_gateway_hops 누락 0건 (chain-analysis 연동, 본 도구는 fixture에 표기된 값만 비교)
  4. clients 페르소나 ≥ 4종
  5. mermaid 흐름도 노드 수 ≥ expected의 100% (gateways + clients + 표면)
  6. failure_modes 1건 이상 표기

사용:
  python3 v11_oahu_check.py <expected-fixture> <actual-auth-boundary>

Exit code:
  0: 6개 정량 기준 모두 PASS
  1: 하나 이상 FAIL
  2: 입력 오류
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from _validate_auth_boundary import normalize_surface_key  # noqa: E402


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("expected_fixture", help="V11A-a expected fixture 경로")
    p.add_argument("actual_boundary", help="실제 auth-boundary.json 경로")
    args = p.parse_args()

    exp_path = Path(args.expected_fixture)
    act_path = Path(args.actual_boundary)

    if not exp_path.is_file():
        print(f"FAIL: expected fixture 없음: {exp_path}", file=sys.stderr)
        return 2
    if not act_path.is_file():
        print(f"FAIL: actual auth-boundary.json 없음: {act_path}", file=sys.stderr)
        return 2

    try:
        expected = load_json(exp_path)
        actual = load_json(act_path)
    except json.JSONDecodeError as e:
        print(f"FAIL: JSON 파싱 실패: {e}", file=sys.stderr)
        return 2

    criteria = expected.get("_v11a_acceptance_criteria", {})
    results: list[tuple[str, bool, str]] = []

    # 1. surface_key 일치율
    exp_routes = expected.get("routes") or []
    act_routes = actual.get("routes") or []
    exp_keys = {normalize_surface_key(r["surface_key"]) for r in exp_routes if r.get("surface_key")}
    act_keys = {normalize_surface_key(r["surface_key"]) for r in act_routes if r.get("surface_key")}
    if exp_keys:
        matched = exp_keys & act_keys
        rate = len(matched) / len(exp_keys)
    else:
        rate = 1.0
    min_rate = criteria.get("surface_key_match_rate_min", 0.95)
    results.append(
        (
            "1. surface_key 일치율 ≥ " + f"{min_rate:.0%}",
            rate >= min_rate,
            f"matched={len(exp_keys & act_keys)}/{len(exp_keys)} ({rate:.0%}), 누락={list(exp_keys - act_keys)[:3]}",
        )
    )

    # 2. gateway_id 매핑 100%
    exp_map = {
        normalize_surface_key(r["surface_key"]): r.get("gateway_id")
        for r in exp_routes
        if r.get("surface_key")
    }
    act_map = {
        normalize_surface_key(r["surface_key"]): r.get("gateway_id")
        for r in act_routes
        if r.get("surface_key")
    }
    mismatched: list[str] = []
    for k, exp_gw in exp_map.items():
        act_gw = act_map.get(k)
        if act_gw != exp_gw:
            mismatched.append(f"{k}: expected={exp_gw} actual={act_gw}")
    results.append(
        (
            "2. gateway_id 매핑 100%",
            not mismatched,
            f"불일치 {len(mismatched)}건: {mismatched[:3]}",
        )
    )

    # 3. cross_gateway_hops 누락 0건
    # expected가 cross_gateway_hops를 명시한 경우만 검증 (fixture에 정의 없으면 N/A)
    exp_hops_count = sum(
        len(r.get("cross_gateway_hops") or []) for r in exp_routes
    )
    act_hops_count = sum(
        len(r.get("cross_gateway_hops") or []) for r in act_routes
    )
    results.append(
        (
            "3. cross_gateway_hops 누락 0건",
            act_hops_count >= exp_hops_count,
            f"expected={exp_hops_count}, actual={act_hops_count}",
        )
    )

    # 4. clients 페르소나 수
    exp_personas = {
        c.get("persona") for c in (expected.get("clients") or [])
    } - {None}
    act_personas = {
        c.get("persona") for c in (actual.get("clients") or [])
    } - {None}
    min_personas = criteria.get("clients_persona_min", 4)
    results.append(
        (
            f"4. clients 페르소나 ≥ {min_personas}종",
            len(act_personas) >= min_personas,
            f"actual={len(act_personas)} ({sorted(act_personas)[:4]})",
        )
    )

    # 5. mermaid 노드 수 (gateways + clients + 표면)
    exp_nodes = (
        len(expected.get("gateways") or [])
        + len(expected.get("clients") or [])
        + len(exp_routes)
    )
    act_nodes = (
        len(actual.get("gateways") or [])
        + len(actual.get("clients") or [])
        + len(act_routes)
    )
    min_nodes = criteria.get("mermaid_node_count_min", exp_nodes)
    results.append(
        (
            f"5. mermaid 노드 수 ≥ {min_nodes}",
            act_nodes >= min_nodes,
            f"actual={act_nodes} (gateways={len(actual.get('gateways') or [])}, clients={len(actual.get('clients') or [])}, routes={len(act_routes)})",
        )
    )

    # 6. failure_modes 1건 이상
    act_fm_count = sum(len(r.get("failure_modes") or []) for r in act_routes)
    min_fm = criteria.get("failure_modes_min_total", 1)
    results.append(
        (
            f"6. failure_modes ≥ {min_fm}건",
            act_fm_count >= min_fm,
            f"actual={act_fm_count}건",
        )
    )

    # 결과 출력
    print("=" * 60)
    print("V11A-a oahu-feed 회귀 검증 결과")
    print(f"  expected: {exp_path}")
    print(f"  actual:   {act_path}")
    print("=" * 60)
    pass_count = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    for crit, ok, msg in results:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {crit}")
        if msg:
            print(f"         {msg}")
    print("-" * 60)
    print(f"  {pass_count}/{total} PASS")

    return 0 if pass_count == total else 1


if __name__ == "__main__":
    sys.exit(main())
