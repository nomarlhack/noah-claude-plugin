#!/usr/bin/env python3
"""v11_general_acceptance.py — V11A-b 일반 수용 기준 검증

모든 프로젝트에 적용 가능한 ground-truth 무관 기준만 검증한다.
oahu-feed 회귀(V11A-a)는 별도 v11a_fixture_validator.py + v11_oahu_check.py.

검증 기준:
  V11A-b-1: auth-boundary.json schema 통과율 100% (lint_auth_boundary.py와 동일 로직)
  V11A-b-2: applicable=false면 reason 필수 + enum 값
  V11A-b-3: applicable=true면 gateways OR unknowns 중 하나 non-empty
  V11A-b-4: 보고서(noah-sast-report.md)의 모든 후보 진입 경계가 routes에 M5 매칭

사용:
  python3 v11_general_acceptance.py <auth-boundary.json 경로> [--report <report.md>]

Exit code:
  0: 모든 기준 PASS
  1: 하나 이상 FAIL
  2: 입력 오류
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from _validate_auth_boundary import (  # noqa: E402
    match_surface_key,
    validate_auth_boundary,
    VALID_REASONS,
)

# 보고서 본문에서 `**진입 경계**: <METHOD> <path> ...` 라인 추출
# SKILL.md/vuln-format에 형식 의무화: METHOD path [via gateway_id] [기타]
_ENTRY_LINE_RE = re.compile(
    r"^\*\*진입 경계\*\*:\s*(?P<method>[A-Z*]+|\[[^\]]+\])\s*(?P<path>[^\s(]+)",
    re.MULTILINE,
)


def parse_report_entry_keys(report_text: str) -> list[str]:
    """보고서에서 `**진입 경계**: METHOD path` 추출. (M5 매칭용 키 후보)"""
    keys: list[str] = []
    for m in _ENTRY_LINE_RE.finditer(report_text):
        method = m.group("method").strip("[]")
        path = m.group("path").strip()
        if method and path:
            keys.append(f"{method} {path}")
    return keys


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("boundary_path", help="auth-boundary.json 경로")
    p.add_argument(
        "--report",
        default=None,
        help="보고서 MD 경로 (V11A-b-4 검증용). 미지정 시 V11A-b-1~3만 수행.",
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

    results: list[tuple[str, bool, str]] = []  # (criterion, pass, msg)

    # V11A-b-1: schema 통과율 100%
    schema_failures = validate_auth_boundary(data)
    if schema_failures:
        results.append(
            (
                "V11A-b-1 schema 통과율 100%",
                False,
                f"위반 {len(schema_failures)}건: {schema_failures[:3]}",
            )
        )
    else:
        results.append(("V11A-b-1 schema 통과율 100%", True, ""))

    # V11A-b-2 & V11A-b-3: reason / gateways·unknowns
    # (validate_auth_boundary가 이미 검증했지만 명시적으로 분리 보고)
    applicable = data.get("applicable")
    if applicable is False:
        reason = data.get("reason")
        if reason in VALID_REASONS and reason != "topology_unresolved":
            results.append(
                (
                    "V11A-b-2 applicable=false reason 검증",
                    True,
                    f"정당 우회: {reason}",
                )
            )
            # V11A-b-3 N/A
            results.append(
                (
                    "V11A-b-3 gateways/unknowns non-empty",
                    True,
                    "N/A (applicable=false)",
                )
            )
        else:
            results.append(
                (
                    "V11A-b-2 applicable=false reason 검증",
                    False,
                    f"reason 누락/위반: {reason}",
                )
            )
            results.append(
                (
                    "V11A-b-3 gateways/unknowns non-empty",
                    False,
                    "N/A (applicable=false 처리 실패)",
                )
            )
    elif applicable is True:
        gw = data.get("gateways") or []
        un = data.get("unknowns") or []
        if gw or un:
            results.append(
                (
                    "V11A-b-3 gateways/unknowns non-empty",
                    True,
                    f"gateways={len(gw)}, unknowns={len(un)}",
                )
            )
        else:
            results.append(
                (
                    "V11A-b-3 gateways/unknowns non-empty",
                    False,
                    "applicable=true인데 gateways·unknowns 모두 비어있음",
                )
            )
        results.append(
            (
                "V11A-b-2 applicable=false reason 검증",
                True,
                "N/A (applicable=true)",
            )
        )
    else:
        results.append(
            (
                "V11A-b-2 applicable=false reason 검증",
                False,
                f"applicable이 bool 아님: {applicable}",
            )
        )
        results.append(
            (
                "V11A-b-3 gateways/unknowns non-empty",
                False,
                "applicable이 bool 아님",
            )
        )

    # V11A-b-4: 보고서 진입 경계 매칭 (--report 제공 시만)
    if args.report:
        report_path = Path(args.report)
        if not report_path.is_file():
            results.append(
                (
                    "V11A-b-4 보고서 진입 경계 routes 매칭",
                    False,
                    f"보고서 파일 없음: {report_path}",
                )
            )
        else:
            report_text = report_path.read_text(encoding="utf-8")
            entry_keys = parse_report_entry_keys(report_text)
            if not entry_keys:
                results.append(
                    (
                        "V11A-b-4 보고서 진입 경계 routes 매칭",
                        True,
                        "보고서에 진입 경계 라인 0건 (검증 대상 없음)",
                    )
                )
            else:
                route_keys = [
                    r.get("surface_key", "")
                    for r in (data.get("routes") or [])
                    if r.get("surface_key")
                ]
                unmatched: list[str] = []
                for ek in entry_keys:
                    matched = any(
                        match_surface_key(ek, rk) for rk in route_keys
                    )
                    if not matched:
                        unmatched.append(ek)
                if unmatched:
                    results.append(
                        (
                            "V11A-b-4 보고서 진입 경계 routes 매칭",
                            False,
                            f"매칭 실패 {len(unmatched)}건 / 전체 {len(entry_keys)}건: {unmatched[:3]}",
                        )
                    )
                else:
                    results.append(
                        (
                            "V11A-b-4 보고서 진입 경계 routes 매칭",
                            True,
                            f"전체 {len(entry_keys)}건 매칭",
                        )
                    )

    # 결과 출력
    print("=" * 60)
    print("V11A-b 일반 수용 기준 검증 결과")
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
