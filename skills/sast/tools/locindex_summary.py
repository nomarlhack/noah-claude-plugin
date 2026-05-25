#!/usr/bin/env python3
"""
locindex.json을 파일별 그룹핑 요약으로 변환한다.

Phase 1 에이전트는 locindex.json을 Read 도구로 직접 읽지 않고
이 스크립트를 Bash로 실행하여 출력을 분석 입력으로 사용한다.

출력 구조:
  - 헤더: 스캐너명 + tier별 총 건수
  - 파일별 1줄: best_tier / taint·ast·generic 건수 / sink 룰 여부 / 파일명
  - tier 내림차순(taint→ast→generic), 동 tier 내 taint 건수 내림차순 정렬
  - 노이즈 파일(vendor, min.js, 룰 YAML 등) 자동 제거 후 별도 집계

에이전트 활용 방법:
  1. 출력 전체를 읽어 어떤 파일이 어느 tier에서 매칭됐는지 파악한다.
  2. [SINK] 표시 파일을 우선 Read하여 실제 sink 코드 확인.
  3. taint best_tier 파일에서 source→sink 데이터흐름 추적.
  4. ast/generic만 있는 파일은 파일당 1회 Read로 패턴 의미 확인.
  5. 노이즈 요약의 건수가 COVERAGE accounted 계산에 포함됨.

사용법:
  python3 locindex_summary.py <locindex.json 경로>
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# 노이즈 패턴: 실제 취약점 분석 대상이 아닌 파일 경로 기준
# ---------------------------------------------------------------------------
NOISE_PATTERNS = [
    "vendor/",
    ".min.js:",
    "node_modules/",
    ".yaml:",
    ".yml:",
    "/sast/scanners/",
    "/sast/tools/",
    "noah-8719/skills/",
    "qunit",
    "Chart2.9",
]

TIER_RANK = {"taint": 3, "ast": 2, "generic": 1}


def is_noise(loc: str) -> bool:
    return any(p in loc for p in NOISE_PATTERNS)


def is_sink_rule(rule_ids: list) -> bool:
    """sink 또는 taint 룰 여부 — 고신뢰 HTML sink 신호."""
    return any("sink" in r or "taint" in r for r in rule_ids)


def main():
    if len(sys.argv) < 2:
        print("usage: locindex_summary.py <locindex.json>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"[ERROR] 파일 없음: {path}", file=sys.stderr)
        sys.exit(1)

    d = json.loads(path.read_text(encoding="utf-8"))
    locations: dict = d.get("locations", {})
    meta: dict = d.get("_scanner", {})
    tc: dict = meta.get("tier_counts", {})

    scanner_name = meta.get("name", path.stem.replace(".locindex", ""))
    total = sum(tc.values())

    # -------------------------------------------------------------------
    # 파일별 집계
    # -------------------------------------------------------------------
    file_info: dict = defaultdict(lambda: {
        "taint": 0, "ast": 0, "generic": 0,
        "has_sink": False, "rules": set(), "best_tier": "generic",
        "full_paths": set(),
    })
    noise_counts: Counter = Counter()

    for loc, v in locations.items():
        tier = v.get("tier", "generic")
        rule_ids = v.get("rule_ids", [])
        fname = Path(loc.split(":")[0]).name

        if is_noise(loc):
            noise_counts[tier] += 1
            continue

        info = file_info[fname]
        info[tier] += 1
        info["full_paths"].add(loc.split(":")[0])
        for r in rule_ids:
            info["rules"].add(r)
        if is_sink_rule(rule_ids):
            info["has_sink"] = True
        if TIER_RANK.get(tier, 0) > TIER_RANK.get(info["best_tier"], 0):
            info["best_tier"] = tier

    # -------------------------------------------------------------------
    # 정렬: best_tier 내림차순 → taint 건수 내림차순 → 파일명 오름차순
    # -------------------------------------------------------------------
    sorted_files = sorted(
        file_info.items(),
        key=lambda x: (
            -TIER_RANK.get(x[1]["best_tier"], 0),
            -x[1]["taint"],
            -x[1]["ast"],
            x[0],
        ),
    )

    real_total = sum(
        info["taint"] + info["ast"] + info["generic"]
        for _, info in file_info.items()
    )
    noise_total = sum(noise_counts.values())

    # -------------------------------------------------------------------
    # 출력
    # -------------------------------------------------------------------
    print(f"=== {scanner_name} 매칭 파일 요약 ===")
    print(f"총 {total}건 → 실제 {real_total}건 / 노이즈 제거 {noise_total}건")
    print(f"tier: taint={tc.get('taint',0)} ast={tc.get('ast',0)} generic={tc.get('generic',0)}")
    print(f"파일 수: {len(file_info)}개")
    print()
    print(f"{'best_tier':<9} {'t':>4} {'a':>5} {'g':>5}  {'파일명'}")
    print("-" * 70)

    for fname, info in sorted_files:
        t = info["taint"]
        a = info["ast"]
        g = info["generic"]
        best = info["best_tier"]
        sink_mark = " [SINK]" if info["has_sink"] else ""
        paths = sorted(info["full_paths"])
        path_hint = f"  ({len(paths)}개 경로)" if len(paths) > 1 else ""
        print(f"{best:<9} {t:>4} {a:>5} {g:>5}  {fname}{sink_mark}{path_hint}")

    print()
    if noise_total > 0:
        noise_detail = " ".join(f"{tier}={cnt}" for tier, cnt in sorted(noise_counts.items()))
        print(f"[노이즈 제거] {noise_total}건 ({noise_detail}) — vendor/min/YAML/룰파일")
    print()
    print("컬럼 설명: best_tier=파일 내 최고 tier | t=taint건수 a=ast건수 g=generic건수")
    print("[SINK] = innerHTML/dangerouslySetInnerHTML 등 고정밀 sink 룰 매치 포함")
    print()
    print("에이전트 분석 순서:")
    print("  1) [SINK] 파일 → Read하여 sink 코드 및 source 추적")
    print("  2) best_tier=taint 파일 → source→sink dataflow 확인")
    print("  3) best_tier=ast 파일 → 패턴 의미 확인 (파일당 1회 Read)")
    print("  4) best_tier=generic 파일 → 클래스 판정 후 대량 제외 가능")


if __name__ == "__main__":
    main()
