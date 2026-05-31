#!/usr/bin/env python3
"""IDOR 검토 인벤토리를 K개 샤드로 분할(레버4: deep-read 샤딩).

목적: 예산 확장. idor-scanner의 검토 단위는 *파일*(각 `#### <파일>` 블록을 통째로 Read하고
service 계층까지 따라가 모든 엔드포인트의 소유권 게이트를 확인)이다. 인벤토리가 수백 파일이면
단일 에이전트는 컨텍스트 예산이 터져 일부만 deep-read하고 나머지를 [미확인]/[INCOMPLETE]로
방치한다(AI-1/AI-4가 이렇게 누락됐다). 이 도구는 인벤토리를 *파일 원자성*을 지키며 K개 샤드로
균형 분할하여, 오케스트레이터가 샤드당 1개 서브에이전트를 병렬 디스패치하게 한다 — 각 에이전트가
자기 예산으로 자기 슬라이스를 deep-read하므로 총 커버리지가 늘고 "단일 에이전트 예산 초과"가
구조적으로 해소된다.

설계 불변식:
- **파일 원자성**: 한 파일의 모든 행은 같은 샤드에 둔다(phase1.md "검토 단위=파일"; sibling 메서드·
  공유 service를 한 에이전트가 함께 봐야 판정 정확). 파일을 쪼개지 않는다.
- **균형**: 샤드 간 검토 비용(≈행 수, [제외] 가중)을 LPT(longest-processing-time) 그리디로 균등화.
- **우선순위 보존**: 입력의 파일 순서([제외] 포함 파일 우선)를 가중치에 반영해 고신호 파일이
  앞 샤드에 모이도록 한다(예산 소진 전 읽힘).
- **무손실**: 모든 파일 섹션이 정확히 한 샤드에 들어간다(분할 전후 행 수 보존).

언어/프레임워크 무관: 인벤토리 MD 구조(`#### <파일>` + 표)만 다루므로 Spring/FastAPI/Go/Rails 등
모든 어댑터 출력에 동일하게 동작한다(패턴 매칭 의미판단 없음 — 순수 분할).

사용:
  python3 idor_shard.py <inventory.md> --shards K --out-dir <dir>
  python3 idor_shard.py <inventory.md> --rows-per-shard N --out-dir <dir>   # K 자동계산
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

_FILE_HEADER_RE = re.compile(r'^####\s+(\S.*?)\s*(?:—|$)')
# MULTILINE: 인벤토리 헤더는 결과 MD 중간(372행 등)에 임베드될 수 있다.
_INVENTORY_HEADER_RE = re.compile(r'^###\s+IDOR 검토 인벤토리', re.MULTILINE)


def parse_inventory(text: str) -> tuple[list[str], list[dict]]:
    """인벤토리 MD를 (프리앰블 라인들, 파일섹션 리스트)로 파싱.

    파일섹션 = {'file', 'lines'(섹션 전체 라인), 'rows'(데이터행 수), 'excluded'([제외] 행 수)}.
    프리앰블 = 첫 `#### <파일>` 이전(헤더+요약+범례). 샤드마다 헤더를 재부착하는 데 쓴다.
    """
    lines = text.splitlines()
    preamble: list[str] = []
    sections: list[dict] = []
    cur: dict | None = None
    for ln in lines:
        if _FILE_HEADER_RE.match(ln):
            if cur is not None:
                sections.append(cur)
            cur = {"file": _FILE_HEADER_RE.match(ln).group(1), "lines": [ln], "rows": 0, "excluded": 0}
            continue
        if cur is None:
            preamble.append(ln)
        else:
            cur["lines"].append(ln)
            s = ln.strip()
            # 데이터 행: `| [ ] | ...` (헤더/구분행 제외)
            if s.startswith("| [") or (s.startswith("|") and "엔드포인트" not in s
                                       and set(s) - set("-:| ")):
                if s.startswith("| ["):
                    cur["rows"] += 1
                    if "[제외]" in s:
                        cur["excluded"] += 1
    if cur is not None:
        sections.append(cur)
    return preamble, sections


def _weight(section: dict) -> int:
    """파일 섹션의 검토 비용 가중치. 행 수 + [제외] 행 가산(고신호=더 정밀 검토)."""
    return section["rows"] + 2 * section["excluded"] + 1  # +1: 빈 파일도 최소 비용


def balance_shards(sections: list[dict], k: int) -> list[list[dict]]:
    """파일 섹션을 K개 샤드로 균형 분할(LPT 그리디, 파일 원자성 유지).

    입력 순서(우선순위)를 보존하기 위해, 가중치 동률 시 원래 인덱스가 작은 파일을 먼저 배치한다.
    """
    k = max(1, k)
    shards: list[list[dict]] = [[] for _ in range(k)]
    loads = [0] * k
    # LPT: 무거운 파일부터. 동률은 원래 순서(우선순위) 보존.
    order = sorted(range(len(sections)), key=lambda i: (-_weight(sections[i]), i))
    for i in order:
        j = min(range(k), key=lambda s: (loads[s], s))  # 최소 부하 샤드(동률은 앞 샤드)
        shards[j].append(sections[i])
        loads[j] += _weight(sections[i])
    # 각 샤드 내부는 원래 파일 순서로 정렬(우선순위·가독성)
    idx = {id(s): n for n, s in enumerate(sections)}
    for sh in shards:
        sh.sort(key=lambda s: idx[id(s)])
    return [sh for sh in shards if sh]  # 빈 샤드 제거


def render_shard(preamble: list[str], shard: list[dict], shard_no: int, total: int) -> str:
    out = list(preamble)
    out.append(f"<!-- IDOR SHARD {shard_no}/{total} — {len(shard)} 파일 -->")
    out.append("")
    for sec in shard:
        out.extend(sec["lines"])
        if out and out[-1].strip():
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("inventory", help="idor 인벤토리 MD 경로(또는 idor-scanner.md)")
    ap.add_argument("--shards", type=int, default=None, help="샤드 개수 K")
    ap.add_argument("--rows-per-shard", type=int, default=60, help="샤드당 목표 행 수(K 자동계산)")
    ap.add_argument("--out-dir", required=True, help="샤드 파일 출력 디렉토리")
    ap.add_argument("--max-shards", type=int, default=18, help="K 자동계산 상한")
    args = ap.parse_args()

    text = Path(args.inventory).read_text(encoding="utf-8")
    m = _INVENTORY_HEADER_RE.search(text)
    if not m:
        print("ERROR: '### IDOR 검토 인벤토리' 헤더를 찾지 못함.", file=sys.stderr)
        return 1
    # 인벤토리 헤더부터 슬라이스: 앞쪽 후보(①②) prose를 프리앰블에서 제외(인벤토리만 샤딩).
    preamble, sections = parse_inventory(text[m.start():])
    total_rows = sum(s["rows"] for s in sections)

    if args.shards:
        k = args.shards
    else:
        k = max(1, min(args.max_shards, math.ceil(total_rows / max(1, args.rows_per_shard))))

    shards = balance_shards(sections, k)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = {"total_files": len(sections), "total_rows": total_rows,
                "shards": len(shards), "files": []}
    for n, sh in enumerate(shards, 1):
        p = out_dir / f"idor_shard_{n}.md"
        p.write_text(render_shard(preamble, sh, n, len(shards)), encoding="utf-8")
        rows = sum(s["rows"] for s in sh)
        manifest["files"].append({"shard": n, "path": str(p), "files": len(sh),
                                  "rows": rows, "excluded": sum(s["excluded"] for s in sh)})
    (out_dir / "idor_shards_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    # 무손실 검증: 분할 전후 행 수 보존
    split_rows = sum(f["rows"] for f in manifest["files"])
    status = "OK" if split_rows == total_rows else f"FAIL(행 손실 {total_rows}→{split_rows})"
    print(f"샤드 {len(shards)}개 생성: {out_dir} (총 {len(sections)}파일/{total_rows}행, 무손실={status})")
    for f in manifest["files"]:
        print(f"  샤드{f['shard']}: {f['files']}파일 {f['rows']}행([제외]{f['excluded']})")
    return 0 if split_rows == total_rows else 2


if __name__ == "__main__":
    sys.exit(main())
