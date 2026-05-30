#!/usr/bin/env python3
"""idor_shard.py (레버4: deep-read 샤딩) 회귀 테스트.

핵심 불변식: (1) 파일 원자성 — 한 파일의 행은 한 샤드에만, (2) 무손실 — 분할 전후 행 수 보존,
(3) 균형 — 샤드 간 부하 균등, (4) 우선순위 보존 — [제외] 포함 파일이 앞 샤드에 모임.
프레임워크 무관(인벤토리 MD 구조만 다룸).
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_MOD = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "idor_shard.py")
_spec = importlib.util.spec_from_file_location("idor_shard", _MOD)
sh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sh)

_HDR = (
    "### IDOR 검토 인벤토리 (기계 생성)\n\n"
    "요약 줄.\n\n"
    "> 범례 줄.\n\n"
)
_COLS = "| 확인 | 엔드포인트 | 외부입력(파라미터) | 위치 | 출처 | 인증 | 소유권게이트 |\n|---|---|---|---|---|---|---|\n"


def _file_section(fname: str, rows: list[tuple]) -> str:
    excl = sum(1 for _, auth in rows if auth == "[제외]")
    out = [f"#### {fname}  — 엔드포인트 {len(rows)}개" + (f" · 인증 미경유 {excl}개" if excl else ""), "", _COLS.rstrip()]
    for i, (ep, auth) in enumerate(rows):
        out.append(f"| [ ] | GET {ep} | id(@PathVariable) | {fname}:{10+i} | taint | {auth} | [미확인] |")
    out.append("")
    return "\n".join(out)


def _inventory(files: list[tuple]) -> str:
    body = "\n".join(_file_section(f, rows) for f, rows in files)
    return _HDR + body + "\n"


class TestParseInventory(unittest.TestCase):
    def test_counts_rows_and_excluded(self):
        md = _inventory([
            ("A.java", [("/a/{id}", "[제외]"), ("/a2/{id}", "[적용]")]),
            ("B.java", [("/b/{id}", "[적용]")]),
        ])
        pre, secs = sh.parse_inventory(md)
        self.assertIn("### IDOR 검토 인벤토리", "\n".join(pre))
        self.assertEqual([s["file"] for s in secs], ["A.java", "B.java"])
        self.assertEqual(secs[0]["rows"], 2)
        self.assertEqual(secs[0]["excluded"], 1)
        self.assertEqual(secs[1]["rows"], 1)


class TestBalanceShards(unittest.TestCase):
    def _mk(self, n_files, rows_each=3):
        return [{"file": f"F{i}.java", "lines": [f"#### F{i}.java"], "rows": rows_each, "excluded": 0}
                for i in range(n_files)]

    def test_file_atomicity_and_lossless(self):
        secs = self._mk(10, rows_each=4)
        shards = sh.balance_shards(secs, 3)
        # 파일 원자성: 모든 파일이 정확히 한 샤드에
        placed = [s["file"] for shard in shards for s in shard]
        self.assertEqual(sorted(placed), sorted(s["file"] for s in secs))
        self.assertEqual(len(placed), len(set(placed)), "파일이 두 샤드에 중복 배치되면 안 됨")
        # 무손실: 행 수 보존
        self.assertEqual(sum(s["rows"] for shard in shards for s in shard),
                         sum(s["rows"] for s in secs))

    def test_balanced_loads(self):
        secs = self._mk(12, rows_each=5)
        shards = sh.balance_shards(secs, 4)
        loads = [sum(sh._weight(s) for s in shard) for shard in shards]
        self.assertLessEqual(max(loads) - min(loads), sh._weight(secs[0]),
                             "샤드 간 부하 편차가 파일 1개 가중치 이내여야 함")

    def test_k_larger_than_files_drops_empty(self):
        secs = self._mk(2)
        shards = sh.balance_shards(secs, 5)
        self.assertEqual(len(shards), 2)  # 빈 샤드 제거

    def test_excluded_weighted_priority(self):
        # [제외] 가중치로 무거워진 파일이 분산되는지(균형) — 한 샤드에 몰리지 않음
        secs = [
            {"file": "hot.java", "lines": ["#### hot.java"], "rows": 2, "excluded": 2},
            {"file": "cold1.java", "lines": ["#### cold1.java"], "rows": 2, "excluded": 0},
            {"file": "cold2.java", "lines": ["#### cold2.java"], "rows": 2, "excluded": 0},
        ]
        shards = sh.balance_shards(secs, 2)
        # hot.java(가중 2+4+1=7)는 단독 샤드, cold 2개(각 3)는 다른 샤드 → 균형
        loads = sorted(sum(sh._weight(s) for s in shard) for shard in shards)
        self.assertEqual(loads, [6, 7])


class TestEndToEnd(unittest.TestCase):
    def test_render_and_lossless_files(self):
        md = _inventory([
            ("A.java", [("/a/{id}", "[제외]"), ("/a2/{id}", "[적용]")]),
            ("B.java", [("/b/{id}", "[적용]"), ("/b2/{id}", "[적용]")]),
            ("C.java", [("/c/{id}", "[제외]")]),
        ])
        pre, secs = sh.parse_inventory(md)
        shards = sh.balance_shards(secs, 2)
        # 렌더된 샤드에 헤더(프리앰블)가 재부착되고 파일 섹션이 보존됨
        rendered = [sh.render_shard(pre, s, i + 1, len(shards)) for i, s in enumerate(shards)]
        all_text = "\n".join(rendered)
        for f in ("A.java", "B.java", "C.java"):
            self.assertIn(f"#### {f}", all_text)
        for r in rendered:
            self.assertIn("### IDOR 검토 인벤토리", r)
            self.assertIn("IDOR SHARD", r)
        # 무손실: 전체 데이터 행 수 보존
        total_in = sum(s["rows"] for s in secs)
        total_out = all_text.count("| [ ] |")
        self.assertEqual(total_in, total_out)


if __name__ == "__main__":
    unittest.main()
