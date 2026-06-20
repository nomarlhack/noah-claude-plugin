#!/usr/bin/env python3
"""phase1_review_assert.py 파일 단위 disposition 감사(§6-A-3) 회귀 테스트.

회귀 대상: 결정/방어 스캐너가 ast/generic 매치를 클래스로 일괄 흡수해, 인덱스가 매치한
서버 결정 파일의 파일명이 결과 MD에 등장조차 하지 않던 FN. 인덱스 매치 서버 파일이 MD에
개별 명시되지 않으면 감사가 위반을 반환해야 한다.

fixture 경로는 성질(서버 결정 경로 vs 클라이언트 컴포넌트)만 드러내는 합성값이다 —
특정 코드베이스에 의존하지 않는다.
"""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_MOD_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "phase1_review_assert.py")
_spec = importlib.util.spec_from_file_location("phase1_review_assert", _MOD_PATH)
pra = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pra)

# 합성 fixture: 경로 성질만 표현 (실제 프로젝트 비의존)
_SERVER_FILE = "src/controller/checker/url_validator.ts"   # /controller/ + /checker/, .ts → 서버 결정
_CLIENT_FILE = "src/components/SubmitForm.tsx"             # .tsx 클라이언트 컴포넌트


class TestServerDecisionFile(unittest.TestCase):
    def test_server_path_is_server(self):
        self.assertTrue(pra._is_server_decision_file(_SERVER_FILE))
        self.assertTrue(pra._is_server_decision_file("api/service/payment_gate.ts"))
        self.assertTrue(pra._is_server_decision_file("server/router/route.js"))

    def test_client_tsx_is_not_server(self):
        self.assertFalse(pra._is_server_decision_file(_CLIENT_FILE))

    def test_test_and_decl_files_excluded(self):
        self.assertFalse(pra._is_server_decision_file("a/service/foo.spec.ts"))
        self.assertFalse(pra._is_server_decision_file("a/service/foo.d.ts"))
        self.assertFalse(pra._is_server_decision_file("a/controller/spec.ts"))

    def test_tool_self_excluded(self):
        self.assertFalse(
            pra._is_server_decision_file("x/noah-8719/skills/sast/tools/select_scanners.py")
        )

    def test_non_server_path_is_not_server(self):
        self.assertFalse(pra._is_server_decision_file("src/util/format.ts"))


class TestFileDispositionAudit(unittest.TestCase):
    def _setup(self, scanner, files, md_text):
        idx = Path(tempfile.mkdtemp())
        p1 = Path(tempfile.mkdtemp())
        locs = {f"{f}:10": {"tier": "ast", "rule_ids": ["x"]} for f in files}
        (idx / f"{scanner}.locindex.json").write_text(
            json.dumps({"locations": locs, "_scanner": {}}), encoding="utf-8"
        )
        (p1 / f"{scanner}.md").write_text(md_text, encoding="utf-8")
        return idx, p1

    def test_unnamed_server_file_flags_violation(self):
        idx, p1 = self._setup(
            "ssrf-scanner", [_SERVER_FILE], "검증 로직 파일들은 클래스로 묶어 제외."
        )
        v = pra._file_disposition_audit(idx, p1, candidates=[], analyzed={"ssrf-scanner"})
        self.assertEqual(len(v), 1)
        self.assertIn("url_validator.ts", v[0])

    def test_named_server_file_passes(self):
        idx, p1 = self._setup(
            "ssrf-scanner", [_SERVER_FILE],
            "url_validator.ts: 예외 경로 기본값 allow [후보].",
        )
        v = pra._file_disposition_audit(idx, p1, candidates=[], analyzed={"ssrf-scanner"})
        self.assertEqual(v, [])

    def test_candidate_file_passes(self):
        idx, p1 = self._setup("ssrf-scanner", [_SERVER_FILE], "묶음 제외.")
        cands = [{"scanner": "ssrf-scanner", "file": _SERVER_FILE}]
        v = pra._file_disposition_audit(idx, p1, candidates=cands, analyzed={"ssrf-scanner"})
        self.assertEqual(v, [])

    def test_non_decision_scanner_not_audited(self):
        # tls-scanner는 결정/방어 집합 밖 → 미명시여도 위반 아님
        idx, p1 = self._setup("tls-scanner", [_SERVER_FILE], "묶음 제외.")
        v = pra._file_disposition_audit(idx, p1, candidates=[], analyzed={"tls-scanner"})
        self.assertEqual(v, [])

    def test_client_file_not_flagged(self):
        # 클라이언트 .tsx는 narrowing으로 대상 외 → 미명시여도 위반 아님
        idx, p1 = self._setup("ssrf-scanner", [_CLIENT_FILE], "묶음 제외.")
        v = pra._file_disposition_audit(idx, p1, candidates=[], analyzed={"ssrf-scanner"})
        self.assertEqual(v, [])


if __name__ == "__main__":
    unittest.main()
