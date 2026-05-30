#!/usr/bin/env python3
"""phase1_review_assert.py session-override 등록 감사(③) 회귀 테스트.

회귀 대상: 고신뢰 session-identity-override 룰(클라이언트↔세션 신원 폴백) 매치가
후보로 등록되지 않고 예산 압박 등으로 조용히 누락되던 FN.
locindex에 매치가 있는데 대응 후보가 없으면 감사가 위반을 반환해야 한다(등록 강제).
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

_RULE = "noah-kotlin-idor-session-identity-override"
_FILE = "src/web/RecentlyViewedPlaceController.kt"


class TestSessionOverrideAudit(unittest.TestCase):
    def _index(self, locations: dict) -> Path:
        d = tempfile.mkdtemp()
        idx = Path(d)
        (idx / "idor-scanner.locindex.json").write_text(
            json.dumps({"locations": locations, "_scanner": {}}), encoding="utf-8"
        )
        return idx

    def _loc(self, line: int, rule: str = _RULE) -> dict:
        return {f"{_FILE}:{line}": {"tier": "ast", "rule_ids": [rule]}}

    def test_match_without_candidate_flags_violation(self):
        idx = self._index(self._loc(27))
        violations = pra._session_override_audit(idx, candidates=[])
        self.assertEqual(len(violations), 1)
        self.assertIn("session-identity-override", violations[0])

    def test_match_with_exact_line_candidate_ok(self):
        idx = self._index(self._loc(27))
        cands = [{"id": "IDOR-X", "scanner": "idor-scanner", "file": _FILE, "line": 27}]
        self.assertEqual(pra._session_override_audit(idx, cands), [])

    def test_match_within_window_ok(self):
        # 매치 라인(27)과 후보 라인(22)이 메서드 본문 내(±20) → 등록된 것으로 인정
        idx = self._index(self._loc(27))
        cands = [{"id": "IDOR-X", "scanner": "idor-scanner", "file": _FILE, "line": 22}]
        self.assertEqual(pra._session_override_audit(idx, cands), [])

    def test_match_far_candidate_flags_violation(self):
        # 같은 파일이지만 라인이 멀면(>20) 다른 메서드 → 등록 누락으로 간주
        idx = self._index(self._loc(200))
        cands = [{"id": "IDOR-X", "scanner": "idor-scanner", "file": _FILE, "line": 22}]
        self.assertEqual(len(pra._session_override_audit(idx, cands)), 1)

    def test_match_different_file_flags_violation(self):
        idx = self._index(self._loc(27))
        cands = [{"id": "IDOR-X", "scanner": "idor-scanner", "file": "src/web/Other.kt", "line": 27}]
        self.assertEqual(len(pra._session_override_audit(idx, cands)), 1)

    def test_non_session_override_rule_not_gated(self):
        # 다른 룰(고신뢰 아님) 매치는 본 감사 대상 아님
        idx = self._index(self._loc(27, rule="noah-kotlin-idor-phase1-pattern"))
        self.assertEqual(pra._session_override_audit(idx, candidates=[]), [])

    def test_missing_locindex_is_graceful(self):
        empty = Path(tempfile.mkdtemp())
        self.assertEqual(pra._session_override_audit(empty, candidates=[]), [])

    def test_java_rule_also_gated(self):
        idx = self._index(self._loc(19, rule="noah-java-idor-session-identity-override"))
        self.assertEqual(len(pra._session_override_audit(idx, candidates=[])), 1)

    def test_absolute_index_matches_relative_candidate(self):
        # 회귀: locindex는 절대경로, 후보 file은 상대경로(build_master_list 출력)여도 동일 파일로 인정.
        # (정확매칭만 하면 포맷 차이로 거짓 위반 → 수동 절대화 땜질이 필요했던 모순)
        d = tempfile.mkdtemp()
        idx = Path(d)
        abs_loc = "/Users/x/proj/" + _FILE  # 인덱스: 절대경로
        (idx / "idor-scanner.locindex.json").write_text(
            json.dumps({"locations": {f"{abs_loc}:27": {"tier": "ast", "rule_ids": [_RULE]}},
                        "_scanner": {}}), encoding="utf-8")
        cands = [{"id": "IDOR-X", "scanner": "idor-scanner", "file": _FILE, "line": 27}]  # 후보: 상대경로
        self.assertEqual(pra._session_override_audit(idx, cands), [],
                         "절대경로 인덱스 ↔ 상대경로 후보가 매칭되어 위반이 없어야 함")


class TestSameFilePath(unittest.TestCase):
    def test_relative_suffix_of_absolute(self):
        self.assertTrue(pra._same_file_path("a/b/X.kt", "/root/proj/a/b/X.kt"))
        self.assertTrue(pra._same_file_path("/root/proj/a/b/X.kt", "a/b/X.kt"))

    def test_exact_match(self):
        self.assertTrue(pra._same_file_path("a/b/X.kt", "a/b/X.kt"))

    def test_same_basename_different_dir_does_not_match(self):
        # 다른 모듈의 동명 파일은 매칭되면 안 됨(컴포넌트 경계 요구 → basename 단독 매칭 방지)
        self.assertFalse(pra._same_file_path("mod1/X.kt", "mod2/X.kt"))

    def test_partial_segment_does_not_match(self):
        # 컴포넌트 경계("/") 요구 → "b/X.kt"가 "zab/X.kt"의 suffix처럼 보여도 매칭 안 됨
        self.assertFalse(pra._same_file_path("b/X.kt", "zab/X.kt"))

    def test_empty_is_false(self):
        self.assertFalse(pra._same_file_path("", "a/X.kt"))


if __name__ == "__main__":
    unittest.main()
