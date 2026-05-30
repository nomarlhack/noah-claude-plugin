#!/usr/bin/env python3
"""phase1_review_assert.py 무인증 직접 객체참조 등록 감사 회귀 테스트.

회귀 대상(클래스): 인증 미경유(`[제외]`) 진입점이 소유권게이트 [미확인]로 방치되고
master-list에도 미등록이면 BOLA/IDOR가 조용히 누락된다(FN). 강제 대상은 두 가지:
- path-variable 2개 이상(중첩 자원 `/{parent}/.../{child}`): 상위↔하위 매핑 미검증.
- path-variable 1개 + 출처=taint(missing-owner-gate 흐름): 단일 객체 IDOR. 공개
  카탈로그 오탐 회피를 위해 taint 신호가 있을 때만 강제(scan-only·path-var 0개는 제외).
session-override 감사(①)와 동일 가족이며 _near_candidate 커버리지 계약을 공유한다.

픽스처는 특정 프로젝트/도메인에 의존하지 않는 합성 값(편향 회피)을 쓴다.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_MOD_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "phase1_review_assert.py")
_spec = importlib.util.spec_from_file_location("phase1_review_assert", _MOD_PATH)
pra = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pra)

_HEADER = (
    "### IDOR 검토 인벤토리 (기계 생성)\n\n"
    "| # | 엔드포인트 | 외부입력(파라미터) | 위치 | 출처 | 인증 | 소유권게이트 |\n"
    "|---|---|---|---|---|---|---|\n"
)
# 합성 중첩 진입점 (path-var 2개) + 위치
_NESTED_EP = "GET /v1/{parentId}/items/{itemId}"
_NESTED_LOC = "ParentItemController.java:42"


def _inv(rows: str) -> str:
    return _HEADER + rows + "\n\n다음 섹션\n"


def _row(endpoint, loc, auth, gate, det="taint+scan"):
    return f"| 1 | {endpoint} | childId(@PathVariable String) | {loc} | {det} | {auth} | {gate} |"


class TestUnauthNestedResourceAudit(unittest.TestCase):
    def _phase1_dir(self, inventory_md: str) -> Path:
        d = Path(tempfile.mkdtemp())
        (d / "idor-scanner.md").write_text(inventory_md, encoding="utf-8")
        return d

    def test_unresolved_nested_unauth_flags_violation(self):
        d = self._phase1_dir(_inv(_row(_NESTED_EP, _NESTED_LOC, "[제외]", "[미확인]")))
        violations = pra._unauth_nested_resource_audit(d, candidates=[])
        self.assertEqual(len(violations), 1)
        self.assertIn("BOLA", violations[0])

    def test_registered_in_master_list_ok(self):
        # master-list에 위치 근접 후보 등록 → 해소 인정
        d = self._phase1_dir(_inv(_row(_NESTED_EP, _NESTED_LOC, "[제외]", "[미확인]")))
        cands = [{"id": "X-1", "scanner": "idor-scanner",
                  "file": "/abs/path/ParentItemController.java", "line": 42}]
        self.assertEqual(pra._unauth_nested_resource_audit(d, cands), [])

    def test_verified_safe_in_inventory_ok(self):
        # [검증](안전 판정)만 인벤토리 텍스트로 해소 인정 → master-list 미등록이어도 통과
        d = self._phase1_dir(_inv(_row(_NESTED_EP, _NESTED_LOC, "[제외]", "[검증] svc.foo():X.java:9")))
        self.assertEqual(pra._unauth_nested_resource_audit(d, candidates=[]), [])

    def test_absent_gate_unregistered_flags_violation(self):
        # [부재](취약 확정)인데 master-list 미등록 → 보고서 누락(FN) → 발화해야 함
        # (phase1.md "[부재]→후보 승격" 및 session-override 게이트와 일관)
        d = self._phase1_dir(_inv(_row(_NESTED_EP, _NESTED_LOC, "[제외]", "[부재]")))
        self.assertEqual(len(pra._unauth_nested_resource_audit(d, candidates=[])), 1)

    def test_partial_gate_unregistered_flags_violation(self):
        # [부분](우회 가능) 미등록 → 발화
        d = self._phase1_dir(_inv(_row(_NESTED_EP, _NESTED_LOC, "[제외]", "[부분]: bypass")))
        self.assertEqual(len(pra._unauth_nested_resource_audit(d, candidates=[])), 1)

    def test_absent_gate_registered_ok(self):
        # [부재]지만 master-list에 후보 등록됨 → 통과
        d = self._phase1_dir(_inv(_row(_NESTED_EP, _NESTED_LOC, "[제외]", "[부재]")))
        cands = [{"id": "X-1", "scanner": "idor-scanner",
                  "file": "/abs/path/ParentItemController.java", "line": 42}]
        self.assertEqual(pra._unauth_nested_resource_audit(d, cands), [])

    def test_single_id_taint_flags_violation(self):
        # path-var 1개 + 출처=taint(missing-owner-gate 흐름) + [제외][미확인] → 단일 객체 IDOR로 발화
        d = self._phase1_dir(_inv(_row("GET /v1/items/{itemId}", "Ctrl.java:10", "[제외]", "[미확인]", det="taint")))
        violations = pra._unauth_nested_resource_audit(d, candidates=[])
        self.assertEqual(len(violations), 1)
        self.assertIn("단일 객체참조", violations[0])

    def test_single_id_scan_only_not_gated(self):
        # path-var 1개지만 출처가 scan-only(약신호) → 공개 카탈로그 오탐 회피 위해 미발화
        d = self._phase1_dir(
            _inv(_row("GET /v1/items/{itemId}", "Ctrl.java:10", "[제외]", "[미확인]", det="controller-scan")))
        self.assertEqual(pra._unauth_nested_resource_audit(d, candidates=[]), [])

    def test_single_id_taint_registered_ok(self):
        # path-var 1개 + taint지만 master-list에 등록됨 → 해소 인정
        d = self._phase1_dir(_inv(_row("GET /v1/items/{itemId}", "Ctrl.java:10", "[제외]", "[미확인]", det="taint")))
        cands = [{"id": "X-1", "scanner": "idor-scanner",
                  "file": "/abs/path/Ctrl.java", "line": 10}]
        self.assertEqual(pra._unauth_nested_resource_audit(d, cands), [])

    def test_no_pathvar_taint_not_gated(self):
        # path-var 0개(객체참조 아님)는 출처=taint여도 미발화 — 목록/검색 등
        d = self._phase1_dir(_inv(_row("GET /v1/items", "Ctrl.java:10", "[제외]", "[미확인]", det="taint")))
        self.assertEqual(pra._unauth_nested_resource_audit(d, candidates=[]), [])

    def test_authenticated_nested_not_gated(self):
        # 인증 적용 행은 본 감사 대상 아님(session/일반 검토가 담당)
        d = self._phase1_dir(_inv(_row(_NESTED_EP, _NESTED_LOC, "[적용]", "[미확인]")))
        self.assertEqual(pra._unauth_nested_resource_audit(d, candidates=[]), [])

    def test_far_candidate_flags_violation(self):
        # 같은 파일이지만 라인이 멀면(>20) 다른 메서드 → 미등록으로 간주
        d = self._phase1_dir(_inv(_row(_NESTED_EP, _NESTED_LOC, "[제외]", "[미확인]")))
        cands = [{"id": "X-1", "scanner": "idor-scanner",
                  "file": "/abs/path/ParentItemController.java", "line": 300}]
        self.assertEqual(len(pra._unauth_nested_resource_audit(d, cands)), 1)

    def test_no_inventory_is_graceful(self):
        d = Path(tempfile.mkdtemp())  # 인벤토리 파일 없음
        self.assertEqual(pra._unauth_nested_resource_audit(d, candidates=[]), [])

    def test_file_grouped_checklist_format_parsed(self):
        # 파일 단위 체크리스트 포맷(파일별 #### 섹션 + 표 헤더 반복 + [ ] 체크박스)도 파싱·발화해야 한다.
        md = (
            "### IDOR 검토 인벤토리 (파일 단위 체크리스트, 기계 생성)\n\n"
            "3 엔드포인트 | 2 파일.\n\n"
            "#### ParentItemController.java  — 엔드포인트 1개 · 인증 미경유 1개\n\n"
            "| 확인 | 엔드포인트 | 외부입력(파라미터) | 위치 | 출처 | 인증 | 소유권게이트 |\n"
            "|---|---|---|---|---|---|---|\n"
            f"| [ ] | {_NESTED_EP} | childId(@PathVariable String) | {_NESTED_LOC} | taint | [제외] | [미확인] |\n\n"
            "#### CatalogController.java  — 엔드포인트 1개\n\n"
            "| 확인 | 엔드포인트 | 외부입력(파라미터) | 위치 | 출처 | 인증 | 소유권게이트 |\n"
            "|---|---|---|---|---|---|---|\n"
            "| [ ] | GET /v1/items/{itemId} | itemId(@PathVariable) | Catalog.java:8 | taint | [적용] | [미확인] |\n"
        )
        d = Path(tempfile.mkdtemp())
        (d / "idor-scanner.md").write_text(md, encoding="utf-8")
        # 무인증 중첩 1건만 발화(인증적용/단일ID는 제외)
        self.assertEqual(len(pra._unauth_nested_resource_audit(d, candidates=[])), 1)

    def test_pathvar_syntax_framework_agnostic(self):
        # 프레임워크별 경로변수 문법(브레이스/앵글/콜론)을 모두 중첩으로 인식해야 한다.
        for ep in ("GET /v1/{a}/sub/{b}",          # Spring/FastAPI/chi
                   "GET /v1/<int:a>/sub/<int:b>",  # Flask/Django
                   "GET /v1/:a/sub/:b"):           # Express/Rails/Gin
            d = self._phase1_dir(_inv(_row(ep, "Ctrl.java:5", "[제외]", "[미확인]")))
            self.assertEqual(len(pra._unauth_nested_resource_audit(d, candidates=[])), 1,
                             msg=f"중첩 미인식: {ep}")


if __name__ == "__main__":
    unittest.main()
