#!/usr/bin/env python3
"""idor_inventory.py controller-scan 모드의 FastAPI(Python) 어댑터 회귀 테스트.

FastAPI는 데코레이터+시그니처 구조라 Spring과 동일한 ①라우트 표지 ②시그니처
입력추출 전략을 재사용한다. 경로 변수 + Path/Query/Body/Header/Cookie/Form/File
의존성을 외부 입력으로 추출하고, 입력 없는 핸들러·라우트 아닌 함수는 제외한다.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_MOD_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "idor_inventory.py")
_spec = importlib.util.spec_from_file_location("idor_inventory", _MOD_PATH)
idor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(idor)

SAMPLE = '''
from fastapi import APIRouter, Query, Header
router = APIRouter()

@router.get("/items/{item_id}")
def read_item(item_id: int, q: str = Query(None)):
    return store.get(item_id)

@router.post("/users/{user_id}/orders")
async def create_order(user_id: int, token: str = Header(...), body: OrderModel):
    return svc.create(user_id, body)

@router.get("/health")
def health():
    return {"ok": True}

def not_a_route(x: int = Query(0)):
    return x
'''


def _scan_text(text: str):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d, "routes.py")
        f.write_text(text, encoding="utf-8")
        return {r["endpoint"]: r["params"] for r in idor._scan_fastapi_file(f)}


class TestFastAPIScan(unittest.TestCase):
    def test_path_variable_extracted(self):
        rows = _scan_text(SAMPLE)
        self.assertIn("GET /items/{item_id}", rows)
        self.assertTrue(any("item_id(path-param)" == p for p in rows["GET /items/{item_id}"]))

    def test_query_dependency_extracted(self):
        rows = _scan_text(SAMPLE)
        self.assertTrue(any(p.startswith("q(Query") for p in rows["GET /items/{item_id}"]))

    def test_header_and_pathvar_on_post(self):
        rows = _scan_text(SAMPLE)
        params = rows["POST /users/{user_id}/orders"]
        self.assertTrue(any(p.startswith("token(Header") for p in params))
        self.assertTrue(any("user_id(path-param)" == p for p in params))

    def test_pydantic_body_conservatively_excluded(self):
        # Pydantic 본문 모델(body: OrderModel)은 타입만으로 판별 불가 → 보수적 제외(taint가 커버)
        rows = _scan_text(SAMPLE)
        self.assertFalse(any("body" in p for p in rows["POST /users/{user_id}/orders"]))

    def test_handler_without_input_excluded(self):
        # 외부 입력 없는 핸들러(/health)는 IDOR 대상 아님 → 미수집
        rows = _scan_text(SAMPLE)
        self.assertNotIn("GET /health", rows)

    def test_non_route_function_excluded(self):
        # 라우트 데코레이터 없는 함수는 입력이 있어도 미수집
        rows = _scan_text(SAMPLE)
        self.assertTrue(all("not_a_route" not in e for e in rows))

    def test_no_fastapi_marker_returns_empty(self):
        # FastAPI 라우트 마커 없는 .py는 스킵
        rows = _scan_text("def plain(x):\n    return x\n")
        self.assertEqual(rows, {})


if __name__ == "__main__":
    unittest.main()
