#!/usr/bin/env python3
"""idor_inventory.py controller-scan 모드의 Flask(Python) 어댑터 회귀 테스트.

Flask는 하이브리드 — 라우트는 데코레이터(@app.route/@app.get), 경로변수는 <int:id>
(Django 형식), 입력은 핸들러 본문 request.* 접근(Express 형식)이다. @app.get은
FastAPI도 쓰므로 'flask'/'fastapi' import 마커로 어댑터를 구분한다.
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

SAMPLE = (
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users/<int:user_id>')\n"
    "def get_user(user_id):\n"
    "    return db.find(user_id)\n\n"
    "@app.route('/search', methods=['POST'])\n"
    "def search():\n"
    "    q = request.args.get('q')\n"
    "    return run(q)\n\n"
    "@app.get('/health')\n"
    "def health():\n"
    "    return 'ok'\n"
)


def _scan(text: str):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d, "app.py")
        f.write_text(text, encoding="utf-8")
        return {r["endpoint"]: r["params"] for r in idor._scan_flask_file(f)}


class TestFlaskScan(unittest.TestCase):
    def setUp(self):
        self.rows = _scan(SAMPLE)

    def test_route_path_var(self):
        self.assertIn("user_id(path-var)", self.rows["GET /users/<int:user_id>"])

    def test_methods_parsed_and_input_hint(self):
        # @app.route(..., methods=['POST'])의 메서드 파싱 + 본문 request.args 힌트
        self.assertIn("POST /search", self.rows)
        self.assertTrue(any("request.args" in p for p in self.rows["POST /search"]))

    def test_get_decorator_no_input_excluded(self):
        # @app.get('/health')는 경로변수·입력 0 → 식별자 미수용 → 제외
        self.assertNotIn("GET /health", self.rows)

    def test_requires_flask_marker(self):
        # flask import 마커 없으면(FastAPI 파일 등) 스킵 — @app.get 충돌 방지
        fastapi_src = (
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/x/{id}')\n"
            "def f(id: int): return id\n"
        )
        self.assertEqual(_scan(fastapi_src), {})


if __name__ == "__main__":
    unittest.main()
