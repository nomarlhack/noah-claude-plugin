#!/usr/bin/env python3
"""idor_inventory.py controller-scan 모드의 Rails(routes.rb) 어댑터 회귀 테스트.

Rails는 라우트(config/routes.rb DSL)와 핸들러(app/controllers)가 분리된다(Django 유사).
get/post/put/patch/delete DSL의 경로 + 경로변수(:id)를 열거하고, 입력은 컨트롤러에
있어 경로변수가 없으면 미상으로 등재한다. routes.draw를 필수 마커로 사용한다.
resources(RESTful 자동)·블록 라우트는 미지원.
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
    "Rails.application.routes.draw do\n"
    "  get '/users/:id', to: 'users#show'\n"
    "  post '/orders', to: 'orders#create'\n"
    "  patch '/files/:file_id/rename', to: 'files#rename'\n"
    "  resources :products\n"
    "  root 'home#index'\n"
    "end\n"
)


def _scan(text: str):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d, "routes.rb")
        f.write_text(text, encoding="utf-8")
        return {r["endpoint"]: r["params"] for r in idor._scan_rails_routes_file(f)}


class TestRailsScan(unittest.TestCase):
    def setUp(self):
        self.rows = _scan(SAMPLE)

    def test_get_path_var(self):
        self.assertIn("id(path-var)", self.rows["GET /users/:id"])

    def test_patch_path_var(self):
        self.assertIn("file_id(path-var)", self.rows["PATCH /files/:file_id/rename"])

    def test_no_pathvar_unknown_marker(self):
        # 경로변수 없는 라우트(POST /orders)는 입력 미상 (핸들러가 app/controllers)
        self.assertTrue(any("미상" in p for p in self.rows["POST /orders"]))

    def test_resources_not_enumerated(self):
        # resources(RESTful 자동)는 미지원 → 명시적 DSL만 열거됨
        self.assertTrue(all("products" not in e for e in self.rows))

    def test_requires_routes_draw_marker(self):
        # routes.draw 마커 없으면(일반 .rb의 get 메서드 호출 등) 스킵
        plain = "class Foo\n  def bar\n    get '/x/:id'\n  end\nend\n"
        self.assertEqual(_scan(plain), {})

    def test_commented_route_excluded(self):
        # 주석 처리된 라우트(#, //)는 가짜 진입점이라 제외 (블라인드 검증 반영)
        rows = _scan(
            "Rails.application.routes.draw do\n"
            "  get '/real/:id', to: 'x#y'\n"
            "  # get '/commented/:id', to: 'a#b'\n"
            "end\n"
        )
        self.assertIn("GET /real/:id", rows)
        self.assertTrue(all("commented" not in e for e in rows))


if __name__ == "__main__":
    unittest.main()
