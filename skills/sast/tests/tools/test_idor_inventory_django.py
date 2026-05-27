#!/usr/bin/env python3
"""idor_inventory.py controller-scan 모드의 Django(urls.py) 어댑터 회귀 테스트.

Django는 라우트(urls.py)와 핸들러(views.py)가 분리되어 항상 '외부 핸들러' 패턴이다.
그래서 urls.py에서 라우트+경로변수만 전수 열거하고(완전성), 입력은 '미상'으로
등재해 에이전트가 view를 Read하게 한다. urlpatterns 할당을 필수 마커로 사용한다.
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
    "from django.urls import path, re_path, include\n"
    "from . import views\n"
    "urlpatterns = [\n"
    "    path('users/<int:user_id>/', views.user_detail),\n"
    "    re_path(r'^orders/(?P<order_id>\\d+)/$', views.order_detail),\n"
    "    path('about/', views.about),\n"
    "    path('api/', include('app.urls')),\n"
    "    path('files/<slug:key>/download/', views.download),\n"
    "]\n"
)


def _scan(text: str):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d, "urls.py")
        f.write_text(text, encoding="utf-8")
        return {r["endpoint"]: r["params"] for r in idor._scan_django_urls_file(f)}


class TestDjangoScan(unittest.TestCase):
    def setUp(self):
        self.rows = _scan(SAMPLE)

    def test_path_int_var(self):
        self.assertIn("user_id(path-var)", self.rows["ANY /users/<int:user_id>"])

    def test_path_slug_var(self):
        self.assertIn("key(path-var)", self.rows["ANY /files/<slug:key>/download"])

    def test_re_path_named_group_var(self):
        # re_path의 (?P<name>...) 명명 그룹도 경로변수로 추출
        ep = next(e for e in self.rows if "orders" in e)
        self.assertIn("order_id(path-var)", self.rows[ep])

    def test_no_pathvar_gets_unknown_marker(self):
        # 경로변수 없는 라우트(about)는 입력 미상으로 등재 (핸들러가 views.py)
        self.assertTrue(any("미상" in p for p in self.rows["ANY /about"]))

    def test_include_mount_excluded(self):
        # include()는 sub-urls 마운트라 라우트 아님 → 제외
        self.assertTrue(all("/api" != e.replace("ANY ", "") for e in self.rows))

    def test_requires_urlpatterns_assignment(self):
        # urlpatterns 할당이 없으면(주석/문자열 언급만) 스킵 — 일반 .py 오탐 방지
        nope = "# urlpatterns 설명\npath('x/<int:id>/', v)\n"
        self.assertEqual(_scan(nope), {})


if __name__ == "__main__":
    unittest.main()
