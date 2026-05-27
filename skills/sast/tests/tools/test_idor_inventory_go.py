#!/usr/bin/env python3
"""idor_inventory.py controller-scan 모드의 Go 어댑터 회귀 테스트.

Go는 본문접근형(라우트=함수 호출, 입력=핸들러 본문의 c.Param/c.Query 접근)이라
Express와 유사하다. Gin/Echo `.GET(...)`·chi `.Get(...)`·net-http `.HandleFunc(...)`
호출의 경로 + 경로변수(:id Gin/Echo, {id} chi/gorilla)를 정확히 열거하고, 입력은
본문 토큰을 best-effort 힌트로, 외부 핸들러는 '입력 미상'으로 등재한다.
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
    "package main\n"
    "func setup(r *gin.Engine) {\n"
    '    r.GET("/users/:id", func(c *gin.Context) {\n'
    '        id := c.Param("id")\n'
    "        c.JSON(200, find(id))\n"
    "    })\n"
    '    r.POST("/orders", createOrder)\n'
    '    chi.Get("/files/{fileID}/download", downloadHandler)\n'
    '    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {\n'
    '        w.Write([]byte("ok"))\n'
    "    })\n"
    "}\n"
)


def _scan(text: str):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d, "routes.go")
        f.write_text(text, encoding="utf-8")
        return {r["endpoint"]: r["params"] for r in idor._scan_go_file(f)}


class TestGoScan(unittest.TestCase):
    def setUp(self):
        self.rows = _scan(SAMPLE)

    def test_gin_colon_var_and_input_hint(self):
        params = self.rows["GET /users/:id"]
        self.assertIn("id(path-var)", params)
        self.assertTrue(any("c.Param" in p for p in params))

    def test_chi_brace_var(self):
        self.assertIn("fileID(path-var)", self.rows["GET /files/{fileID}/download"])

    def test_external_handler_unknown_marker(self):
        # 외부 핸들러(createOrder) + 경로변수·입력 0 → 입력 미상 등재
        self.assertTrue(any("미상" in p for p in self.rows["POST /orders"]))

    def test_handlefunc_inline_no_input_excluded(self):
        # net/http HandleFunc 인라인 + 경로변수·입력 토큰 0 (/health) → 제외
        self.assertNotIn("ANY /health", self.rows)

    def test_no_route_marker_returns_empty(self):
        self.assertEqual(_scan("package main\nfunc main() { println(\"hi\") }\n"), {})


if __name__ == "__main__":
    unittest.main()
