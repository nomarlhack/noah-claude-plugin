#!/usr/bin/env python3
"""idor_inventory.py controller-scan 모드의 Express(Node.js) 어댑터 회귀 테스트.

Express는 본문접근형(라우트=함수 호출, 입력=핸들러 본문의 req.* 접근)이라 시그니처
파싱이 안 통한다. 그래서 ①라우트+경로변수(:var)는 정확히 전수 열거(완전성),
②본문 req.* 접근은 best-effort 입력 힌트, ③외부 핸들러(다른 파일)는 '입력 미상'
마커로 등재해 에이전트가 핸들러를 Read하도록 한다(taint 갭이 큰 영역).
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
const router = require('express').Router();
router.get('/users/:id', (req, res) => {
  res.json(db.find(req.params.id));
});
router.post('/orders/:orderId/cancel', auth, cancelHandler);
app.get('/health', (req, res) => res.send('ok'));
app.post('/login', (req, res) => { const u = req.body.user; });
app.post('/transfer', transferCtrl);
const x = cache.get('key');
'''


def _scan(text: str):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d, "routes.js")
        f.write_text(text, encoding="utf-8")
        return {r["endpoint"]: r["params"] for r in idor._scan_express_file(f)}


class TestExpressScan(unittest.TestCase):
    def setUp(self):
        self.rows = _scan(SAMPLE)

    def test_path_var_and_body_hint(self):
        # 경로변수 + 인라인 핸들러 본문 req.params 힌트
        params = self.rows["GET /users/:id"]
        self.assertIn("id(path-var)", params)
        self.assertTrue(any("req.params" in p for p in params))

    def test_external_handler_with_pathvar_registered(self):
        # 외부 핸들러여도 경로변수가 있으면 확정 등재 (입력 미상 마커 불필요)
        params = self.rows["POST /orders/:orderId/cancel"]
        self.assertIn("orderId(path-var)", params)
        self.assertFalse(any("미상" in p for p in params))

    def test_inline_without_input_excluded(self):
        # 인라인 핸들러 + 경로변수·입력토큰 0 (/health) → 식별자 미수용 → 제외
        self.assertNotIn("GET /health", self.rows)

    def test_body_only_input_hint(self):
        # 경로변수 없지만 본문 req.body 접근 → 입력 힌트로 등재
        params = self.rows["POST /login"]
        self.assertTrue(any("req.body" in p for p in params))

    def test_external_handler_unknown_marker(self):
        # 외부 핸들러 + 경로변수·본문토큰 0 → '입력 미상' 마커로 등재 (완전성 우선)
        params = self.rows["POST /transfer"]
        self.assertTrue(any("미상" in p for p in params))

    def test_non_route_call_excluded(self):
        # cache.get('key')는 경로가 '/' 시작 아님 → 라우트로 오탐 안 됨
        self.assertTrue(all("key" not in e for e in self.rows))

    def test_no_express_marker_returns_empty(self):
        self.assertEqual(_scan("const y = 1;\nfunction f(){ return y; }\n"), {})


if __name__ == "__main__":
    unittest.main()
