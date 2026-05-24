#!/usr/bin/env python3
"""phase1_build_master_list.py 기본 테스트.

테스트 케이스:
  1. 정상 manifest → JSON 생성 + exit 0
  2. 빈 manifest (declared_count: 0) → clean scanner로 처리
  3. 잘못된 JSON → ERROR + exit 1
"""
import json, os, subprocess, tempfile, unittest
from pathlib import Path

SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "..", "tools", "phase1_build_master_list.py"
)

VALID_MD = """\
# xss-scanner Phase 1 결과

## XSS-1: Comment innerHTML XSS

### Code
`src/components/Comment.tsx:18` — innerHTML 사용

### Source→Sink Flow
사용자 입력이 req.body.comment으로 전달되어 Comment 컴포넌트의 innerHTML에 삽입됨.
이 경로에서 sanitize 로직 없음.

### Validation Logic
Comment 컴포넌트 전후 ±30줄 확인 — DOMPurify 등 sanitize 호출 없음.
상위 컴포넌트에서도 escape 처리 없이 raw HTML을 전달.

### Trigger Conditions
POST /api/comments 엔드포인트에서 comment 파라미터로 HTML 삽입 가능.
실제 경로: POST /api/comments (src/routes/api.ts:42)

### Decision
후보 — innerHTML에 사용자 입력이 sanitize 없이 삽입됨

<!-- NOAH-SAST MANIFEST v1 -->
```json
{"declared_count": 1, "candidates": [{"id": "XSS-1", "title": "Comment innerHTML XSS", "file": "src/components/Comment.tsx", "line": 18, "url_path": "/api/comments", "source": "req.body.comment", "sink": "innerHTML", "test_prereq": null}]}
```
<!-- /NOAH-SAST MANIFEST -->
"""

EMPTY_MD = """\
# sqli-scanner Phase 1 결과

이상 없음 — SQL 인젝션 후보 없음.

<!-- NOAH-SAST MANIFEST v1 -->
```json
{"declared_count": 0, "candidates": []}
```
<!-- /NOAH-SAST MANIFEST -->
"""

INVALID_JSON_MD = """\
# ssrf-scanner Phase 1 결과

## SSRF-1: fetch URL

### Code
test

<!-- NOAH-SAST MANIFEST v1 -->
```json
{invalid json here}
```
<!-- /NOAH-SAST MANIFEST -->
"""

NO_MANIFEST_MD = """\
# path-traversal-scanner Phase 1 결과

이상 없음.
"""


class TestBuildMasterList(unittest.TestCase):
    def _run(self, phase1_dir, out_path):
        return subprocess.run(
            ["python3", SCRIPT, str(phase1_dir), str(out_path)],
            capture_output=True, text=True, timeout=30,
        )

    def test_valid_manifest(self):
        """정상 manifest → JSON 생성 + exit 0"""
        with tempfile.TemporaryDirectory() as d:
            (p := os.path.join(d, "xss-scanner.md")) and Path(p).write_text(VALID_MD)
            out = os.path.join(d, "master-list.json")
            r = self._run(d, out)
            self.assertEqual(r.returncode, 0, f"stderr: {r.stderr}")
            self.assertTrue(os.path.exists(out))
            data = json.loads(Path(out).read_text())
            self.assertEqual(len(data["candidates"]), 1)
            self.assertEqual(data["candidates"][0]["id"], "XSS-1")

    def test_empty_manifest(self):
        """빈 manifest (declared_count: 0) → clean scanner, exit 0"""
        with tempfile.TemporaryDirectory() as d:
            Path(os.path.join(d, "sqli-scanner.md")).write_text(EMPTY_MD)
            out = os.path.join(d, "master-list.json")
            r = self._run(d, out)
            self.assertEqual(r.returncode, 0, f"stderr: {r.stderr}")
            data = json.loads(Path(out).read_text())
            self.assertEqual(len(data["candidates"]), 0)
            self.assertIn("sqli-scanner", data.get("clean_scanners", []))

    def test_invalid_json(self):
        """잘못된 JSON manifest → ERROR + exit 1"""
        with tempfile.TemporaryDirectory() as d:
            Path(os.path.join(d, "ssrf-scanner.md")).write_text(INVALID_JSON_MD)
            out = os.path.join(d, "master-list.json")
            r = self._run(d, out)
            self.assertEqual(r.returncode, 1)
            self.assertIn("ERROR", r.stdout)

    def test_no_manifest(self):
        """manifest 블록 없음 → ERROR + exit 1"""
        with tempfile.TemporaryDirectory() as d:
            Path(os.path.join(d, "path-traversal-scanner.md")).write_text(NO_MANIFEST_MD)
            out = os.path.join(d, "master-list.json")
            r = self._run(d, out)
            self.assertEqual(r.returncode, 1)
            self.assertIn("NO_MANIFEST", r.stdout)

    def test_no_args(self):
        """인자 없이 실행 → argparse 인자 누락 에러 + exit 2"""
        r = subprocess.run(
            ["python3", SCRIPT], capture_output=True, text=True, timeout=10,
        )
        # 필수 위치 인자(phase1_dir, output_json) 누락 시 argparse 표준 종료코드 2.
        # (처리 단계 오류는 exit 1 — test_invalid_json / test_no_manifest 참조)
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage", r.stderr)

    def test_chain_analysis_excluded(self):
        """chain-analysis.md는 수집 대상에서 제외 (Phase 1 manifest 형식이 아님)"""
        chain_md = (
            "# 연계 분석 결과\n\n"
            "## 공격 체인 #1\n...\n\n"
            "<!-- NOAH-SAST CHAIN MANIFEST v1 -->\n"
            "```json\n"
            '{"chains": [], "independent": []}\n'
            "```\n"
            "<!-- /NOAH-SAST CHAIN MANIFEST -->\n"
        )
        with tempfile.TemporaryDirectory() as d:
            Path(os.path.join(d, "xss-scanner.md")).write_text(VALID_MD)
            Path(os.path.join(d, "chain-analysis.md")).write_text(chain_md)
            out = os.path.join(d, "master-list.json")
            r = self._run(d, out)
            self.assertEqual(r.returncode, 0, f"stderr: {r.stderr}")
            data = json.loads(Path(out).read_text())
            # chain-analysis.md는 무시되므로 xss-scanner 후보 1개만 있어야 함
            self.assertEqual(len(data["candidates"]), 1)
            self.assertEqual(data["candidates"][0]["scanner"], "xss-scanner")


if __name__ == "__main__":
    unittest.main()
