#!/usr/bin/env python3
"""validate_report.py 기본 테스트.

테스트 케이스:
  1. PASS — MD/HTML POC 건수 일치
  2. FAIL — POC 건수 불일치 → 파일 삭제
  3. 잘못된 인자 (비정수) → exit 1
"""
import os, subprocess, tempfile, unittest

SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "..", "sub-skills", "scan-report", "validate_report.py"
)


def _make_report(directory, name, poc_count, chain=False):
    """지정된 POC 건수를 가진 MD/HTML 픽스처 생성."""
    poc_block = "\n".join([f"#### {i+1}. 취약점 {i+1}\n\n**재현 방법 및 POC**:\ncurl ...\n" for i in range(poc_count)])
    chain_block = "\n## 연계 시나리오\n\n체인 내용\n" if chain else ""
    content = f"# 보고서\n\n{poc_block}{chain_block}"

    with open(os.path.join(directory, f"{name}.md"), "w", encoding="utf-8") as f:
        f.write(content)
    with open(os.path.join(directory, f"{name}.html"), "w", encoding="utf-8") as f:
        f.write(f"<html><body>{content}</body></html>")
    # 테스트 격리: validator는 --master-list 미지정 시 /tmp/phase1_results_*/master-list.json을
    # glob하는 fallback이 있어, 머신에 남은 실제 스캔 잔여물(safe 후보 등)을 주워 검증이 오염된다.
    # 후보 0건 master-list를 명시적으로 제공해 fallback을 차단한다. 경로를 반환한다.
    ml_path = os.path.join(directory, "master-list.json")
    with open(ml_path, "w", encoding="utf-8") as f:
        f.write('{"candidates": []}')
    return ml_path


class TestValidateReport(unittest.TestCase):
    def _run(self, args, cwd):
        return subprocess.run(
            ["python3", SCRIPT] + args,
            capture_output=True, text=True, timeout=10, cwd=cwd,
        )

    def test_pass(self):
        """POC 건수 일치 → PASS + exit 0"""
        with tempfile.TemporaryDirectory() as d:
            ml = _make_report(d, "noah-sast-report", 3)
            r = self._run(["3", "--master-list", ml], d)
            self.assertEqual(r.returncode, 0, f"stdout: {r.stdout}")
            self.assertIn("PASS", r.stdout)

    def test_fail_deletes_files(self):
        """POC 건수 불일치 → FAIL + 파일 삭제 + exit 1"""
        with tempfile.TemporaryDirectory() as d:
            ml = _make_report(d, "noah-sast-report", 2)
            md_path = os.path.join(d, "noah-sast-report.md")
            html_path = os.path.join(d, "noah-sast-report.html")
            self.assertTrue(os.path.exists(md_path))

            r = self._run(["5", "--master-list", ml], d)
            self.assertEqual(r.returncode, 1)
            self.assertIn("FAIL", r.stdout)
            self.assertFalse(os.path.exists(md_path), "MD 파일이 삭제되어야 함")
            self.assertFalse(os.path.exists(html_path), "HTML 파일이 삭제되어야 함")

    def test_chain_analysis_pass(self):
        """--chain-analysis + 연계 시나리오 섹션 존재 → PASS"""
        with tempfile.TemporaryDirectory() as d:
            ml = _make_report(d, "noah-sast-report", 2, chain=True)
            r = self._run(["2", "--chain-analysis", "--master-list", ml], d)
            self.assertEqual(r.returncode, 0, f"stdout: {r.stdout}")
            self.assertIn("chain-analysis", r.stdout)

    def test_invalid_arg(self):
        """비정수 인자 → exit 1"""
        with tempfile.TemporaryDirectory() as d:
            r = self._run(["abc"], d)
            self.assertEqual(r.returncode, 1)
            self.assertIn("정수", r.stderr)

    def test_no_args(self):
        """인자 없이 실행 → Usage + exit 1"""
        with tempfile.TemporaryDirectory() as d:
            r = self._run([], d)
            self.assertEqual(r.returncode, 1)
            self.assertIn("Usage", r.stdout)


if __name__ == "__main__":
    unittest.main()
