#!/usr/bin/env python3
"""validate_report.py POC 플레이스홀더 게이트(변경 3) 회귀 테스트.

회귀 대상: 동적 실행된 항목(phase2.md evidence.commands 존재)의 "재현 방법 및 POC"에
플레이스홀더(<SESSION_COOKIE> 등)가 남으면 검토자가 재현 불가 → 경고(exit 6)로 잡는다.
판정은 상태가 아니라 evidence 존재 기준이므로 무인증 동적후보도 대상이고,
정적 후보(commands 부재)는 플레이스홀더가 정당하므로 오탐이 없어야 한다.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_VALIDATE = os.path.join(
    os.path.dirname(__file__), "..", "..", "sub-skills", "scan-report", "validate_report.py"
)

_PHASE2_WITH_CMD = """# scanner — Phase 2 결과
```json
{"scanner": "x", "schema_version": 2, "results": [
  {"id": "DYN-1", "evidence": {"commands": ["curl -s 'https://h/a' -H 'Cookie: real=1'"], "responses": ["HTTP 200"]}},
  {"id": "DYNC-2", "evidence": {"commands": ["curl -s 'https://h/b?id=9'"], "responses": ["HTTP 200 {...}"]}}
]}
```
"""
_PHASE2_NO_CMD = """# scanner — Phase 2 결과
```json
{"scanner": "y", "schema_version": 2, "results": [
  {"id": "STAT-3", "evidence": {"observations": ["정적 후보 — 동적 미실행"]}}
]}
```
"""


def _section(num, vid, poc_body):
    return (
        f"#### {num}. 제목 {vid}\n\n"
        f"**ID**: {vid}\n"
        f"**상태**: 후보\n\n"
        f"#### 재현 방법 및 POC\n\n"
        f"{poc_body}\n\n"
        f"#### 권장 조치\n\n수정.\n\n"
    )


class TestPocPlaceholderGate(unittest.TestCase):
    def _run(self, candidates, sections, p2_files):
        d = Path(tempfile.mkdtemp())
        for name, content in p2_files.items():
            (d / name).write_text(content, encoding="utf-8")
        # source_phase2_file 절대경로로 치환
        for c in candidates:
            if c.get("source_phase2_file"):
                c["source_phase2_file"] = str(d / c["source_phase2_file"])
        (d / "master-list.json").write_text(
            json.dumps({"candidates": candidates}), encoding="utf-8"
        )
        body = "## 스캐너별 실행 결과\n\n" + "".join(sections)
        md = "## 개요\n\n**테스트 환경**: https://h\n\n" + body
        (d / "rep.md").write_text(md, encoding="utf-8")
        # html: POC 건수만 맞춤 (count 검증 통과용)
        (d / "rep.html").write_text(body.replace("####", "<h4>"), encoding="utf-8")
        n_poc = md.count("재현 방법 및 POC")
        out = d / "out.json"
        subprocess.run(
            [sys.executable, _VALIDATE, str(n_poc), str(d / "rep"),
             "--master-list", str(d / "master-list.json"),
             "--json-output", str(out)],
            capture_output=True, text=True, cwd=str(d),
        )
        return json.loads(out.read_text(encoding="utf-8"))["warnings"]

    def test_dynamic_confirmed_with_placeholder_flagged(self):
        cands = [{"id": "DYN-1", "status": "confirmed", "source_phase2_file": "p2a.md"}]
        secs = [_section(1, "DYN-1", "curl -X GET \"<TARGET_HOST>/x\" -H \"Cookie: <SESSION_COOKIE>\"")]
        w = self._run(cands, secs, {"p2a.md": _PHASE2_WITH_CMD})
        self.assertTrue(any("DYN-1" in x and "플레이스홀더" in x for x in w), w)

    def test_dynamic_candidate_with_placeholder_flagged(self):
        # 무인증 동적후보: 상태=후보지만 evidence.commands 존재 → 대상
        cands = [{"id": "DYNC-2", "status": "candidate", "source_phase2_file": "p2a.md"}]
        secs = [_section(1, "DYNC-2", "curl \"https://h/b?accountId=<USER_ID>\"")]
        w = self._run(cands, secs, {"p2a.md": _PHASE2_WITH_CMD})
        self.assertTrue(any("DYNC-2" in x and "플레이스홀더" in x for x in w), w)

    def test_static_candidate_placeholder_not_flagged(self):
        # 정적 후보(commands 부재) → 플레이스홀더 정당, 미발화
        cands = [{"id": "STAT-3", "status": "candidate", "source_phase2_file": "p2b.md"}]
        secs = [_section(1, "STAT-3", "curl \"<TARGET_HOST>/z\" -H \"Cookie: <SESSION_COOKIE>\"")]
        w = self._run(cands, secs, {"p2b.md": _PHASE2_NO_CMD})
        self.assertFalse(any("STAT-3" in x and "플레이스홀더" in x for x in w), w)

    def test_dynamic_real_values_no_false_positive(self):
        # 동적 항목이 실값 POC + XSS payload <script> + 로그 [ERROR] 포함 → 오탐 없어야 함
        cands = [{"id": "DYN-1", "status": "confirmed", "source_phase2_file": "p2a.md"}]
        poc = (
            "curl -X POST 'https://h/c' -H 'Cookie: _kau=abc123' "
            "-d 'q=<script>alert(1)</script>'\n응답: HTTP 200 `[ERROR] <!ENTITY> [TRUNCATED]`"
        )
        secs = [_section(1, "DYN-1", poc)]
        w = self._run(cands, secs, {"p2a.md": _PHASE2_WITH_CMD})
        self.assertFalse(any("DYN-1" in x and "플레이스홀더" in x for x in w), w)


if __name__ == "__main__":
    unittest.main()
