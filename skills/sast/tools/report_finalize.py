#!/usr/bin/env python3
"""
Step 12 후처리 2~6단계를 일괄 실행: validate → lint → html → links → open.
조건부 단계인 report-review(1단계)는 메인 에이전트가 별도 수행한다.

Usage:
  report_finalize.py <NOAH_SAST_DIR> <PHASE1_RESULTS_DIR> <confirmed_candidate_count>

CWD 요구: 호출 시 작업 디렉토리가 `noah-sast-report.md`가 있는 곳이어야 한다
(`md_to_html.py`가 `os.getcwd()` 기준으로 입력을 읽는다 — 대개 `assemble_report.py`
호출 CWD와 동일).

Exit code:
  항상 0 (Claude Code Bash tool UI 경고 방지). 실제 결과는 stdout의
  `report_finalize_exit=N` 줄과 `failed_step=<단계명>`로 전달한다.
  N = 0(성공), 1(단계 실패), 2(CLI 인자 오류).
"""

import subprocess
import sys
from pathlib import Path


STEPS = [
    # validate_report가 MD·HTML 동기화를 검증하므로 md_to_html을 먼저 실행한다.
    ("md_to_html", "sub-skills/scan-report/md_to_html.py"),
    ("validate_report", "sub-skills/scan-report/validate_report.py"),
    ("lint_reader_layer", "tools/lint_reader_layer.py"),
    ("validate_links", "sub-skills/scan-report/validate_links.py"),
    ("open", None),
]

REPORT_MD = "noah-sast-report.md"
REPORT_HTML = "noah-sast-report.html"


def _run(name: str, cmd: list[str]) -> int:
    print(f"[{name}] {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, check=False)
        return r.returncode
    except FileNotFoundError as e:
        print(f"[{name}] FileNotFoundError: {e}", file=sys.stderr)
        return 127


def main() -> tuple[int, str]:
    if len(sys.argv) != 4:
        print(
            "Usage: report_finalize.py <NOAH_SAST_DIR> <PHASE1_RESULTS_DIR> "
            "<confirmed_candidate_count>",
            file=sys.stderr,
        )
        return 2, "cli_args"

    noah_sast_dir = Path(sys.argv[1])
    phase1_results_dir = Path(sys.argv[2])
    count = sys.argv[3]

    for name, rel in STEPS:
        if name == "validate_report":
            rc = _run(name, [
                "python3", str(noah_sast_dir / rel), count,
                "--master-list", str(phase1_results_dir / "master-list.json"),
            ])
        elif name == "lint_reader_layer":
            rc = _run(name, ["python3", str(noah_sast_dir / rel), REPORT_MD])
        elif name == "md_to_html":
            rc = _run(name, ["python3", str(noah_sast_dir / rel)])
        elif name == "validate_links":
            rc = _run(name, ["python3", str(noah_sast_dir / rel), REPORT_HTML])
        elif name == "open":
            rc = _run(name, ["open", REPORT_HTML])
        else:
            continue
        # validate_report exit 6 = 경고 수준 (파일 유지) — 통과 처리
        if name == "validate_report" and rc == 6:
            print(f"[{name}] OK (warnings only, exit=6)")
            continue
        if rc != 0:
            print(f"[{name}] FAIL (exit={rc})")
            return 1, name
        print(f"[{name}] OK")

    return 0, ""


if __name__ == "__main__":
    rc, failed_step = main()
    print(f"report_finalize_exit={rc}")
    if failed_step:
        print(f"failed_step={failed_step}")
    sys.exit(0)
