#!/usr/bin/env python3
"""
Noah SAST grep 인덱싱 스크립트.

각 스캐너의 phase1.md frontmatter에서 grep_patterns를 추출하여
프로젝트 전체에 grep을 실행하고, 스캐너별 JSON 인덱스를 저장한다.

사용:
  python3 grep_index.py \\
    --scanners-dir <NOAH_SAST_DIR>/scanners \\
    --project-root <PROJECT_ROOT> \\
    --out-dir <PATTERN_INDEX_DIR>

Exit:
  0 = 모든 스캐너 JSON 생성 성공
  1 = 환경/CLI 오류 (grep 부재, 경로 오타, 권한 등)
  2 = 부분 실패 — _failures.json 참조
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML이 필요합니다. `pip install pyyaml`", file=sys.stderr)
    sys.exit(1)


INCLUDE_EXTS = [
    "*.js", "*.jsx", "*.mjs", "*.cjs",
    "*.ts", "*.tsx", "*.mts", "*.cts",
    "*.java", "*.kt", "*.kts", "*.scala", "*.groovy", "*.clj", "*.cljs",
    "*.py", "*.pyw",
    "*.rb", "*.erb", "*.rake",
    "*.php", "*.phtml",
    "*.go",
    "*.rs",
    "*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.hxx",
    "*.cs", "*.cshtml", "*.razor",
    "*.swift", "*.m", "*.mm",
    "*.dart",
    "*.ex", "*.exs", "*.erl", "*.hrl",
    "*.pl", "*.pm",
    "*.lua",
    "*.ps1", "*.psm1",
    "*.hs",
    "*.fs", "*.fsx", "*.ml", "*.mli",
    "*.r", "*.R", "*.jl", "*.nim", "*.cr", "*.zig", "*.d", "*.v",
    "*.sol", "*.coffee", "*.elm", "*.re", "*.res",
    "*.cob", "*.cbl", "*.f90", "*.f95", "*.for", "*.pas", "*.dpr",
    "*.adb", "*.ads", "*.vb", "*.vbs",
    "*.scm", "*.rkt", "*.lisp", "*.cl", "*.tcl", "*.hack", "*.abap",
    "*.cls", "*.trigger", "*.cfm", "*.cfc", "*.pp",
    "*.html", "*.htm", "*.vue", "*.svelte", "*.astro", "*.marko", "*.mdx",
    "*.jsp", "*.asp", "*.aspx", "*.ejs", "*.hbs", "*.pug", "*.jade",
    "*.jinja", "*.jinja2", "*.twig", "*.ftl", "*.mustache", "*.liquid", "*.njk", "*.vm",
    "*.conf", "*.yaml", "*.yml", "*.json", "*.xml", "*.sql",
    "*.tf", "*.tfvars", "*.hcl",
    "*.graphql", "*.gql", "*.proto",
    "*.sh", "*.bash", "*.zsh",
    "*.lock",
]

EXCLUDE_DIRS = [
    "node_modules", ".git", "dist", "build",
    "target", "out", ".next", ".nuxt", ".cache",
    ".gradle", "__pycache__", "vendor", "Pods", "bower_components",
    ".idea", ".vscode", ".husky",
    "coverage", ".nyc_output", ".pytest_cache", ".mypy_cache", ".tox",
    ".eggs", "*.egg-info", ".terraform", ".serverless",
    ".parcel-cache", ".turbo", ".svn", ".hg", "storybook-static",
    # Android: 로케일/리소스 중복 컷 — 기본 values/, drawable/는 유지
    "values-*", "drawable-*", "mipmap-*", "raw",
]

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
GREP_TIMEOUT_SEC = 120


def check_environment() -> None:
    if shutil.which("grep") is None:
        print("ERROR: `grep` 명령을 찾을 수 없습니다", file=sys.stderr)
        sys.exit(1)
    try:
        subprocess.run(
            ["grep", "--version"],
            capture_output=True, check=True, timeout=5,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"ERROR: grep --version 확인 실패: {e}", file=sys.stderr)
        sys.exit(1)


def load_patterns(phase1_md: Path) -> list[str]:
    """phase1.md frontmatter에서 grep_patterns 추출."""
    text = phase1_md.read_text(encoding="utf-8")
    m = FRONTMATTER_RE.match(text)
    if not m:
        raise ValueError("frontmatter 블록(---)을 찾을 수 없음")
    data = yaml.safe_load(m.group(1))
    if data is None:
        return []
    patterns = data.get("grep_patterns", [])
    if not isinstance(patterns, list):
        raise ValueError(f"grep_patterns는 리스트여야 함: {type(patterns).__name__}")
    return [str(p) for p in patterns]


def run_grep(pattern: str, project_root: str) -> tuple[list[str], str | None]:
    """단일 패턴에 대해 grep 실행. (매치 리스트, 오류사유) 반환."""
    include_args = [f"--include={ext}" for ext in INCLUDE_EXTS]
    exclude_args = [f"--exclude-dir={d}" for d in EXCLUDE_DIRS]
    # --binary-files=text: EUC-KR/CP949/ISO-8859 등 비-UTF8 텍스트도 매치 추출
    # (binary로 분류되면 매치 자체가 누락되어 한국 레거시 PHP/JSP 코드베이스에서 다수 누락 발생)
    cmd = [
        "grep", "-rnE", "--binary-files=text",
        *include_args, *exclude_args,
        pattern, project_root,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=GREP_TIMEOUT_SEC, check=False,
        )
    except subprocess.TimeoutExpired:
        return [], "grep_timeout"
    except OSError as e:
        return [], f"io_error: {e}"

    # grep exit code 규약:
    #   0 = 매치 있음, 1 = 매치 없음, 2+ = 오류 (단, 일부 환경에서 access denied도 2)
    # 매치 없음은 정상. 2 이상은 stderr로 판단.
    if result.returncode >= 2:
        # 경고성 stderr(접근 거부 등)는 무시하고 stdout 그대로 사용. 치명적이면 빈 배열.
        # regex 컴파일 실패는 BSD grep에서 "invalid" 메시지를 남긴다.
        err = result.stderr.lower()
        if "invalid" in err or "trailing backslash" in err or "unbalanced" in err:
            return [], f"regex_error: {result.stderr.strip().splitlines()[0] if result.stderr else 'unknown'}"
        # 그 외는 stdout이 있으면 일단 수용
    matches: list[str] = []
    for line in result.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            matches.append(f"{parts[0]}:{parts[1]}")
    return matches, None


def process_scanner(
    scanner_name: str,
    scanner_dir: Path,
    project_root: str,
    out_dir: Path,
    failures: dict,
) -> int:
    """스캐너 1개 처리. 총 히트 수 반환."""
    phase1_md = scanner_dir / "phase1.md"
    if not phase1_md.exists():
        failures.setdefault(scanner_name, []).append(
            {"scanner": scanner_name, "reason": "phase1_md_missing", "detail": str(phase1_md)}
        )
        (out_dir / f"{scanner_name}.json").write_text("{}\n", encoding="utf-8")
        return 0

    try:
        patterns = load_patterns(phase1_md)
    except (yaml.YAMLError, ValueError) as e:
        failures.setdefault(scanner_name, []).append(
            {"scanner": scanner_name, "reason": "yaml_parse_error", "detail": str(e)}
        )
        (out_dir / f"{scanner_name}.json").write_text("{}\n", encoding="utf-8")
        return 0

    results: dict[str, list[str]] = {}
    for pattern in patterns:
        matches, err = run_grep(pattern, project_root)
        results[pattern] = matches
        if err is not None:
            failures.setdefault(scanner_name, []).append(
                {"pattern": pattern, "reason": err.split(":")[0], "detail": err}
            )

    out_path = out_dir / f"{scanner_name}.json"
    out_path.write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return sum(len(v) for v in results.values())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Noah SAST grep 인덱싱 스크립트"
    )
    parser.add_argument("--scanners-dir", required=True,
                        help="<NOAH_SAST_DIR>/scanners 경로")
    parser.add_argument("--project-root", required=True,
                        help="스캔 대상 프로젝트 루트")
    parser.add_argument("--out-dir", required=True,
                        help="JSON 인덱스 저장 디렉토리 (PATTERN_INDEX_DIR)")
    args = parser.parse_args()

    check_environment()

    scanners_dir = Path(args.scanners_dir).resolve()
    project_root = str(Path(args.project_root).resolve())
    out_dir = Path(args.out_dir).resolve()

    if not scanners_dir.is_dir():
        print(f"ERROR: scanners-dir 없음: {scanners_dir}", file=sys.stderr)
        return 1
    if not Path(project_root).is_dir():
        print(f"ERROR: project-root 없음: {project_root}", file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    scanner_dirs = sorted(
        p for p in scanners_dir.iterdir()
        if p.is_dir() and p.name.endswith("-scanner")
    )
    if not scanner_dirs:
        print(f"ERROR: {scanners_dir} 아래 -scanner 디렉토리가 없음", file=sys.stderr)
        return 1

    failures: dict[str, list[dict]] = {}
    counts: dict[str, int] = {}

    for scanner_dir in scanner_dirs:
        name = scanner_dir.name
        try:
            counts[name] = process_scanner(
                name, scanner_dir, project_root, out_dir, failures,
            )
        except Exception as e:
            failures.setdefault(name, []).append(
                {"scanner": name, "reason": "unexpected_error", "detail": repr(e)}
            )
            (out_dir / f"{name}.json").write_text("{}\n", encoding="utf-8")
            counts[name] = 0

    # 무결성 검증
    expected_jsons = {f"{d.name}.json" for d in scanner_dirs}
    actual_jsons = {p.name for p in out_dir.glob("*.json") if p.name != "_failures.json"}
    missing = expected_jsons - actual_jsons
    if missing:
        print(f"ERROR: 무결성 검증 실패 — 누락된 JSON: {sorted(missing)}",
              file=sys.stderr)
        return 1

    # 실패 기록
    if failures:
        (out_dir / "_failures.json").write_text(
            json.dumps(failures, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    # 카운트 요약 (stdout)
    print(f"파일 저장 완료: {out_dir}/")
    print()
    print("스캐너별 히트 건수 (파일경로:라인번호 기준):")
    for name in sorted(counts.keys()):
        print(f"{name}: {counts[name]}건")

    return 2 if failures else 0


def _emit_summary(rc: int) -> None:
    """Claude Code Bash tool은 exit code 비0 시 UI에 경고를 띄운다. 정상·부분 실패
    모두 exit 0으로 종료하고 실제 결과는 stdout 키워드로 전달한다. 메인 에이전트는
    `run_grep_index_exit=N` 줄을 파싱해 분기 판정한다."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--scanners-dir")
    parser.add_argument("--project-root")
    parser.add_argument("--out-dir")
    args, _ = parser.parse_known_args()
    json_count = 0
    expected = 0
    if args.out_dir and Path(args.out_dir).is_dir():
        json_count = len([
            p for p in Path(args.out_dir).glob("*-scanner.json")
            if p.name != "_failures.json"
        ])
    if args.scanners_dir and Path(args.scanners_dir).is_dir():
        expected = len([
            d for d in Path(args.scanners_dir).iterdir()
            if d.is_dir() and d.name.endswith("-scanner")
        ])
    print(f"run_grep_index_exit={rc}")
    print(f"json_count={json_count}")
    print(f"expected={expected}")


if __name__ == "__main__":
    rc = main()
    _emit_summary(rc)
    sys.exit(0)
