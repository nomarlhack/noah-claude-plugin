#!/usr/bin/env python3
"""
Noah SAST semgrep 인덱싱 스크립트.

각 스캐너의 `rules/` 디렉토리에 있는 *.yaml semgrep 룰을 실행하여
프로젝트 전체에 매치를 인덱싱하고, 스캐너별 JSON 인덱스를 저장한다.

Phase 1 패턴 인덱싱의 단일 진실 원천이다:
- `rules/` 디렉토리가 있는 스캐너: semgrep 룰(pattern/taint)을 실행해 매치를 인덱싱
- `rules/`가 없는 grep-less 스캐너(business-logic 등): 빈 `{}` 인덱스를 작성

모든 스캐너의 JSON 인덱스를 PATTERN_INDEX_DIR에 작성한다.

출력 JSON 포맷:
  {
    "<rule_id>": ["path/to/file.kt:42", "path/to/other.kt:7", ...],
    ...
  }

사용:
  python3 semgrep_index.py \\
    --scanners-dir <NOAH_SAST_DIR>/scanners \\
    --project-root <PROJECT_ROOT> \\
    --out-dir <PATTERN_INDEX_DIR> \\
    [--exclude-paths <PATH1> <PATH2> ...]

  스킬 디렉토리가 project-root 안에 있으면 자동으로 스캔 대상에서 제외된다.
  추가로 제외할 경로가 있으면 --exclude-paths로 지정 (절대경로 또는 project-root 기준 상대경로).

Exit (stdout `run_semgrep_index_exit=N`):
  0 = 정상 (rules/ 있는 모든 스캐너 처리 성공)
  1 = 환경/CLI 오류 (semgrep 부재, 경로 오류)
  2 = 부분 실패 — _semgrep_failures.json 참조
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


SEMGREP_TIMEOUT_SEC = 600

# 비-UTF8 텍스트 파일을 디코딩 시도하는 인코딩 우선순위.
# euc-kr/cp949는 한국 레거시 PHP/JSP, shift_jis는 일본 코드베이스, iso-8859-1은 fallback.
DECODE_TRY_ENCODINGS = ("utf-8-sig", "euc-kr", "cp949", "shift_jis", "iso-8859-1")

# UTF-8 mirror 빌드 시 제외할 디렉토리
MIRROR_EXCLUDE_DIRS = {
    "node_modules", ".git", "dist", "build",
    "target", "out", ".next", ".nuxt", ".cache",
    ".gradle", "__pycache__", "vendor", "Pods", "bower_components",
    ".idea", ".vscode", ".husky",
    "coverage", ".nyc_output", ".pytest_cache", ".mypy_cache", ".tox",
    ".eggs", ".terraform", ".serverless",
    ".parcel-cache", ".turbo", ".svn", ".hg", "storybook-static",
}

# 코드 확장자 필터링.
# `languages: [generic]` 룰이 .png/.lock 등 무관 파일까지 스캔하는 것을 차단.
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
]


def _has_code_ext(path: Path) -> bool:
    suffix = path.suffix.lower()
    return any(suffix == ext.lstrip("*").lower() for ext in INCLUDE_EXTS)


def build_utf8_mirror(
    project_root: Path,
    exclude_abs: set[str] | None = None,
) -> tuple[Path | None, dict[str, str]]:
    """비-UTF8 텍스트 파일을 UTF-8로 변환한 임시 미러 디렉토리 생성.

    반환: (mirror_root, {mirror_abs_path: original_abs_path} 매핑).
    변환된 파일이 0건이면 (None, {}) 반환.
    exclude_abs: 스캔에서 제외할 절대경로 집합.
    """
    mirror = Path(tempfile.mkdtemp(prefix="noah_sast_utf8_mirror_"))
    mapping: dict[str, str] = {}
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in MIRROR_EXCLUDE_DIRS for part in path.parts):
            continue
        if exclude_abs and any(
            str(path.resolve()).startswith(ep) for ep in exclude_abs
        ):
            continue
        if not _has_code_ext(path):
            continue
        try:
            raw = path.read_bytes()
        except (OSError, PermissionError):
            continue
        try:
            raw.decode("utf-8")
            continue  # 이미 UTF-8
        except UnicodeDecodeError:
            pass
        decoded: str | None = None
        for enc in DECODE_TRY_ENCODINGS:
            try:
                decoded = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if decoded is None:
            continue
        try:
            rel = path.relative_to(project_root)
        except ValueError:
            continue
        dst = mirror / rel
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(decoded, encoding="utf-8")
            mapping[str(dst.resolve())] = str(path.resolve())
        except OSError:
            continue
    if not mapping:
        shutil.rmtree(mirror, ignore_errors=True)
        return None, {}
    return mirror, mapping


def check_environment() -> None:
    if shutil.which("semgrep") is None:
        print(
            "ERROR: `semgrep` 명령을 찾을 수 없습니다. `pip install semgrep` 또는 `brew install semgrep`",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        subprocess.run(
            ["semgrep", "--version"],
            capture_output=True, check=True, timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"ERROR: semgrep --version 확인 실패: {e}", file=sys.stderr)
        sys.exit(1)


def collect_rule_files(rules_dir: Path) -> list[Path]:
    """rules/ 아래 모든 *.yaml / *.yml 파일."""
    files: list[Path] = []
    for ext in ("*.yaml", "*.yml"):
        files.extend(sorted(rules_dir.glob(ext)))
    return files


# php 전용 룰 파일(언어 suffix 컨벤션: pattern.php.yaml / taint.php.yaml).
# semgrep의 PHP 분석기는 병렬 멀티파일 스캔에서 매치를 비결정적으로 누락한다
# (-j 1 단일 스레드에서만 안정. 검증: 다른 7개 언어는 병렬에서도 결정적, PHP만 요동).
# 따라서 php 룰은 -j 1 + *.php 한정으로 별도 패스 실행해 결정성을 확보한다.
PHP_RULE_SUFFIXES = (".php.yaml", ".php.yml")

# project_root별 .php 파일 존재 여부 캐시 (스캐너마다 트리를 다시 걷지 않도록).
_HAS_PHP_CACHE: dict[str, bool] = {}


def _project_has_php(project_root: str, extra_targets: list[str] | None) -> bool:
    """project_root(및 mirror 타깃)에 .php 파일이 하나라도 있으면 True. 결과 캐시."""
    if project_root in _HAS_PHP_CACHE:
        return _HAS_PHP_CACHE[project_root]
    found = False
    for root in [project_root, *(extra_targets or [])]:
        try:
            if next(Path(root).rglob("*.php"), None) is not None:
                found = True
                break
        except OSError:
            pass
    _HAS_PHP_CACHE[project_root] = found
    return found


def _invoke_semgrep(
    rule_files: list[Path],
    project_root: str,
    include_exts: list[str],
    extra_targets: list[str] | None,
    exclude_abs: set[str] | None,
    jobs: int | None,
) -> tuple[dict, str | None]:
    """semgrep 1회 호출 → (data, error). jobs가 주어지면 -j <jobs>로 병렬도 고정."""
    cmd = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore"]
    for ext in include_exts:
        cmd.extend(["--include", ext])
    for rf in rule_files:
        cmd.extend(["--config", str(rf)])
    # 스캔 대상에서 제외할 경로. project_root 기준 상대경로로 변환해서 --exclude 적용.
    if exclude_abs:
        proj = Path(project_root).resolve()
        for ep in exclude_abs:
            try:
                rel = Path(ep).relative_to(proj)
                cmd.extend(["--exclude", str(rel)])
            except ValueError:
                pass  # project_root 밖 경로는 무시
    if jobs is not None:
        cmd.extend(["-j", str(jobs)])
    cmd.append(project_root)
    if extra_targets:
        cmd.extend(extra_targets)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=SEMGREP_TIMEOUT_SEC, check=False,
        )
    except subprocess.TimeoutExpired:
        return {}, "semgrep_timeout"
    except OSError as e:
        return {}, f"io_error: {e}"

    # semgrep exit code: 0 (findings 0건도 0), 1 (finding 있음), 2+ 오류
    if result.returncode not in (0, 1):
        err_snippet = (result.stderr or "").strip().splitlines()[:5]
        return {}, f"semgrep_error: rc={result.returncode}: {' | '.join(err_snippet)}"

    if not result.stdout.strip():
        return {}, None

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {}, f"json_decode_error: {e}"

    return data, None


def run_semgrep(
    rule_files: list[Path],
    project_root: str,
    extra_targets: list[str] | None = None,
    exclude_abs: set[str] | None = None,
) -> tuple[dict, str | None]:
    """semgrep 실행. 결과 JSON 파싱 후 (results, error) 반환.
    extra_targets가 있으면 함께 스캔 (UTF-8 mirror 디렉토리 지원).
    exclude_abs: --exclude 경로로 제외할 절대경로 집합.

    php 전용 룰이 있고 프로젝트에 .php가 있으면 결정성 확보를 위해 2-패스로 실행:
      (1) php 제외 룰 → 병렬(기본 -j)로 전체 스캔
      (2) php 룰만 → -j 1 + *.php 한정으로 스캔
    두 패스 결과를 병합한다. php가 없는 프로젝트는 기존과 동일하게 단일 패스."""
    php_rules = [rf for rf in rule_files if str(rf).endswith(PHP_RULE_SUFFIXES)]
    other_rules = [rf for rf in rule_files if rf not in php_rules]

    # php 룰이 없거나 프로젝트에 .php가 없으면 단일 패스(기존 동작 그대로).
    if not php_rules or not _project_has_php(project_root, extra_targets):
        return _invoke_semgrep(
            rule_files, project_root, INCLUDE_EXTS, extra_targets, exclude_abs, None
        )

    # 2-패스. .php는 패스2 전담이므로 패스1 include에서 제외(중복 스캔 방지).
    merged: dict = {"results": [], "errors": []}

    if other_rules:
        non_php_exts = [e for e in INCLUDE_EXTS if e != "*.php"]
        data_main, err_main = _invoke_semgrep(
            other_rules, project_root, non_php_exts, extra_targets, exclude_abs, None
        )
        if err_main is not None:
            # 메인 패스 실패는 기존처럼 전체 실패로 처리(보수적).
            return {}, err_main
        merged["results"].extend(data_main.get("results", []))
        merged["errors"].extend(data_main.get("errors", []))

    # php 패스: -j 1 단일 스레드 + *.php 한정 (결정성).
    data_php, err_php = _invoke_semgrep(
        php_rules, project_root, ["*.php"], extra_targets, exclude_abs, 1
    )
    if err_php is not None:
        if not other_rules:
            return {}, err_php
        # 메인은 성공했는데 php 패스만 실패 → 메인 결과는 보존하고 php 실패는 비치명적 기록.
        merged["errors"].append({"type": "php_pass_error", "message": err_php})
    else:
        merged["results"].extend(data_php.get("results", []))
        merged["errors"].extend(data_php.get("errors", []))

    return merged, None


def normalize_check_id(check_id: str) -> str:
    """semgrep check_id는 룰 파일 경로 + 룰 id를 합친 형태로 나오므로 마지막 컴포넌트만 추출."""
    return check_id.rsplit(".", 1)[-1]


# tier 우선순위: taint(dataflow 확정) > ast(언어 파서) > generic(regex)
TIER_RANK = {"taint": 3, "ast": 2, "generic": 1}


def rule_tier(rule_id: str) -> str:
    """룰 ID 네이밍 컨벤션으로 신뢰도 tier 판정.
    - *-taint            → dataflow가 source 도달성 + sanitizer 부재 확정 (고신뢰)
    - noah-<slug>-phase1-pattern → generic regex (언어 무관, 위치만, 저신뢰)
    - 그 외 (noah-<lang>-...-pattern, *-sink-pattern 등) → 언어 AST 매치 (중간)
    """
    if rule_id.endswith("-taint"):
        return "taint"
    if rule_id.endswith("-phase1-pattern") and "-" in rule_id:
        # generic 룰은 noah-<slug>-phase1-pattern 형식. 언어 prefix가 없으면 generic.
        # noah-python-sqli-phase1-pattern 처럼 언어가 박힌 것은 ast로 본다.
        mid = rule_id[len("noah-"):-len("-phase1-pattern")] if rule_id.startswith("noah-") else ""
        langs = {"python", "javascript", "typescript", "java", "kotlin",
                 "go", "ruby", "php", "csharp", "scala"}
        first = mid.split("-")[0] if mid else ""
        return "ast" if first in langs else "generic"
    return "ast"


def process_scanner(
    scanner_name: str,
    scanner_dir: Path,
    project_root: str,
    out_dir: Path,
    failures: dict,
    utf8_mirror: Path | None = None,
    mirror_path_map: dict[str, str] | None = None,
    exclude_abs: set[str] | None = None,
) -> int:
    """스캐너 1개 처리. rules/ 디렉토리가 있어야 처리. 총 매치 수 반환."""
    rules_dir = scanner_dir / "rules"
    if not rules_dir.is_dir():
        # rules/ 없는 grep-less 스캐너(business-logic 등): 빈 인덱스를 작성해
        # 다운스트림(select_scanners 등)의 인덱스 파일 계약을 유지하고 skip 신호 반환.
        (out_dir / f"{scanner_name}.json").write_text("{}\n", encoding="utf-8")
        return -1  # skip 신호 (rules 없음)

    rule_files = collect_rule_files(rules_dir)
    if not rule_files:
        failures.setdefault(scanner_name, []).append(
            {"scanner": scanner_name, "reason": "no_rule_files", "detail": str(rules_dir)}
        )
        (out_dir / f"{scanner_name}.json").write_text("{}\n", encoding="utf-8")
        return 0

    extra = [str(utf8_mirror)] if utf8_mirror else None
    data, err = run_semgrep(rule_files, project_root, extra_targets=extra, exclude_abs=exclude_abs)
    if err is not None:
        failures.setdefault(scanner_name, []).append(
            {"scanner": scanner_name, "reason": err.split(":")[0], "detail": err}
        )
        (out_dir / f"{scanner_name}.json").write_text("{}\n", encoding="utf-8")
        return 0

    # semgrep errors 필드 점검 (rule parse error 등)
    sem_errors = data.get("errors", [])
    if sem_errors:
        for se in sem_errors:
            failures.setdefault(scanner_name, []).append({
                "scanner": scanner_name,
                "reason": se.get("type", "semgrep_rule_error"),
                "detail": se.get("message", str(se))[:500],
            })

    # results를 rule_id별로 그룹핑. mirror path는 원본 path로 치환.
    results_by_rule: dict[str, list[str]] = {}
    seen: set[tuple[str, str, int]] = set()
    # 위치별 인덱스 (사이드카 locindex.json용): "file:line" → {rule_ids, tier, severity}
    loc_index: dict[str, dict] = {}
    tiers_present: set[str] = set()
    for finding in data.get("results", []):
        rule_id = normalize_check_id(finding.get("check_id", "unknown"))
        path = finding.get("path", "")
        line = finding.get("start", {}).get("line", 0)
        if not path or not line:
            continue
        # mirror 안의 경로면 원본 경로로 치환
        if mirror_path_map:
            try:
                abs_path = str(Path(path).resolve())
            except OSError:
                abs_path = path
            original = mirror_path_map.get(abs_path)
            if original:
                path = original
        loc = f"{path}:{line}"
        tier = rule_tier(rule_id)
        severity = finding.get("extra", {}).get("severity", "")
        tiers_present.add(tier)

        # 위치별 dedup: 같은 file:line이 여러 룰에 매치되면 rule_ids 배열로 보존하고
        # tier는 최고로 승격. (트레이드오프 2 해결 — 다중 취약점 관점 손실 방지)
        slot = loc_index.get(loc)
        if slot is None:
            loc_index[loc] = {
                "rule_ids": [rule_id],
                "tier": tier,
                "severity": severity,
            }
        else:
            if rule_id not in slot["rule_ids"]:
                slot["rule_ids"].append(rule_id)
            if TIER_RANK.get(tier, 0) > TIER_RANK.get(slot["tier"], 0):
                slot["tier"] = tier
                slot["severity"] = severity

        key = (rule_id, path, line)
        if key in seen:
            continue  # 원본 + mirror 양쪽에서 매치된 경우 중복 제거
        seen.add(key)
        results_by_rule.setdefault(rule_id, []).append(loc)

    # 매치가 0건인 rule은 키로 포함시키지 않는다 (select_scanners.py의
    # sum(len(v) for v in data.values()) 집계에는 영향 없음).
    # 비-UTF8 파일 누락은 UTF-8 mirror가 보강하므로 별도 머지 단계가 필요 없다.
    out_path = out_dir / f"{scanner_name}.json"
    out_path.write_text(
        json.dumps(results_by_rule, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    # 사이드카 locindex.json — 위치별 rule_ids + 최고 tier + severity + 스캐너 메타.
    # Phase 1 그룹 에이전트가 tier 우선순위(taint→ast→generic)로 검토하는 데 사용.
    # has_taint: "이번 스캔에서 taint 매치가 1건이라도 발생했는지" (룰 보유 여부 아님).
    #   true  → dataflow 신호 작동 → generic-only 위치를 후순위로 (taint/ast 우선)
    #   false → ast/generic이 유일 신호 → 전수 분석 (후순위 금지, FN 방지)
    has_taint = "taint" in tiers_present
    has_ast = "ast" in tiers_present
    locindex_out = {
        "_scanner": {
            "name": scanner_name,
            "has_taint": has_taint,
            "has_ast": has_ast,
            "tiers_present": sorted(tiers_present, key=lambda t: -TIER_RANK.get(t, 0)),
            "tier_counts": {
                t: sum(1 for s in loc_index.values() if s["tier"] == t)
                for t in ("taint", "ast", "generic")
            },
        },
        "locations": loc_index,
    }
    locindex_path = out_dir / f"{scanner_name}.locindex.json"
    locindex_path.write_text(
        json.dumps(locindex_out, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    return sum(len(v) for v in results_by_rule.values())


def resolve_exclude_paths(
    project_root: Path,
    scanners_dir: Path,
    extra_paths: list[str],
) -> set[str]:
    """스캔 제외 절대경로 집합을 계산.

    - 스킬 자신의 상위 디렉토리(noah-sast)가 project-root 안에 있으면 자동 감지해 제외.
    - --exclude-paths 인수로 추가 지정 가능.
    """
    exclude: set[str] = set()

    # scanners_dir은 <NOAH_SAST_DIR>/scanners — 상위가 스킬 루트
    skill_root = scanners_dir.parent.resolve()
    proj = project_root.resolve()
    try:
        skill_root.relative_to(proj)
        exclude.add(str(skill_root))
        print(
            f"  스킬 디렉토리 자동 제외: {skill_root}",
            file=sys.stderr,
        )
    except ValueError:
        pass  # 스킬이 project-root 밖에 있음 — 제외 불필요

    for p in extra_paths:
        resolved = Path(p).resolve()
        exclude.add(str(resolved))

    return exclude


def main() -> int:
    parser = argparse.ArgumentParser(description="Noah SAST semgrep 인덱싱 스크립트")
    parser.add_argument("--scanners-dir", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument(
        "--exclude-paths", nargs="*", default=[],
        help="스캔에서 제외할 추가 경로 (절대경로 또는 project-root 기준 상대경로)",
    )
    args = parser.parse_args()

    check_environment()

    scanners_dir = Path(args.scanners_dir).resolve()
    project_root = Path(args.project_root).resolve()
    out_dir = Path(args.out_dir).resolve()

    if not scanners_dir.is_dir():
        print(f"ERROR: scanners-dir 없음: {scanners_dir}", file=sys.stderr)
        return 1
    if not project_root.is_dir():
        print(f"ERROR: project-root 없음: {project_root}", file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    exclude_abs = resolve_exclude_paths(project_root, scanners_dir, args.exclude_paths)
    project_root_str = str(project_root)

    scanner_dirs = sorted(
        p for p in scanners_dir.iterdir()
        if p.is_dir() and p.name.endswith("-scanner")
    )

    failures: dict[str, list[dict]] = {}
    counts: dict[str, int] = {}
    processed: list[str] = []
    skipped: list[str] = []

    # 비-UTF8 텍스트 파일(EUC-KR/CP949/ISO-8859 등)을 UTF-8로 변환한 임시 미러 빌드.
    # semgrep이 비-UTF8 파일을 파싱 못 해 매치를 누락하는 문제를 보완.
    print("UTF-8 mirror 빌드 중...", file=sys.stderr)
    utf8_mirror, mirror_path_map = build_utf8_mirror(project_root, exclude_abs=exclude_abs)
    if utf8_mirror is not None:
        print(f"  비-UTF8 파일 {len(mirror_path_map)}개 변환 → {utf8_mirror}",
              file=sys.stderr)
    else:
        print("  비-UTF8 파일 없음", file=sys.stderr)

    for scanner_dir in scanner_dirs:
        name = scanner_dir.name
        try:
            n = process_scanner(
                name, scanner_dir, project_root_str, out_dir, failures,
                utf8_mirror=utf8_mirror, mirror_path_map=mirror_path_map,
                exclude_abs=exclude_abs,
            )
        except Exception as e:
            failures.setdefault(name, []).append(
                {"scanner": name, "reason": "unexpected_error", "detail": repr(e)}
            )
            (out_dir / f"{name}.json").write_text("{}\n", encoding="utf-8")
            n = 0

        if n == -1:
            skipped.append(name)
            continue
        counts[name] = n
        processed.append(name)

    # mirror cleanup
    if utf8_mirror is not None:
        shutil.rmtree(utf8_mirror, ignore_errors=True)

    # 실패 기록
    if failures:
        (out_dir / "_semgrep_failures.json").write_text(
            json.dumps(failures, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    print(f"파일 저장 완료: {out_dir}/")
    print()
    if processed:
        print("스캐너별 히트 건수 (semgrep 적용):")
        for name in sorted(processed):
            print(f"{name}: {counts[name]}건")
    else:
        print("semgrep 적용 대상 스캐너 없음 (rules/ 디렉토리를 가진 스캐너가 없음)")
    if skipped:
        print()
        print(f"rules/ 없음 — 빈 인덱스 작성 (grep-less 스캐너): {len(skipped)}개")

    return 2 if failures else 0


def _emit_summary(rc: int) -> None:
    """Bash exit 0, stdout 키워드로 분기 전달 (Claude Code Bash tool UI 경고 회피)."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--scanners-dir")
    parser.add_argument("--project-root")
    parser.add_argument("--out-dir")
    parser.add_argument("--exclude-paths", nargs="*", default=[])
    args, _ = parser.parse_known_args()
    processed_count = 0
    if args.scanners_dir and Path(args.scanners_dir).is_dir():
        for d in Path(args.scanners_dir).iterdir():
            if d.is_dir() and d.name.endswith("-scanner") and (d / "rules").is_dir():
                processed_count += 1
    print(f"run_semgrep_index_exit={rc}")
    print(f"semgrep_processed={processed_count}")


if __name__ == "__main__":
    rc = main()
    _emit_summary(rc)
    sys.exit(0)
