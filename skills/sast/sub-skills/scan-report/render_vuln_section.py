#!/usr/bin/env python3
"""
render_vuln_section.py — VulnSection JSON → Markdown renderer

Usage:
    python3 render_vuln_section.py <section.json> [<section2.json> ...] --output <output.md>
    python3 render_vuln_section.py <section.json> [<section2.json> ...] --validate-only
"""

import argparse
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Schema validation (optional: requires jsonschema)
# ---------------------------------------------------------------------------

SCHEMA_PATH = Path(__file__).parent / "vuln_section_schema.json"

try:
    import jsonschema
    _JSONSCHEMA_AVAILABLE = True
except ImportError:
    _JSONSCHEMA_AVAILABLE = False


def load_schema() -> dict:
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


_VALID_STATUS = {"확인됨", "후보"}


def _basic_validate(data: dict, filepath: str) -> list[str]:
    """jsonschema 없을 때 실행할 기본 구조 검증. 위반 메시지 목록 반환."""
    errors = []
    if not isinstance(data.get("scanner"), str):
        errors.append(f"[scanner] 필드가 없거나 문자열이 아님")
    vulns = data.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        errors.append(f"[vulnerabilities] 배열이 아님")
        return errors
    for i, v in enumerate(vulns):
        prefix = f"[vulnerabilities[{i}]]"
        for req in ("id", "title", "type", "status", "location",
                    "entry_boundary", "source", "sink", "cause", "remediation"):
            if not v.get(req):
                errors.append(f"{prefix}.{req} 필수 필드 누락 또는 빈 값")
        status = v.get("status", "")
        if status not in _VALID_STATUS:
            errors.append(
                f"{prefix}.status='{status}' 허용되지 않음 "
                f"(허용: {sorted(_VALID_STATUS)}). 심각도(HIGH/MEDIUM/LOW) 사용 금지."
            )
        poc = v.get("poc")
        if not poc or not isinstance(poc.get("steps"), list) or len(poc["steps"]) == 0:
            errors.append(f"{prefix}.poc.steps 비어있거나 없음 (최소 1단계 필요)")
    return errors


def validate_data(data: dict, filepath: str) -> bool:
    """Return True if valid (or validation skipped). Print and return False on error."""
    if not _JSONSCHEMA_AVAILABLE:
        # jsonschema 없으면 기본 검증으로 대체 (enum 위반 등 주요 항목 포함)
        basic_errors = _basic_validate(data, filepath)
        if basic_errors:
            for msg in basic_errors:
                print(f"SCHEMA_ERROR: {filepath}: {msg}", file=sys.stderr)
            return False
        return True

    schema = load_schema()
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        for err in errors:
            path = ".".join(str(p) for p in err.absolute_path) or "(root)"
            print(f"SCHEMA_ERROR: {filepath}: [{path}] {err.message}", file=sys.stderr)
        return False
    return True


# ---------------------------------------------------------------------------
# Display-name helper
# ---------------------------------------------------------------------------

def scanner_display_name(scanner: str) -> str:
    """
    Remove trailing '-scanner' suffix, then capitalize each word segment.
    e.g. 'xss-scanner'             → 'Xss'
         'hardcoded-secrets-scanner' → 'Hardcoded-Secrets'
    """
    name = scanner
    if name.lower().endswith("-scanner"):
        name = name[: -len("-scanner")]
    # capitalize each hyphen-separated word, re-join with hyphen
    parts = name.split("-")
    return "-".join(p.capitalize() for p in parts)


# ---------------------------------------------------------------------------
# Markdown rendering helpers
# ---------------------------------------------------------------------------

def render_poc_steps(steps: list) -> str:
    if not steps:
        return "_POC 정보 없음_"
    lines = []
    for step in steps:
        lines.append(f"##### {step.get('title', 'Step')}")
        lines.append("")
        lines.append(step.get("content", ""))
        lines.append("")
    return "\n".join(lines).rstrip()


def _get(v: dict, key: str, default: str = "") -> str:
    """dict에서 값을 꺼내되, 없거나 None이면 default 반환."""
    val = v.get(key)
    return str(val) if val is not None else default


def _get_poc_steps(v: dict) -> list:
    """poc.steps 안전 추출."""
    poc = v.get("poc")
    if not poc:
        return []
    return poc.get("steps", [])


def render_vuln_confirmed(n: int, v: dict) -> str:
    """Render a single '확인됨' vulnerability block."""
    blocks = []

    blocks.append(f"#### {n}. {_get(v, 'title', '(제목 없음)')}")
    blocks.append("")
    blocks.append(f"**ID**: {_get(v, 'id')}")
    blocks.append(f"**유형**: {_get(v, 'type')}")
    blocks.append(f"**상태**: 확인됨")
    blocks.append(f"**위치**: `{_get(v, 'location')}`")
    blocks.append(f"**진입 경계**: {_get(v, 'entry_boundary')}")
    blocks.append(f"**Source**: {_get(v, 'source')}")
    blocks.append(f"**Sink**: {_get(v, 'sink')}")
    blocks.append("")
    blocks.append("#### 원인 분석")
    blocks.append("")
    blocks.append(_get(v, "cause", "_원인 분석 없음_"))
    blocks.append("")
    blocks.append("#### 재현 방법 및 POC")
    blocks.append("")
    blocks.append(render_poc_steps(_get_poc_steps(v)))
    blocks.append("")
    blocks.append("#### 권장 조치")
    blocks.append("")
    blocks.append(_get(v, "remediation", "_권장 조치 없음_"))

    return "\n".join(blocks)


def render_vuln_candidate(n: int, v: dict) -> str:
    """Render a single '후보' vulnerability block."""
    blocks = []

    blocks.append(f"#### {n}. {_get(v, 'title', '(제목 없음)')}")
    blocks.append("")
    blocks.append(f"**ID**: {_get(v, 'id')}")
    blocks.append(f"**유형**: {_get(v, 'type')}")
    blocks.append(f"**상태**: 후보 (추가 검증 필요)")
    blocks.append(f"**위치**: `{_get(v, 'location')}`")
    blocks.append(f"**진입 경계**: {_get(v, 'entry_boundary')}")
    unconfirmed = _get(v, "unconfirmed_reason")
    if unconfirmed:
        blocks.append(f"**미확인 사유**: {unconfirmed}")
    blocks.append("")
    blocks.append("#### 소스코드 분석")
    blocks.append("")
    blocks.append(_get(v, "cause", "_소스코드 분석 없음_"))
    blocks.append("")
    blocks.append("#### 재현 방법 및 POC")
    blocks.append("")
    blocks.append(render_poc_steps(_get_poc_steps(v)))
    blocks.append("")
    blocks.append("#### 권장 조치")
    blocks.append("")
    blocks.append(_get(v, "remediation", "_권장 조치 없음_"))

    return "\n".join(blocks)


def render_section(data: dict) -> tuple[str, str, int]:
    """
    Render one VulnSection JSON dict to a Markdown string.
    Returns (markdown_text, display_name, vuln_count).
    """
    display_name = scanner_display_name(data["scanner"])
    vulns = data.get("vulnerabilities", [])

    lines = []
    lines.append(f"### {display_name} Scanner")
    lines.append("")

    for i, v in enumerate(vulns, start=1):
        if v["status"] == "확인됨":
            lines.append(render_vuln_confirmed(i, v))
        else:
            lines.append(render_vuln_candidate(i, v))
        lines.append("")

    return "\n".join(lines).rstrip(), display_name, len(vulns)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Render VulnSection JSON file(s) to Markdown"
    )
    parser.add_argument(
        "inputs",
        metavar="section.json",
        nargs="+",
        help="One or more VulnSection JSON files",
    )
    parser.add_argument(
        "--output",
        metavar="output.md",
        help="Output Markdown file path (required unless --validate-only)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate schema only; do not render",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.validate_only and not args.output:
        print("ERROR: --output is required when not using --validate-only", file=sys.stderr)
        sys.exit(1)

    all_valid = True
    sections: list[tuple[dict, str]] = []  # (data, filepath)

    for filepath in args.inputs:
        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"SCHEMA_ERROR: {filepath}: {exc}", file=sys.stderr)
            all_valid = False
            continue

        if not validate_data(data, filepath):
            all_valid = False
            continue

        sections.append((data, filepath))

    if args.validate_only:
        if all_valid:
            print(f"validation passed: {len(sections)} file(s)")
            sys.exit(0)
        else:
            sys.exit(1)

    if not all_valid:
        # Abort rendering if any file failed validation (and jsonschema is available)
        if _JSONSCHEMA_AVAILABLE:
            sys.exit(1)
        # If jsonschema not available, all_valid was only set False on parse errors
        sys.exit(1)

    # Render
    rendered_parts = []
    summary_parts = []

    for data, _filepath in sections:
        md_text, display_name, count = render_section(data)
        rendered_parts.append(md_text)
        summary_parts.append(f"{display_name}({count}건)")

    output_md = "\n\n".join(rendered_parts) + "\n"

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output_md, encoding="utf-8")

    print(f"rendered: {' '.join(summary_parts)}")
    print(f"output: {output_path}")


if __name__ == "__main__":
    main()
