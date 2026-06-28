#!/usr/bin/env python3
"""generate_skeleton.py — 보고서 스켈레톤 MD를 데이터 파일에서 자동 생성한다.

Usage:
    python3 generate_skeleton.py \\
        --master-list /tmp/master-list.json \\
        --auth-boundary /tmp/auth-boundary.json \\
        --phase1-dir /tmp/phase1 \\
        --project-root /path/to/project \\
        --scan-date 2026-06-28 \\
        --stack "언어 :: Kotlin 2.1.21 ;; 웹 :: Spring MVC" \\
        --test-env "https://api.example.com,https://admin.example.com" \\
        --output /tmp/skeleton.md \\
        --select-scanners-output /tmp/select_scanners_output.json

설계 원칙:
    메인 에이전트가 직접 작성하던 스켈레톤(개요, 인증경계 표+mermaid,
    이상없음/미적용 스캐너 표, 플레이스홀더)을 100% 기계적으로 생성한다.
    총괄 요약 및 취약점 요약 테이블은 assemble_report.py가 담당하므로 생성하지 않는다.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path


# 스크립트 위치 기준으로 scanners 디렉토리 자동 resolve (하드코딩 없음)
SCANNERS_DIR = Path(__file__).parent.parent.parent / "scanners"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json(path: str) -> dict | list:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def safe_label(text: str) -> str:
    """mermaid 라벨에서 큰따옴표를 제거하고 특수문자를 안전하게 처리한다."""
    return str(text).replace('"', "'").replace('\n', ' ')


def trunc(text: str, n: int = 20) -> str:
    s = str(text)
    return s[:n] + "…" if len(s) > n else s


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def build_overview(
    project_root: str, scan_date: str, test_env: str, stack: str, master_list: dict,
    no_issue_count: int = 0, not_applied_count: int = 0,
) -> str:
    target = os.path.basename(project_root.rstrip("/\\"))
    candidates = master_list.get("candidates", [])
    confirmed = sum(1 for c in candidates if c.get("status") == "confirmed")
    candidate = sum(1 for c in candidates if c.get("status") == "candidate")
    safe = sum(1 for c in candidates if c.get("status") == "safe")
    lines = [
        "## 개요",
        "",
        f"**대상**: {target}",
        f"**스캔 일시**: {scan_date}",
        "**스캔 방식**: 소스코드 분석 + 동적 테스트",
        # 빈 test_env → '해당 없음' (빈 값이면 lint가 다음 줄을 값으로 오인)
        f"**테스트 환경**: {test_env.strip() or '해당 없음'}",
        f"**스택**: {stack}",
        "",
        # 수치 — inject_summary_table()이 master-list.json 기반으로 최종 교체
        f"**확인됨**: {confirmed}건",
        f"**후보**: {candidate}건",
        f"**안전 (정적·동적 검증 완료)**: {safe}건",
        f"**이상 없음 스캐너**: {no_issue_count}개",
        f"**미적용 스캐너**: {not_applied_count}개",
        "",
        "---",
    ]
    return "\n".join(lines)


def build_auth_boundary(auth_boundary: dict) -> str:
    gateways = auth_boundary.get("gateways", [])
    clients = auth_boundary.get("clients", [])
    routes = auth_boundary.get("routes", [])

    sections = ["## 인증 경계", ""]

    # --- 게이트웨이 표 ---
    if gateways:
        sections += [
            "### 게이트웨이",
            "| ID | 호스트 패턴 | Base Path |",
            "|----|------------|-----------|",
        ]
        for gw in gateways:
            gid = gw.get("id", "")
            hp = gw.get("host_pattern", "")
            bp = gw.get("base_path", "")
            sections.append(f"| {gid} | {hp} | {bp} |")
        sections.append("")

    # --- 클라이언트 표 ---
    if clients:
        sections += [
            "### 클라이언트",
            "| ID | 페르소나 | 자격증명 |",
            "|----|---------|---------|",
        ]
        for cl in clients:
            cid = cl.get("id", "")
            persona = cl.get("persona", "")
            cred = cl.get("credential", "")
            sections.append(f"| {cid} | {persona} | `{cred}` |")
        sections.append("")

    # --- 경로 표 ---
    if routes:
        sections += [
            "### 경로",
            "| 표면 | 클라이언트 | 게이트웨이 | 인증 근거 | 도달성 |",
            "|------|----------|----------|---------|-------|",
        ]
        for rt in routes:
            surface = rt.get("surface_key", rt.get("surface", ""))
            client_ids = ", ".join(rt.get("client_ids", []))
            gw_id = rt.get("gateway_id", "(없음)")
            auth_basis = rt.get("auth_basis", "")
            reachability = rt.get("reachability", "")
            sections.append(f"| `{surface}` | {client_ids} | {gw_id} | {auth_basis} | {reachability} |")
        sections.append("")

    # --- mermaid 흐름도 ---
    need_diagram = (
        len(routes) >= 2 or len(clients) >= 2 or len(gateways) >= 2
    )
    if need_diagram:
        sections += build_mermaid(gateways, clients, routes)
        sections.append("")

    sections.append("---")
    return "\n".join(sections)


def build_mermaid(gateways: list, clients: list, routes: list) -> list[str]:
    lines = [
        "```mermaid",
        "flowchart LR",
        "    classDef gw fill:#3b82f6,stroke:#1d4ed8,color:#fff",
        "    classDef client fill:#fbbf24,stroke:#d97706,color:#000",
        "    classDef surface_auth fill:#22c55e,stroke:#15803d,color:#fff",
        "    classDef surface_anon fill:#ef4444,stroke:#b91c1c,color:#fff",
    ]

    # Gateway nodes
    for gw in gateways:
        gid = gw.get("id", "")
        hp = gw.get("host_pattern", "")
        node_id = f"GW_{re.sub(r'[^A-Za-z0-9_]', '_', gid)}"
        label = safe_label(f"{gid}\\n({hp})")
        lines.append(f'    {node_id}["{label}"]:::gw')

    # Client nodes
    for cl in clients:
        cid = cl.get("id", "")
        cred = cl.get("credential", "")
        node_id = f"C_{re.sub(r'[^A-Za-z0-9_]', '_', cid)}"
        label = safe_label(f"{cid}\\n({trunc(cred, 20)})")
        lines.append(f'    {node_id}["{label}"]:::client')

    # Surface nodes and edges
    for i, rt in enumerate(routes):
        surface = rt.get("surface_key", rt.get("surface", f"surface_{i}"))
        identity_src = rt.get("identity_source", "")
        reachability = rt.get("reachability", "")
        gateway_id = rt.get("gateway_id", "")
        client_ids = rt.get("client_ids", [])

        is_anon = "익명" in str(identity_src) or identity_src == "없음(익명)"
        auth_label = "permitAll" if is_anon else "인증필요"
        css_class = "surface_anon" if is_anon else "surface_auth"
        node_id = f"S_{i}"
        label = safe_label(f"{surface}\\n({auth_label})")
        lines.append(f'    {node_id}["{label}"]:::{css_class}')

        arrow = "-->" if reachability == "확정" else "-.->"

        # edges: clients → surface
        for cid in client_ids:
            c_node = f"C_{re.sub(r'[^A-Za-z0-9_]', '_', cid)}"
            lines.append(f"    {c_node} {arrow} {node_id}")

        # edge: gateway → surface (if gateway specified)
        if gateway_id:
            gw_node = f"GW_{re.sub(r'[^A-Za-z0-9_]', '_', gateway_id)}"
            lines.append(f"    {gw_node} {arrow} {node_id}")

    lines.append("```")
    return lines


def build_scanner_placeholders() -> str:
    lines = [
        "## 스캐너별 실행 결과",
        "",
        "<!-- SCANNER_SECTIONS_HERE -->",
    ]
    return "\n".join(lines)


def build_ai_discovery_placeholder() -> str:
    lines = [
        "## AI 자율 탐색 결과",
        "",
        "<!-- AI_DISCOVERY_SECTION_HERE -->",
    ]
    return "\n".join(lines)


def build_no_issue_table(phase1_dir: str, master_list: dict) -> tuple[str, int]:
    """declared_count: 0인 스캐너 표를 생성한다. (master-list 후보 있는 것 제외)"""
    # scanner 이름 단위로 후보 유무 판별 (ID 기반이 아닌 scanner 필드 기준)
    scanners_with_candidates: set[str] = set()
    for cand in master_list.get("candidates", []):
        scanner = cand.get("scanner", "")
        if scanner:
            scanners_with_candidates.add(scanner)

    no_issue_scanners = []
    phase1_path = Path(phase1_dir)
    if phase1_path.exists():
        for md_file in sorted(phase1_path.glob("*-scanner.md")):
            scanner_name = md_file.stem  # e.g. "xss-scanner"
            # 후보가 있는 스캐너는 이상없음에서 제외
            if scanner_name in scanners_with_candidates:
                continue
            try:
                content = md_file.read_text(encoding="utf-8")
            except Exception:
                continue
            if re.search(r'"declared_count"\s*:\s*0', content):
                # strip common suffixes for display
                display = scanner_name.removesuffix("-scanner")
                no_issue_scanners.append(display)

    lines = [
        "<!-- SAFE_SECTION_HERE -->",
        "",
        "## 이상 없음 스캐너 점검 항목 요약",
        "",
    ]

    if no_issue_scanners:
        lines += [
            "| # | 스캐너 | 판정 | 근거 요약 |",
            "|---|--------|------|---------|",
        ]
        for idx, name in enumerate(no_issue_scanners, 1):
            lines.append(f"| {idx} | {name} | 이상 없음 | 후보 0건 |")
    else:
        lines.append("_이상 없음으로 분류된 스캐너가 없습니다._")

    return "\n".join(lines), len(no_issue_scanners)


def build_not_applied_table(
    phase1_dir: str,
    select_scanners_output: str | None,
) -> tuple[str, int]:
    """미적용 스캐너 목록 표를 생성한다."""
    # All scanner dirs
    all_scanners: set[str] = set()
    if SCANNERS_DIR.exists():
        for d in SCANNERS_DIR.iterdir():
            if d.is_dir() and d.name.endswith("-scanner"):
                all_scanners.add(d.name)

    # 실제 실행된 스캐너 = phase1_dir에 결과 MD 파일이 존재하는 것
    # _expected_scanners.json은 select_scanners.py 기준 33개만 있고 AI 검토 복원 스캐너는 포함 안 됨
    # 따라서 실제 MD 파일 존재 여부로 판별해야 정확함
    executed_scanners: set[str] = set()
    phase1_path = Path(phase1_dir)
    if phase1_path.exists():
        for md_file in phase1_path.glob("*-scanner.md"):
            executed_scanners.add(md_file.stem)
    # 결과 파일이 없으면 _expected_scanners.json fallback
    if not executed_scanners:
        expected_path = phase1_path / "_expected_scanners.json"
        if expected_path.exists():
            try:
                data = load_json(str(expected_path))
                if isinstance(data, list):
                    executed_scanners = set(data)
                elif isinstance(data, dict):
                    executed_scanners = set(data.get("scanners", data.get("expected", [])))
            except Exception:
                pass

    not_applied = sorted(all_scanners - executed_scanners)

    # Reasons from select_scanners_output
    # select_scanners.py 텍스트 출력 형식: | scanner | 0 | ❌ 제외 | 사유 |
    # JSON 형식도 지원
    reasons: dict[str, str] = {}
    if select_scanners_output and os.path.exists(select_scanners_output):
        try:
            raw = open(select_scanners_output, encoding="utf-8").read()
            # 텍스트 파이프 테이블 형식 파싱 (select_scanners.py 기본 출력)
            for line in raw.splitlines():
                m = re.match(
                    r'\|\s*([A-Za-z0-9_-]+)\s*\|\s*\d+\s*\|\s*❌\s*제외\s*\|\s*(.+?)\s*\|',
                    line
                )
                if m:
                    reasons[m.group(1)] = m.group(2).strip()
            # 텍스트 파싱 실패 시 JSON 시도
            if not reasons:
                data = json.loads(raw)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            name = item.get("scanner", item.get("name", ""))
                            reason = item.get("reason", item.get("사유", "해당 없음"))
                            if name:
                                reasons[name] = reason
                elif isinstance(data, dict):
                    excluded = data.get("excluded", data.get("not_applied", []))
                    if isinstance(excluded, list):
                        for item in excluded:
                            if isinstance(item, dict):
                                name = item.get("scanner", item.get("name", ""))
                                reason = item.get("reason", item.get("사유", "해당 없음"))
                                if name:
                                    reasons[name] = reason
                    else:
                        for k, v in data.items():
                            if isinstance(v, str):
                                reasons[k] = v
        except Exception:
            pass

    lines = [
        "## 미적용 스캐너 목록",
        "",
    ]

    if not_applied:
        lines += [
            "| # | 스캐너 | 제외 사유 |",
            "|---|--------|---------|",
        ]
        for idx, name in enumerate(not_applied, 1):
            reason = reasons.get(name, "해당 없음")
            lines.append(f"| {idx} | {name} | {reason} |")
    else:
        lines.append("_미적용 스캐너가 없습니다._")

    return "\n".join(lines), len(not_applied)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="보고서 스켈레톤 MD를 데이터 파일에서 자동 생성한다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--master-list", required=True, help="master-list.json 경로")
    parser.add_argument("--auth-boundary", required=True, help="auth-boundary.json 경로")
    parser.add_argument("--phase1-dir", required=True, help="Phase1 결과 디렉토리 경로")
    parser.add_argument("--project-root", required=True, help="프로젝트 루트 경로")
    parser.add_argument("--scan-date", required=True, help="스캔 일시 (YYYY-MM-DD)")
    parser.add_argument("--stack", required=True, help="스택 정보")
    parser.add_argument("--test-env", required=True, help="테스트 환경 호스트 (쉼표 구분)")
    parser.add_argument("--output", required=True, help="출력 skeleton.md 경로")
    parser.add_argument(
        "--select-scanners-output",
        default=None,
        help="select_scanners.py 출력 파일 경로 (미적용 사유 포함, 선택)",
    )
    args = parser.parse_args()

    # Load data — 파일 없음 시 친화적 오류 출력
    try:
        master_list = load_json(args.master_list)
    except FileNotFoundError:
        print(f"ERROR: master-list.json 파일 없음: {args.master_list}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: master-list.json 파싱 실패: {e}", file=sys.stderr)
        sys.exit(1)
    if isinstance(master_list, list):
        master_list = {"candidates": master_list}

    try:
        auth_boundary = load_json(args.auth_boundary)
    except FileNotFoundError:
        print(f"ERROR: auth-boundary.json 파일 없음: {args.auth_boundary}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: auth-boundary.json 파싱 실패: {e}", file=sys.stderr)
        sys.exit(1)
    if isinstance(auth_boundary, list):
        auth_boundary = {"routes": auth_boundary}

    # Build sections (overview는 이상없음/미적용 수치 계산 후 재생성)
    auth_section = build_auth_boundary(auth_boundary)
    chain_placeholder = "<!-- CHAIN_SECTION_HERE -->"
    scanner_section = build_scanner_placeholders()
    ai_section = build_ai_discovery_placeholder()
    no_issue_section, no_issue_count = build_no_issue_table(args.phase1_dir, master_list)
    not_applied_section, not_applied_count = build_not_applied_table(
        args.phase1_dir, args.select_scanners_output
    )

    # 이상없음/미적용 수치 확보 후 overview 재생성
    overview = build_overview(
        args.project_root, args.scan_date, args.test_env, args.stack, master_list,
        no_issue_count=no_issue_count, not_applied_count=not_applied_count,
    )

    gw_count = len(auth_boundary.get("gateways", []))

    # Assemble
    parts = [
        "# 통합 취약점 스캔 보고서",
        "",
        overview,
        "",
        auth_section,
        "",
        chain_placeholder,
        "",
        scanner_section,
        "",
        ai_section,
        "",
        no_issue_section,
        "",
        not_applied_section,
    ]
    content = "\n".join(parts) + "\n"

    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")

    section_count = 7  # overview, auth, chain, scanner, ai, no-issue, not-applied
    print(
        f"generated: {args.output} "
        f"({section_count}개 섹션, 게이트웨이 {gw_count}개, "
        f"이상없음 {no_issue_count}개, 미적용 {not_applied_count}개)"
    )


if __name__ == "__main__":
    main()
