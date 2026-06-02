#!/usr/bin/env python3
"""
lint_reader_layer.py — 보고서 MD/HTML의 헤딩 및 개요 필드 검증.

vuln-format.md를 단일 진실 원천으로 사용한다. 두 가지 검증:

1. **헤딩 검사** (h1~h6): _contracts.md §9의 내부 규약 용어(BANNED_PATTERNS)가
   헤딩 텍스트에 노출되지 않았는지 검사. 정규식 블랙리스트 방식.

2. **개요 필드 검사**: 보고서 최상단 개요 블록의 `**필드명**:` 라인을
   vuln-format.md의 "통합 보고서 구조" 섹션에서 파싱한 **허용 필드 집합**과
   대조. 블랙리스트 없이 단일 출처 화이트리스트로 검증하므로 필드 이름이
   단어 변형을 거쳐도 스펙에 없으면 차단된다.

   - 신규 필드가 필요하면 vuln-format.md의 "통합 보고서 구조" 코드 블록을
     먼저 갱신. lint가 다음 실행 시 자동 반영.
   - 스펙 파일을 찾지 못하면 개요 검사는 스킵 (헤딩 검사만 수행).

Exit code:
  0: pass
  5: lint 위반 (헤딩 금지 토큰 또는 스펙 외 개요 필드)
  1: CLI 인자 오류

Usage:
  python3 lint_reader_layer.py <report.md> [<report.html>]
"""

import os
import re
import sys

# 금지 토큰 정규식 (헤딩 한정 — _contracts.md §9 내부 규약 용어 차단용)
# 개요 필드명은 블랙리스트가 아니라 vuln-format.md 스펙 기반 화이트리스트로 검사한다.
BANNED_PATTERNS = [
    (r"§\s*\d+", "§N (checklist 섹션 번호)"),
    (r"\bmode\s*=\s*(phase1-review|phase2-review|report-review)\b", "mode명"),
    (r"\b(DISCARD|OVERRIDE|CONFIRM)\b", "내부 라벨 (DISCARD/OVERRIDE/CONFIRM)"),
    (r"Source\s*도달성", "Source 도달성"),
    (r"실질\s*영향\s*반증", "실질 영향 반증"),
    (r"\b[a-z0-9_-]+\.py\b", "스크립트 파일명"),
    (r"phase1_(validated|discarded_reason|eval_state)", "phase1_* 필드명"),
    (r"safe_category", "safe_category 필드명"),
]

# 헤딩 패턴: MD는 `^#+\s`, HTML은 `<h\d>`
MD_HEADING = re.compile(r"^(#+)\s+(.*)$", re.MULTILINE)
HTML_HEADING = re.compile(r"<h(\d)[^>]*>(.*?)</h\d>", re.IGNORECASE | re.DOTALL)

# 개요 필드 패턴: **필드명**: 값 — 필드명만 검사 대상
MD_OVERVIEW_FIELD = re.compile(r"^\*\*([^*]+?)\*\*\s*:\s*(.+)$", re.MULTILINE)


def _load_allowed_overview_fields():
    """vuln-format.md의 '통합 보고서 구조' 섹션에서 허용 필드 목록 추출.

    반환: 허용 필드 이름 리스트 (순서 유지), 스펙 파싱 실패 시 None.
    스펙 파일 경로는 본 스크립트 기준 상대 경로 resolve.
    """
    spec_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "sub-skills", "scan-report", "vuln-format.md"
    )
    if not os.path.isfile(spec_path):
        return None
    text = open(spec_path, encoding="utf-8").read()
    # "## 통합 보고서 구조" 헤딩 직후 첫 ```markdown 코드 블록 추출
    m = re.search(
        r"##\s+통합\s*보고서\s*구조\s*\n\s*```markdown\s*\n(.*?)\n```",
        text, re.DOTALL
    )
    if not m:
        return None
    block = m.group(1)
    fields = re.findall(r"^\*\*([^*]+?)\*\*\s*:", block, re.MULTILINE)
    return [f.strip() for f in fields]


# 템플릿 변수 → 정규식 치환 테이블
TEMPLATE_VAR_REGEX = {
    "{N}": r"\d+",
    "{SCANNER_NAME}": r"[A-Za-z0-9가-힣/][A-Za-z0-9가-힣/\s\-]*",
    "{VULN_TITLE}": r".+",
    "{TITLE}": r".+",
    "{IDS}": r"[A-Z][A-Z0-9_]*-\d+(?:\s*~\s*[A-Z][A-Z0-9_]*-\d+)?",
}


def _load_allowed_heading_spec():
    """vuln-format.md의 '보고서 섹션 구조' 섹션에서 허용 헤딩 스펙 추출.

    라인 단위 상태 머신으로 파싱한다. 정규식 기반 섹션 추출은 코드블록
    내부의 `##` 같은 예시 헤딩을 섹션 종료로 오인하므로 부적절.

    반환: (fixed_headings_set, template_regex_list)
    스펙 파싱 실패 시 (None, None).
    """
    spec_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "sub-skills", "scan-report", "vuln-format.md"
    )
    if not os.path.isfile(spec_path):
        return (None, None)
    with open(spec_path, encoding="utf-8") as f:
        lines = f.read().split("\n")

    fixed_set = set()
    template_regexes = []

    # 상태: outside / in_section / in_fixed_block / in_template_block
    state = "outside"
    in_code_fence = False
    subsection = None  # "fixed" | "template" | None
    section_started = False

    SECTION_HEADING_RE = re.compile(r"^##\s+보고서\s*섹션\s*구조\b")
    SUB_FIXED_RE = re.compile(r"^###\s+고정\s*헤딩\b")
    SUB_TEMPLATE_RE = re.compile(r"^###\s+템플릿\s*헤딩\b")

    for line in lines:
        stripped = line.strip()

        # 1. 섹션 시작 진입
        if state == "outside":
            if SECTION_HEADING_RE.match(line):
                state = "in_section"
            continue

        # 2. 섹션 내부
        # 다음 top-level `## ` 헤딩을 만나면 섹션 종료 (단 코드블록 밖일 때만)
        if not in_code_fence and re.match(r"^##\s+[^#]", line) and not SECTION_HEADING_RE.match(line):
            break

        # 코드블록 fence 토글
        if stripped.startswith("```"):
            if in_code_fence:
                # 블록 종료
                in_code_fence = False
                subsection = None
            else:
                in_code_fence = True
            continue

        # 서브섹션 헤더 (코드블록 밖)
        if not in_code_fence:
            if SUB_FIXED_RE.match(line):
                subsection = "fixed_pending"  # 다음 코드블록이 고정 헤딩
                continue
            if SUB_TEMPLATE_RE.match(line):
                subsection = "template_pending"
                continue
            # 다른 서브섹션으로 이동
            if re.match(r"^###\s+", line):
                subsection = None
            continue

        # 코드블록 내부
        if in_code_fence:
            # subsection_pending → 실제 수집 상태로 전환 (fence 진입 시)
            # 위 로직에서 fence 진입 시 subsection은 pending 상태이므로 여기서 처리
            if subsection == "fixed_pending":
                subsection = "fixed"
            elif subsection == "template_pending":
                subsection = "template"

            if subsection == "fixed":
                if re.match(r"^#+\s+\S", stripped):
                    fixed_set.add(stripped)
            elif subsection == "template":
                if re.match(r"^#+\s+\S", stripped):
                    pattern = re.escape(stripped)
                    for var, var_regex in TEMPLATE_VAR_REGEX.items():
                        pattern = pattern.replace(re.escape(var), var_regex)
                    template_regexes.append(re.compile(f"^{pattern}$"))

    if not fixed_set and not template_regexes:
        return (None, None)
    return (fixed_set, template_regexes)


def _strip_code_blocks(text: str) -> str:
    """MD 텍스트에서 ```...``` 코드블록 내부를 공백 라인으로 대체.

    헤딩 정규식이 코드블록 내부 `# 주석`을 헤딩으로 오인하지 않도록 전처리.
    라인 수는 유지하여 라인 번호 계산 정합성 보존.
    """
    result = []
    in_code = False
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("```"):
            in_code = not in_code
            result.append("")  # fence 라인도 비움
            continue
        if in_code:
            result.append("")  # 코드블록 내부는 공백 라인
        else:
            result.append(line)
    return "\n".join(result)


# 모듈 로드 시 1회만 스펙 파싱 (단일 진실 원천)
ALLOWED_OVERVIEW_FIELDS = _load_allowed_overview_fields()
ALLOWED_FIXED_HEADINGS, ALLOWED_TEMPLATE_HEADINGS = _load_allowed_heading_spec()


def _heading_matches_spec(level: int, heading: str) -> bool:
    """헤딩이 허용 스펙에 매칭되는지 확인."""
    if ALLOWED_FIXED_HEADINGS is None:
        return True  # 스펙 파싱 실패 시 헤딩 검사 스킵
    full = "#" * level + " " + heading
    if full in ALLOWED_FIXED_HEADINGS:
        return True
    for pat in (ALLOWED_TEMPLATE_HEADINGS or []):
        if pat.match(full):
            return True
    return False


def _extract_overview_block(text: str) -> tuple[str, int]:
    """보고서 최상단의 개요 블록을 추출한다.

    `# 제목` → `## 개요`(선택) → `**필드**:` 형태를 인식. 범위는 개요 컨텐츠
    시작 ~ 첫 `---` 또는 다음 `## ...` 이전. 개요 블록 없으면 ('', 0) 반환.
    """
    m_title = re.search(r"^#\s+.+$", text, re.MULTILINE)
    if not m_title:
        return ('', 0)
    body_start = m_title.end()

    # `## 개요` 헤딩이 있으면 그 이후를 개요 컨텐츠 시작으로 설정
    m_overview = re.search(r"^##\s+개요\s*$", text[body_start:], re.MULTILINE)
    if m_overview:
        body_start = body_start + m_overview.end()

    after = text[body_start:]
    # 종료 지점: 첫 `---` 또는 (개요 이후) 다음 `## ` 이전
    end_offsets = []
    for pat in (r"^---\s*$", r"^##\s+"):
        em = re.search(pat, after, re.MULTILINE)
        if em:
            end_offsets.append(em.start())
    if not end_offsets:
        return ('', 0)
    end_offset = min(end_offsets)
    block = after[:end_offset]
    start_line = text[:body_start].count("\n") + 1
    return (block, start_line)


def check_md(path: str) -> list[str]:
    if not os.path.isfile(path):
        return []
    text = open(path, encoding="utf-8").read()
    # 코드블록 내부 `# 주석`을 헤딩으로 오인하지 않도록 전처리
    scan_text = _strip_code_blocks(text)
    violations = []

    # 1. 헤딩 검사: (A) 화이트리스트(vuln-format.md 스펙) + (B) 블랙리스트 backup
    for m in MD_HEADING.finditer(scan_text):
        level = len(m.group(1))
        heading = m.group(2).strip()
        line_no = scan_text.count("\n", 0, m.start()) + 1

        # (A) 화이트리스트: 스펙 외 헤딩 차단
        if not _heading_matches_spec(level, heading):
            violations.append(
                f"{path}:{line_no} (h{level}): 스펙 외 헤딩 — "
                f"vuln-format.md '보고서 섹션 구조' 섹션 참조 → \"{heading}\""
            )
            continue  # 스펙 외는 BANNED 검사 불필요 (이미 차단)

        # (B) 블랙리스트 backup: 스펙 통과 후에도 내부 규약 용어 검사
        # 예: `{VULN_TITLE}` 템플릿은 자유 텍스트 허용이라 DISCARD가 들어올 수 있음
        # NOTE: 내부 라벨(DISCARD/OVERRIDE/CONFIRM)은 대문자 키워드 전용이라 case-sensitive로 검사.
        # 영어 일반 단어 'Override'(예: "X-HTTP-Method-Override")는 정상 후보 제목에 등장 가능.
        for pattern, label in BANNED_PATTERNS:
            hit = re.search(pattern, heading)
            if hit:
                violations.append(
                    f"{path}:{line_no} (h{level}): 금지 토큰 '{label}' → \"{heading}\""
                )

    # 2. 개요 섹션 필드명 검사
    # vuln-format.md 스펙에서 파싱한 허용 집합과 대조 (단일 진실 원천).
    # 단어 변형(예: '파이프 구성', '스캔 단계')에도 강건 — 스펙에 없는 필드는 무조건 차단.
    overview_block, overview_start_line = _extract_overview_block(scan_text)
    if overview_block and ALLOWED_OVERVIEW_FIELDS is not None:
        allowed = {f for f in ALLOWED_OVERVIEW_FIELDS}
        for fm in MD_OVERVIEW_FIELD.finditer(overview_block):
            field_name = fm.group(1).strip()
            rel_line = overview_block.count("\n", 0, fm.start()) + 1
            abs_line = overview_start_line + rel_line
            if field_name not in allowed:
                violations.append(
                    f"{path}:{abs_line} (개요 필드): 스펙 외 필드 '**{field_name}**:' — "
                    f"허용 필드는 vuln-format.md '통합 보고서 구조' 섹션 참조 "
                    f"(현재 허용: {ALLOWED_OVERVIEW_FIELDS})"
                )
                continue
            # '테스트 환경' 값 형식 가드: 도메인·호스트 목록 또는 <TARGET_HOST>만 허용.
            # 값은 모든 POC curl 호스트의 단일 진실 원천이므로 서술(한글 부가설명)을 금지한다.
            # 예외: 동적 테스트 미수행 시 '해당 없음'으로 시작하는 값.
            if field_name == "테스트 환경":
                value = fm.group(2).strip()
                if re.search(r"[가-힣]", value) and not value.startswith("해당 없음"):
                    violations.append(
                        f"{path}:{abs_line} (개요 필드): '테스트 환경' 값에 서술/한글 포함 — "
                        f"도메인·호스트 목록 또는 <TARGET_HOST>만 허용(서술 금지). "
                        f"'prod 확인' 등 부가 설명은 본문/블록쿼트로 분리하고, "
                        f"동적 테스트 미수행 시에만 '해당 없음'을 사용한다."
                    )
    return violations


def check_html(path: str) -> list[str]:
    if not os.path.isfile(path):
        return []
    text = open(path, encoding="utf-8").read()
    violations = []

    # vuln-block 내부의 <h3>는 MD의 #### 헤딩이 md_to_html.py 구조적 특이사항으로
    # 한 단계 승격된 결과이며, MD lint에서 이미 검사했으므로 HTML에서는 스킵한다.
    vuln_block_regions = [
        (m.start(), m.end())
        for m in re.finditer(
            r'<details class="vuln-block"[^>]*>.*?</details>',
            text, re.DOTALL
        )
    ]

    def _in_vuln_block(pos: int) -> bool:
        return any(start <= pos < end for start, end in vuln_block_regions)

    # 1. 헤딩 검사: 화이트리스트 + 블랙리스트 backup
    for m in HTML_HEADING.finditer(text):
        if _in_vuln_block(m.start()):
            continue
        level_str = m.group(1)
        level = int(level_str)
        heading = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        line_no = text.count("\n", 0, m.start()) + 1

        # (A) 화이트리스트
        if not _heading_matches_spec(level, heading):
            violations.append(
                f"{path}:{line_no} (h{level_str}): 스펙 외 헤딩 — "
                f"vuln-format.md '보고서 섹션 구조' 섹션 참조 → \"{heading}\""
            )
            continue

        # (B) 블랙리스트 backup
        for pattern, label in BANNED_PATTERNS:
            hit = re.search(pattern, heading, re.IGNORECASE)
            if hit:
                violations.append(
                    f"{path}:{line_no} (h{level_str}): 금지 토큰 '{label}' → \"{heading}\""
                )

    # 2. 개요 섹션 필드명 검사 (HTML: <h1> 이후 첫 <h2>/<hr> 전까지)
    # vuln-format.md 스펙 기반 화이트리스트 대조
    if ALLOWED_OVERVIEW_FIELDS is not None:
        allowed = {f for f in ALLOWED_OVERVIEW_FIELDS}
        m_h1 = re.search(r"<h1[^>]*>.*?</h1>", text, re.IGNORECASE | re.DOTALL)
        if m_h1:
            body_start = m_h1.end()
            after = text[body_start:]
            end_offsets = []
            for pat in (r"<h2[^>]*>", r"<hr\s*/?>"):
                em = re.search(pat, after, re.IGNORECASE)
                if em:
                    end_offsets.append(em.start())
            if end_offsets:
                overview_html = after[:min(end_offsets)]
                # HTML에서 <strong>필드</strong>: 또는 <b>필드</b>: 형식
                for fm in re.finditer(
                    r"<(?:strong|b)>([^<]+?)</(?:strong|b)>\s*:",
                    overview_html, re.IGNORECASE
                ):
                    field_name = fm.group(1).strip()
                    if field_name in allowed:
                        continue
                    abs_offset = body_start + fm.start()
                    line_no = text.count("\n", 0, abs_offset) + 1
                    violations.append(
                        f"{path}:{line_no} (개요 필드): 스펙 외 필드 "
                        f"'<strong>{field_name}</strong>:' — "
                        f"허용 필드는 vuln-format.md '통합 보고서 구조' 섹션 참조 "
                        f"(현재 허용: {ALLOWED_OVERVIEW_FIELDS})"
                    )
    return violations


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: lint_reader_layer.py <report.md> [<report.html>]", file=sys.stderr)
        return 1

    all_violations = []
    all_violations.extend(check_md(sys.argv[1]))
    if len(sys.argv) >= 3:
        all_violations.extend(check_html(sys.argv[2]))

    if all_violations:
        print(f"FAIL: 독자 레이어 용어 노출 {len(all_violations)}건", file=sys.stderr)
        for v in all_violations:
            print(f"  - {v}", file=sys.stderr)
        print(
            "\n검사 범위:\n"
            "  1) 헤딩(# ~ ######): _contracts.md §9 내부 규약 용어 차단 — 본문·테이블은 풀이 형태로 허용.\n"
            "  2) 개요 필드명: vuln-format.md '통합 보고서 구조' 스펙 단일 출처 기반 화이트리스트.\n"
            "     신규 필드가 필요하면 먼저 vuln-format.md 스펙을 갱신하세요.",
            file=sys.stderr,
        )
        return 5  # §13 exit code table: 5 = lint 위반

    print(f"OK: lint 통과")
    return 0


if __name__ == "__main__":
    sys.exit(main())
