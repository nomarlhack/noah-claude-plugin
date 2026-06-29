#!/usr/bin/env python3
"""assemble_report.py — 스켈레톤과 서브에이전트 결과를 조립하여 MD 보고서를 생성한다.

Usage:
    python3 assemble_report.py \\
        --skeleton /tmp/skeleton.md \\
        --sections /tmp/sr_001.md /tmp/sr_002.md \\
        --output noah-sast-report.md \\
        [--chain /tmp/chain.json] \\
        [--ai /tmp/ai_section.md]

설계 원칙:
    요약 테이블은 상세 섹션에서 자동 생성한다 (단일 진실 원천).
    연계 시나리오 섹션은 chain_analysis 데이터에서 자동 생성한다.
"""
import argparse, json, os, re, sys

# auth_boundary file_path 기반 재파생 fallback (phase1_build_master_list.py와 동일 규칙).
# phase2-review 에이전트가 master-list.json 재직렬화 시 auth_boundary를 '' 로 교체해도
# 보고서 조립 시점에 file_path로 복구한다.
def _fallback_auth_boundary(file_path: str) -> str:
    f = file_path or ""
    if "loco-web-jude-dkos" in f:
        return "외부망.무인증"
    if "loco-bo-jude-admin" in f:
        return "내부망.인증"
    if "lazenca" in f:
        for kw in ("GroupAlarm", "GroupAction", "RoomChatbot", "SecureImage",
                   "GroupChat", "GroupSubscription"):
            if kw in f:
                return "내부망.인증"
        return "내부망.무인증"
    if "jude-misc-api" in f:
        return "내부망.인증"
    if "loco-api-jude" in f or "loco-bo-jude" in f or "loco-bo-common" in f:
        for kw in ("gift", "Gift", "kids", "Kids", "profile", "Profile",
                   "moim", "Moim", "Schedule", "Poll"):
            if kw in f:
                return "내부망.인증"
        return "내부망.무인증"
    return "내부망.무인증"


def normalize_vuln_headings(text):
    """**N번 ...**: 제목 형식을 #### N. 제목 헤딩으로 정규화."""
    def replace_heading(m):
        num = m.group(1)
        title = m.group(2).strip().rstrip('*').strip()
        return f'#### {num}. {title}'
    text = re.sub(
        r'^\*\*(\d+)번\s*(?:\([^)]+\))?\s*[-–]\s*[A-Za-z0-9_-]+:\s*(.+?)\*{0,2}\s*$',
        replace_heading, text, flags=re.MULTILINE)
    text = re.sub(
        r'^\*\*(\d+)번\s*[-–]\s*[A-Za-z0-9_-]+\*\*:\s*(.+)$',
        replace_heading, text, flags=re.MULTILINE)
    return text


def clean_section(text):
    """## 레벨 헤딩 제거 + 취약점 헤딩 정규화."""
    text = normalize_vuln_headings(text)
    lines = text.split('\n')
    return '\n'.join(l for l in lines if not l.startswith('## '))


CATEGORIES = {
    "no_external_path": "외부 접근 경로 없음",
    "defense_verified": "방어 계층 작동 확인",
    "not_applicable": "취약점 성립 조건 미충족",
    "false_positive": "정적 분석 오탐",
    "platform_default_defense": "최신 플랫폼 방어",
    "architectural_rationale_only": "아키텍처 근거 중복",
}


def _classify_safe(candidate):
    """safe 후보의 표시 라벨을 반환. safe_category enum이 없으면 "기타".

    safe_category는 phase2-review/phase1-review 에이전트가 명시적으로 기록해야 한다.
    누락 시 build_safe_section이 safe_bucket_unclassified로 exit 7을 유도한다.
    """
    explicit = candidate.get("safe_category")
    if explicit in CATEGORIES:
        return CATEGORIES[explicit]
    return "기타"


def validate_safe_consistency(candidates):
    """safe 후보의 safe_category와 근거 필드 정합성을 검증한다.

    Phase 1 DISCARD 경로(phase1_discarded_reason != null)는 면제.
    defense_verified는 verified_defense + rederivation_performed=true 필수.

    Returns:
        list[str]: 위반 메시지 목록 (빈 리스트 = 통과)
    """
    ENUM = {"no_external_path", "defense_verified", "not_applicable", "false_positive",
            "platform_default_defense", "architectural_rationale_only", None}
    issues = []
    all_ids = {c.get("id") for c in candidates if c.get("id")}
    # master-list에 실제 존재하는 prefix 집합으로만 참조 검증
    # (RFC-/CVE-/ISO- 등 외부 표준 번호 false positive 방지)
    allowed_prefixes = {i.split("-")[0] for i in all_ids if "-" in i}
    id_pattern = re.compile(r"[A-Z]{2,}[A-Z0-9]*-\d+")
    for c in candidates:
        if c.get("status") != "safe":
            continue
        cat = c.get("safe_category")
        # enum 검증 (None sentinel 허용)
        if cat not in ENUM:
            issues.append(f"{c.get('id')}: safe_category='{cat}'이 enum 범위 밖")
            continue
        # Phase 1 DISCARD 경로는 면제 (§12-C §9 면제 규칙)
        if c.get("phase1_discarded_reason"):
            # architectural_rationale_only는 참조 대상 ID 존재 무결성 추가 검증
            if cat == "architectural_rationale_only":
                raw_refs = set(id_pattern.findall(c.get("phase1_discarded_reason") or ""))
                # master-list prefix 집합에 속하는 참조만 검증 대상 (외부 표준 번호 무시)
                refs = {r for r in raw_refs if r.split("-")[0] in allowed_prefixes}
                refs.discard(c.get("id"))
                missing = refs - all_ids
                if refs and missing:
                    issues.append(
                        f"{c.get('id')}: architectural_rationale_only 참조 대상 부재: {sorted(missing)}"
                    )
            continue
        # defense_verified는 verified_defense + rederivation_performed 필수
        if cat == "defense_verified":
            vd = c.get("verified_defense")
            if not vd or not isinstance(vd, dict):
                issues.append(f"{c.get('id')}: defense_verified인데 verified_defense 객체 없음")
            if not c.get("rederivation_performed"):
                issues.append(f"{c.get('id')}: defense_verified인데 rederivation_performed != true")
    return issues


def validate_skeleton_overview(skeleton_text):
    """스켈레톤 개요 구조 검증.

    메타 필드(**대상**, **스캔 일시** 등)가 h1 직후에 있고 ## 개요가 그 뒤에 별도로
    위치하는 "분리 작성" 패턴을 감지한다. 이 구조에서 md_to_html.py의 개요 카드가
    메타 필드를 인식하지 못해 대상/스캔일시/스택이 렌더링에서 누락된다.

    정상 구조:
        # h1
        ## 개요          ← ## 개요가 h1 바로 다음
        **대상**: ...    ← 메타 필드가 ## 개요 안

    비정상 구조 (차단):
        # h1
        **대상**: ...    ← 메타 필드가 ## 개요 밖 (h1 직후 평문)
        ---
        ## 개요          ← ## 개요가 뒤늦게 등장

    Returns:
        list[str]: 오류 메시지 목록 (빈 리스트 = 통과)
    """
    issues = []

    # h1 직후 ~ 첫 ## 헤딩 이전 구간에 메타 필드가 있는지 탐지
    m_h1 = re.search(r'(?m)^#\s+.+$', skeleton_text)
    if not m_h1:
        return issues  # h1 없으면 스킵

    after_h1 = skeleton_text[m_h1.end():]

    # 첫 ## 헤딩 위치 파악
    m_h2 = re.search(r'(?m)^##\s+', after_h1)
    h2_offset = m_h2.start() if m_h2 else len(after_h1)
    before_first_h2 = after_h1[:h2_offset]

    # h1 ~ 첫 ## 사이에 **키**: 값 형태 메타 필드가 있으면 분리 작성 패턴
    meta_in_preamble = re.search(r'(?m)^\*\*[^\n*]+\*\*\s*:', before_first_h2)
    if meta_in_preamble:
        # 첫 ## 헤딩이 ## 개요가 아닌 경우도 포함
        first_h2_text = m_h2.group(0).strip() if m_h2 else ''
        is_overview = bool(re.match(r'^##\s*개요\s*$', first_h2_text))
        if not is_overview:
            issues.append(
                "ERROR: skeleton 개요 구조 오류 — h1 직후에 메타 필드(**대상**, **스캔 일시** 등)가 있고 "
                "'## 개요'가 그 뒤에 별도로 위치합니다. "
                "이 구조에서 md_to_html.py 개요 카드가 메타 필드를 인식하지 못합니다.\n"
                "  수정: # h1 바로 다음에 '## 개요'를 쓰고, 모든 메타 필드를 그 안에 넣으세요.\n"
                "  예) # 통합 취약점 스캔 보고서\n"
                "      ## 개요\n"
                "      **대상**: ..."
            )
    return issues


def build_summary_table(master_list_path):
    """master-list.json에서 총괄 요약 테이블을 직접 생성한다.

    스켈레톤 작성자가 테이블/볼드 어느 형식으로 작성해도 이 함수가 덮어쓰므로
    md_to_html.py 파싱 실패(수치 0 표시)가 발생하지 않는다.

    Returns:
        str: MD 테이블 텍스트. master-list 없으면 빈 문자열.
    """
    if not master_list_path:
        return ''
    try:
        with open(master_list_path, encoding='utf-8') as f:
            ml = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return ''

    candidates = ml.get('candidates', [])
    confirmed = sum(1 for c in candidates if c.get('status') == 'confirmed')
    candidate = sum(1 for c in candidates if c.get('status') == 'candidate')
    safe = sum(1 for c in candidates if c.get('status') == 'safe')

    return (
        f'| 확인됨 | {confirmed}건 |\n'
        f'| 후보 (추가 검증 필요) | {candidate}건 |\n'
        f'| 안전 (정적·동적 검증 완료) | {safe}건 |'
    )


def inject_summary_table(report_text, master_list_path):
    """보고서 MD에서 총괄 요약 수치 블록을 master-list 기반으로 교체한다.

    스켈레톤의 개요 섹션에 있는 확인됨/후보/안전 수치를
    볼드 형식(**확인됨**: N건)이든 테이블 형식이든 관계없이
    정확한 값으로 덮어쓴다.
    """
    if not master_list_path:
        return report_text
    try:
        with open(master_list_path, encoding='utf-8') as f:
            ml = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return report_text

    candidates = ml.get('candidates', [])
    confirmed = sum(1 for c in candidates if c.get('status') == 'confirmed')
    candidate = sum(1 for c in candidates if c.get('status') == 'candidate')
    safe = sum(1 for c in candidates if c.get('status') == 'safe')

    # 볼드 형식 교체: **확인됨**: N건 / **후보...**: N건 / **안전...**: N건
    report_text = re.sub(
        r'(\*\*(?:확인됨|확인된 취약점)[^*]*\*\*\s*:\s*)\d+(?:건)?',
        lambda m: m.group(1) + f'{confirmed}건',
        report_text
    )
    report_text = re.sub(
        r'(\*\*후보[^*]*\*\*\s*:\s*)\d+(?:건)?',
        lambda m: m.group(1) + f'{candidate}건',
        report_text
    )
    report_text = re.sub(
        r'(\*\*안전[^*]*\*\*\s*:\s*)\d+(?:건)?',
        lambda m: m.group(1) + f'{safe}건',
        report_text
    )
    # 파이프 테이블 형식 교체: | 확인됨 | N건 |
    report_text = re.sub(
        r'(\|\s*(?:확인됨|확인된 취약점)[^|]*\|\s*)\d+(?:건)?(\s*\|)',
        lambda m: m.group(1) + f'{confirmed}건' + m.group(2),
        report_text
    )
    report_text = re.sub(
        r'(\|\s*후보[^|]*\|\s*)\d+(?:건)?(\s*\|)',
        lambda m: m.group(1) + f'{candidate}건' + m.group(2),
        report_text
    )
    report_text = re.sub(
        r'(\|\s*안전[^|]*\|\s*)\d+(?:건)?(\s*\|)',
        lambda m: m.group(1) + f'{safe}건' + m.group(2),
        report_text
    )
    return report_text


def build_safe_section(master_list_path):
    """master-list.json을 읽어 ## 안전 판정 항목 섹션을 4분류로 자동 생성.

    safe 후보가 없으면 빈 문자열 반환.
    "기타" 버킷은 보고서에서 제외하고 stderr로 경고 + exit 7 유도.

    Returns:
        (str, int, list[str]): (MD 텍스트, 기타 버킷 건수, 정합성 위반 목록)
    """
    if not master_list_path:
        return ('', 0, [])
    try:
        with open(master_list_path, encoding='utf-8') as f:
            ml = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return ('', 0, [])

    candidates = ml.get("candidates", [])
    # 정합성 검증
    consistency_issues = validate_safe_consistency(candidates)

    buckets = {
        "외부 접근 경로 없음": [],
        "방어 계층 작동 확인": [],
        "취약점 성립 조건 미충족": [],
        "정적 분석 오탐": [],
        "최신 플랫폼 방어": [],
        "아키텍처 근거 중복": [],
        "기타": [],
    }
    for c in candidates:
        if c.get("status") != "safe":
            continue
        cat = _classify_safe(c)
        buckets[cat].append(c)

    unclassified_count = len(buckets["기타"])
    if unclassified_count:
        unclassified_ids = [c.get("id", "") for c in buckets["기타"]]
        print(
            f"WARN: safe_bucket_unclassified {unclassified_count}건: {unclassified_ids}\n"
            f"      phase2-review/phase1-review 에이전트가 safe_category를 명시해야 한다 "
            f"(_contracts.md §3 enum 참조).",
            file=sys.stderr,
        )
    # "기타"는 보고서에서 제외 (독자 레이어 유출 금지)
    buckets.pop("기타")

    total = sum(len(v) for v in buckets.values())
    if total == 0:
        return ('', unclassified_count, consistency_issues)

    # 카테고리별 테이블 컬럼 지정
    COLUMNS = {
        "외부 접근 경로 없음": "근거",
        "방어 계층 작동 확인": "방어 메커니즘",
        "취약점 성립 조건 미충족": "부재하는 요건",
        "정적 분석 오탐": "오탐 이유",
        "최신 플랫폼 방어": "동등 방어 근거",
        "아키텍처 근거 중복": "경로 증거 대상 후보",
    }

    lines = ['## 안전 판정 항목', '']
    for cat, items in buckets.items():
        if not items:
            continue
        col_header = COLUMNS[cat]
        lines.append(f'### {cat} ({len(items)}건)')
        lines.append('')
        lines.append(f'| ID | 제목 | {col_header} |')
        lines.append(f'|----|------|{"-" * max(len(col_header), 4)}|')
        for c in items:
            cid = c.get("id", "")
            title = (c.get("title") or "").replace("|", "\\|")
            # 근거: verified_defense.reason (방어 작동) 또는 phase1_discarded_reason (그 외)
            if cat == "방어 계층 작동 확인":
                vd = c.get("verified_defense") or {}
                note = c.get("evidence_summary") or vd.get("reason") or f"{vd.get('file','')}:{vd.get('lines','')}"
            else:
                note = c.get("phase1_discarded_reason") or c.get("evidence_summary") or ""
            note = note.replace("|", "\\|").replace("\n", " ")
            # 60자 초과 시 축약 방지: 원문 유지 (독자 판단)
            lines.append(f'| {cid} | {title} | {note} |')
        lines.append('')
    return ('\n'.join(lines).rstrip() + '\n', unclassified_count, consistency_issues)


def build_defense_imbalance_warnings(master_list_path):
    """동일 file:line을 지적하는 후보 그룹에 safe와 (candidate|confirmed)가 혼재하면 경고.

    같은 코드 경로를 다른 관점에서 본 여러 스캐너의 판정이 엇갈리면
    "safe 가정이 무효화될 수 있음"을 보고서에 시각적으로 드러낸다.

    Returns:
        str: 경고 블록 MD (있으면). 경고 없으면 빈 문자열.
    """
    if not master_list_path:
        return ''
    try:
        with open(master_list_path, encoding='utf-8') as f:
            ml = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return ''

    # (file, line) 기준 그룹핑
    groups = {}
    for c in ml.get("candidates", []):
        f = c.get("file")
        ln = c.get("line")
        if not f or not ln:
            continue
        key = (str(f), int(ln) if str(ln).isdigit() else str(ln))
        groups.setdefault(key, []).append(c)

    imbalanced = []
    for (f, ln), items in groups.items():
        if len(items) < 2:
            continue
        statuses = {c.get("status") for c in items}
        # safe와 confirmed/candidate가 혼재하면 심층 방어 불균형
        if "safe" in statuses and (statuses & {"confirmed", "candidate"}):
            safe_ids = [c.get("id") for c in items if c.get("status") == "safe"]
            other_items = [c for c in items if c.get("status") != "safe"]
            imbalanced.append({
                "location": f"{f}:{ln}",
                "safe_ids": safe_ids,
                "other_items": other_items,
            })

    if not imbalanced:
        return ''

    lines = [
        '### 심층 방어 불균형 경고',
        '',
        '동일 코드 경로를 다른 관점에서 본 스캐너 판정이 엇갈립니다. '
        '한 관점에서 안전 판정됐더라도 다른 관점의 취약점 수정 과정에서 '
        '기존 안전 가정이 무효화될 수 있으므로 회귀 테스트가 필요합니다.',
        '',
    ]
    for entry in imbalanced:
        lines.append(f'- **{entry["location"]}**')
        lines.append(f'  - 안전 판정: {", ".join(entry["safe_ids"])}')
        for oi in entry["other_items"]:
            st = oi.get("status", "?")
            lines.append(f'  - {st}: {oi.get("id")} ({(oi.get("title") or "")[:60]})')
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n\n'


def build_chain_section(ca):
    """chain_analysis 데이터에서 ## 연계 시나리오 MD 섹션을 생성한다.

    Returns:
        str: 생성된 MD 텍스트. 연계 분석 미수행이면 빈 문자열.
    """
    if ca is None:
        return ''

    if isinstance(ca, str):
        ca = json.loads(ca)

    lines = ['## 연계 시나리오', '']

    # 테이블 셀 값에 포함된 | 는 \| 로 이스케이프하고 개행은 공백으로 치환한다
    # (요약/안전 테이블과 동일 규칙 — 미적용 시 셀이 분할되어 표가 깨진다)
    def _cell(s):
        return str(s).replace("|", "\\|").replace("\n", " ")

    chains = ca.get('chains', [])
    independent = ca.get('independent', [])

    if chains:
        for i, chain in enumerate(chains, 1):
            lines.append(f'### 체인 #{i}: {chain["title"]}')
            lines.append('')
            lines.append(f'**공격자 프로필**: {chain["attacker"]}')
            lines.append(f'**최종 영향**: {chain["impact"]}')
            lines.append('')
            lines.append('| Step | 취약점 | 설명 |')
            lines.append('|------|--------|------|')
            for j, step in enumerate(chain['steps'], 1):
                lines.append(f'| {j} | {_cell(step["vuln"])} | {_cell(step["desc"])} |')
            lines.append('')
            if chain.get('poc'):
                lines.append(chain['poc'])
                lines.append('')

        if independent:
            lines.append('### 독립 후보')
            lines.append('')

    if independent:
        lines.append('| 후보 | 체인 미구성 사유 |')
        lines.append('|------|----------------|')
        for item in independent:
            lines.append(f'| {_cell(item["id"])} | {_cell(item["reason"])} |')
        lines.append('')

    return '\n'.join(lines)


def build_table_from_details(report_text, master_list_ids=None, id_to_remark=None, id_to_auth_boundary=None):
    """상세 섹션을 파싱하여 취약점 요약 테이블을 자동 생성한다.

    master_list_ids: master-list.json의 candidates[].id 집합 (set).
    id_to_remark: id -> 비고 문자열 맵 (선택).
    id_to_auth_boundary: id -> 인증경계 문자열 맵 (선택). 제공되면 '상태' 우측에
    '인증경계' 컬럼을 추가한다 (외부망.무인증/외부망.인증/내부망.무인증/내부망.인증)."""
    lines = report_text.split('\n')

    in_scanner_section = False
    current_scanner = ''
    vulns = []
    current_vuln_title = None
    current_id = ''
    current_type = ''
    current_status = ''

    def _flush():
        if current_vuln_title:
            vulns.append((current_vuln_title, current_id, current_type, current_scanner, current_status))

    for line in lines:
        if line.startswith('## 스캐너별 실행 결과') or line.startswith('## AI 자율 탐색 결과') or line.startswith('## 동적 테스트 확인 취약점'):
            in_scanner_section = True
            continue
        if line.startswith('## ') and in_scanner_section:
            _flush()
            current_vuln_title = None
            current_id = ''
            current_type = ''
            current_status = ''
            in_scanner_section = False
            continue

        if not in_scanner_section:
            continue

        m_scanner = re.match(r'^###\s+(.+?)\s*$', line)
        if m_scanner and not re.match(r'^###\s+\d+\.', line):
            _flush()
            current_vuln_title = None
            current_id = ''
            current_type = ''
            current_status = ''
            scanner_name = m_scanner.group(1).strip()
            parts = [p.strip() for p in scanner_name.split('/')]
            parts = [re.sub(r'\s+', '-', p.lower()) for p in parts]
            # '### <name> Scanner'와 '### <name>-scanner Scanner' 모두 '<name>-scanner'로 정규화
            # ('Scanner' 단어가 공백→대시 변환으로 '-scanner' 접미사가 되므로, 중복 접미사를 1개로 축약)
            parts = [re.sub(r'(?:-scanner){2,}$', '-scanner', p) for p in parts]
            current_scanner = ' / '.join(parts)
            continue

        m_vuln = re.match(r'^#{2,4}\s+(\d+)\.\s+(.+)$', line)
        if m_vuln:
            _flush()
            current_vuln_title = m_vuln.group(2).strip()
            current_id = ''
            current_type = ''
            current_status = ''
            continue

        # **ID**: <master-list id> — 섹션 범위 내 첫 매치만 수용
        m_id = re.match(r'^\*\*ID\*\*:\s*(.+?)\s*$', line)
        if m_id and current_vuln_title and not current_id:
            raw_id = m_id.group(1).strip()
            # master_list_ids 제공 시 유효성 검증 후 폴백
            if master_list_ids is not None:
                current_id = raw_id if raw_id in master_list_ids else '—'
            else:
                current_id = raw_id
            continue

        # **유형**: ... 또는 **유형:** ...
        m_type = re.match(r'^\*\*유형:?\*\*\s*:?\s*(.+)$', line)
        if m_type and current_vuln_title:
            current_type = m_type.group(1).strip()
            continue

        # **상태**: ... 또는 **상태:** ...
        m_status = re.match(r'^\*\*상태:?\*\*\s*:?\s*(.+)$', line)
        if m_status and current_vuln_title:
            raw = m_status.group(1).strip()
            if '확인됨' in raw:
                current_status = '확인됨'
            else:
                current_status = '후보'
            continue

    _flush()

    if not vulns:
        return report_text

    # 헤딩 재번호
    heading_pat = re.compile(r'^(#{2,4})\s+\d+\.\s+(.+)$', re.MULTILINE)
    matches = list(heading_pat.finditer(report_text))
    result = report_text
    for new_num, m in enumerate(reversed(matches), 1):
        actual_num = len(matches) - new_num + 1
        hashes = m.group(1)
        title = m.group(2)
        result = result[:m.start()] + f'{hashes} {actual_num}. {title}' + result[m.end():]

    # 요약 테이블 생성 (ID 칼럼 추가, id_to_auth_boundary 제공 시 인증경계 컬럼 추가)
    # 스캐너 컬럼 표시용: -scanner 접미사 제거 (xss-scanner / sqli-scanner → xss / sqli)
    def _scanner_disp(sc):
        return ' / '.join(re.sub(r'-scanner$', '', p.strip()) for p in str(sc).split('/'))

    _has_ab = id_to_auth_boundary is not None
    _has_remark = id_to_remark is not None

    def _escape_cell(s):
        return str(s).replace('|', '\\|').replace('\n', ' ')

    if _has_ab:
        table_lines = [
            '| # | ID | 제목 | 상태 | 인증경계 |',
            '|---|-----|------|------|:--------:|',
        ]
        for idx, (title, vid, vtype, scanner, status) in enumerate(vulns, 1):
            vid_cell = vid if vid else '—'
            ab = id_to_auth_boundary.get(vid, '') if vid else ''
            table_lines.append(f'| {idx} | {vid_cell} | {_escape_cell(title)} | {status} | {_escape_cell(ab)} |')
    elif _has_remark:
        table_lines = [
            '| 순번 | ID | 취약점 제목 | 스캐너 | 상태 | 비고 |',
            '|---|-----|------------|--------|------|------|',
        ]
        for idx, (title, vid, vtype, scanner, status) in enumerate(vulns, 1):
            vid_cell = vid if vid else '—'
            remark = id_to_remark.get(vid, '—') if vid else '—'
            table_lines.append(f'| {idx} | {vid_cell} | {_escape_cell(title)} | {_scanner_disp(scanner)} | {status} | {_escape_cell(remark)} |')
    else:
        table_lines = [
            '| 순번 | ID | 취약점 제목 | 스캐너 | 상태 |',
            '|---|-----|------------|--------|------|',
        ]
        for idx, (title, vid, vtype, scanner, status) in enumerate(vulns, 1):
            vid_cell = vid if vid else '—'
            table_lines.append(f'| {idx} | {vid_cell} | {_escape_cell(title)} | {_scanner_disp(scanner)} | {status} |')
    new_table = '\n'.join(table_lines)

    # 헤딩 직후 placeholder 테이블을 자동 생성 테이블로 치환한다.
    # 헤딩과 테이블 사이에 안내용 HTML 주석(<!-- ... -->)이 끼어 있어도 매칭되도록 허용한다.
    tbl_section = re.search(
        r'(## 취약점 요약 테이블[ \t]*\n'
        r'(?:[ \t]*\n)*'                              # 빈 줄
        r'(?:<!--[\s\S]*?-->[ \t]*\n(?:[ \t]*\n)*)?'  # 선택적 HTML 주석 + 빈 줄
        r'(?:>[ \t]*[^\n]*\n(?:[ \t]*\n)*)*'          # 선택적 blockquote 안내문 + 빈 줄
        r')'
        r'(\|[^\n]+\n'
        r'\|[^\n]+\n'
        r'(?:\|[^\n]+\n)*)',
        result
    )
    if tbl_section:
        result = result[:tbl_section.start(2)] + new_table + '\n' + result[tbl_section.end(2):]
    elif vulns:
        # 스켈레톤에 '## 취약점 요약 테이블' 헤딩이 없거나 placeholder 테이블이 없는 경우 —
        # '## 스캐너별 실행 결과' 또는 '## AI 자율 탐색 결과' 직전에 섹션을 자동 삽입한다.
        insert_heading = re.search(
            r'\n(## (?:스캐너별 실행 결과|AI 자율 탐색 결과))',
            result
        )
        if insert_heading:
            insert_pos = insert_heading.start(0)
            result = (
                result[:insert_pos]
                + '\n\n## 취약점 요약 테이블\n\n'
                + new_table
                + '\n'
                + result[insert_pos:]
            )
        else:
            result += '\n\n## 취약점 요약 테이블\n\n' + new_table + '\n'

    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='스켈레톤과 서브에이전트 결과를 조립하여 MD 보고서를 생성한다.')
    parser.add_argument('--skeleton', required=True, help='스켈레톤 MD 파일 경로')
    parser.add_argument('--sections', nargs='+', required=True, help='서브에이전트 결과 MD 파일 경로 (1개 이상)')
    parser.add_argument('--output', required=True, help='출력 보고서 파일 경로 (예: noah-sast-report.md)')
    parser.add_argument('--chain', default=None, help='연계 분석 JSON 파일 경로 (없으면 생략)')
    parser.add_argument('--ai', default=None, help='AI 자율 탐색 결과 MD 파일 경로 (없으면 생략)')
    parser.add_argument('--master-list', default=None, help='master-list.json 경로 (4분류 safe 섹션 자동 생성용)')
    args = parser.parse_args()

    # 입력 파일 읽기
    try:
        skeleton = open(args.skeleton, encoding='utf-8').read()
    except FileNotFoundError:
        print(f"ERROR: 스켈레톤 파일 없음: {args.skeleton}", file=sys.stderr)
        sys.exit(1)

    subagent_results = []
    for sp in args.sections:
        try:
            subagent_results.append(open(sp, encoding='utf-8').read())
        except FileNotFoundError:
            print(f"WARNING: 섹션 파일 없음, 건너뜀: {sp}", file=sys.stderr)

    chain_analysis = None
    if args.chain:
        try:
            with open(args.chain, encoding='utf-8') as f:
                chain_analysis = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"WARNING: 연계 분석 파일 읽기 실패: {e}", file=sys.stderr)

    ai_discovery_results = ""
    if args.ai:
        try:
            ai_discovery_results = open(args.ai, encoding='utf-8').read()
        except FileNotFoundError:
            print(f"WARNING: AI 자율 탐색 파일 없음: {args.ai}", file=sys.stderr)

    # skeleton 개요 구조 검증 — 메타 필드 위치가 ## 개요 밖에 있으면 차단
    _ov_issues = validate_skeleton_overview(skeleton)
    if _ov_issues:
        print('\n'.join(_ov_issues), file=sys.stderr)
        sys.exit(8)

    # 섹션 내 중복 ID 감지 및 경고 (render_vuln_section.py를 거치지 않은 MD fallback 경우 대비)
    _combined_sections = '\n'.join(subagent_results)
    _all_ids_in_sections = re.findall(r'\*\*ID\*\*:\s*([A-Z]+-[\w]+)', _combined_sections)
    from collections import Counter as _Counter
    _dup_ids = {k: v for k, v in _Counter(_all_ids_in_sections).items() if v > 1}
    if _dup_ids:
        print(f"WARNING: 섹션 내 중복 ID 감지 — {_dup_ids}. 보고서에 중복 항목이 포함됩니다. "
              f"원인: 여러 배치 JSON 파일이 동일 ID를 포함함. render_vuln_section.py 실행 시 "
              f"자동 제거됩니다. 직접 MD를 전달하는 경우 소스 JSON에서 중복을 제거하세요.",
              file=sys.stderr)

    # 조립
    sections_text = '\n\n---\n\n'.join(clean_section(s) for s in subagent_results)
    full_report = skeleton.replace('<!-- SCANNER_SECTIONS_HERE -->', sections_text)

    chain_md = build_chain_section(chain_analysis)
    # 동일 file:line safe/candidate 혼재 경고를 연계 시나리오 앞에 prepend (있으면)
    imbalance_md = build_defense_imbalance_warnings(args.master_list)
    if imbalance_md:
        if chain_md:
            chain_md = imbalance_md + chain_md
        else:
            # chain_analysis 없어도 경고만 삽입되도록 "## 연계 시나리오" 헤더 추가
            chain_md = '## 연계 시나리오\n\n' + imbalance_md + '연계 분석 수행되지 않음.\n'
    full_report = full_report.replace('<!-- CHAIN_SECTION_HERE -->', chain_md)

    if ai_discovery_results.strip():
        ai_section = clean_section(ai_discovery_results)
        full_report = full_report.replace('<!-- AI_DISCOVERY_SECTION_HERE -->', ai_section)
    else:
        full_report = re.sub(
            r'\n## AI 자율 탐색 결과\s*\n+<!-- AI_DISCOVERY_SECTION_HERE -->',
            '',
            full_report
        )

    # master-list.json이 제공되면 ID 집합을 로드하여 상세 섹션의 **ID** 값을
    # 교차검증한다. 미제공 시 build_table_from_details는 ID 값을 그대로 수용.
    master_list_ids = None
    id_to_remark = None
    id_to_auth_boundary = None
    if args.master_list and os.path.isfile(args.master_list):
        try:
            with open(args.master_list, encoding='utf-8') as f:
                _ml_data = json.load(f)
            master_list_ids = {
                c.get('id') for c in _ml_data.get('candidates', [])
                if c.get('id')
            }
            # id -> 비고 맵
            id_to_remark = {}
            # id -> 인증경계 맵
            id_to_auth_boundary = {}
            _VALID_AB = {'외부망.무인증', '외부망.인증', '내부망.무인증', '내부망.인증'}
            for c in _ml_data.get('candidates', []):
                cid = c.get('id')
                if not cid:
                    continue
                st = c.get('status')
                tag = c.get('tag') or ''
                if st == 'confirmed':
                    id_to_remark[cid] = '동적 테스트 완료'
                elif st == 'candidate':
                    id_to_remark[cid] = tag if tag else '동적 분석 생략'
                else:
                    id_to_remark[cid] = '—'
                # auth_boundary 필드가 유효한 값이면 인증경계 맵에 추가.
                # 유효하지 않으면 file_path 기반 재파생으로 복구
                # (phase2-review 에이전트가 JSON 재직렬화 시 훼손했을 때의 방어선).
                ab = c.get('auth_boundary', '')
                if ab in _VALID_AB:
                    id_to_auth_boundary[cid] = ab
                elif c.get('file'):
                    id_to_auth_boundary[cid] = _fallback_auth_boundary(c.get('file', ''))
            # 인증경계 값이 하나도 없으면 None으로 폴백 (이전 보고서 호환)
            if not id_to_auth_boundary:
                id_to_auth_boundary = None
        except (json.JSONDecodeError, IOError) as e:
            print(f"WARNING: master-list.json 로드 실패, ID 검증 스킵: {e}", file=sys.stderr)
            master_list_ids = None
            id_to_remark = None
            id_to_auth_boundary = None

    full_report = build_table_from_details(full_report, master_list_ids, id_to_remark, id_to_auth_boundary)

    # 총괄 요약 수치를 master-list.json 기반으로 교체
    # (스켈레톤 작성 형식(볼드/테이블)에 무관하게 정확한 값을 보장)
    full_report = inject_summary_table(full_report, args.master_list)

    # skeleton과 output이 같은 경로이면 비멱등 조립 위험 차단
    if os.path.abspath(args.skeleton) == os.path.abspath(args.output):
        print(
            f"ERROR: skeleton과 output 경로가 동일함: {args.skeleton}\n"
            f"       동일 파일 재사용은 비멱등 조립을 유발한다.",
            file=sys.stderr,
        )
        sys.exit(1)

    # 안전 판정 4분류 섹션 자동 생성 (vuln-format.md "safe 판정 4분류" 규약)
    safe_md, unclassified_count, consistency_issues = build_safe_section(args.master_list)

    # 정합성 위반 시 exit 1
    if consistency_issues:
        print("ERROR: validate_safe_consistency 실패:", file=sys.stderr)
        for msg in consistency_issues:
            print(f"  - {msg}", file=sys.stderr)
        sys.exit(1)

    # safe 섹션이 필요한데 skeleton에 플레이스홀더 없으면 exit 6
    if safe_md and '<!-- SAFE_SECTION_HERE -->' not in full_report:
        print(
            "ERROR: missing_placeholder — skeleton에 `<!-- SAFE_SECTION_HERE -->` 플레이스홀더가 없음.\n"
            "       vuln-format.md 구조에 따라 skeleton을 재작성해야 한다.",
            file=sys.stderr,
        )
        sys.exit(6)

    if '<!-- SAFE_SECTION_HERE -->' in full_report:
        full_report = full_report.replace('<!-- SAFE_SECTION_HERE -->', safe_md or '')

    # 잔존 플레이스홀더 감지 — 치환 실패는 조용한 섹션 누락을 유발
    _PLACEHOLDERS = [
        '<!-- SCANNER_SECTIONS_HERE -->',
        '<!-- CHAIN_SECTION_HERE -->',
        '<!-- AI_DISCOVERY_SECTION_HERE -->',
        '<!-- SAFE_SECTION_HERE -->',
    ]
    _remaining = [ph for ph in _PLACEHOLDERS if ph in full_report]
    if _remaining:
        print(
            f"ERROR: 조립 후 플레이스홀더 {len(_remaining)}개가 치환되지 않고 남아있음:\n"
            + '\n'.join(f"  {ph}" for ph in _remaining)
            + "\n  보고서 섹션이 누락된 상태입니다. 스켈레톤 구조를 확인하세요.",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(full_report)

    # "기타" 버킷: 독자 레이어 노출 방지, stderr 경고 후 exit 7
    if unclassified_count:
        print(
            f"ERROR: safe_bucket_unclassified — {unclassified_count}건이 4분류 중 어느 것에도 해당하지 않음.",
            file=sys.stderr,
        )
        sys.exit(7)

    poc = full_report.count('재현 방법 및 POC')
    has_chain = '## 연계 시나리오' in full_report
    print(f"조립 완료: {os.path.getsize(args.output)} bytes, POC {poc}건, 공격시나리오={'✓' if has_chain else '✗'}")
