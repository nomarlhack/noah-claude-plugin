#!/usr/bin/env python3
"""validate_report.py — 보고서 정량·구조 검증.

Fail 검증 (exit 1, 보고서 파일을 .invalid 백업으로 rename — 영구 삭제 아님):
  - MD/HTML POC 건수 일치, 심각도 표시 금지, 연계 분석 섹션 존재, safe 섹션 존재

Warning 검증 (exit 6, 보고서 파일 유지):
  - (a) 상세 섹션 **ID** 필드 존재 + master-list 매칭
  - (b) 상세 ID 집합 ↔ master-list id 집합 양방향 집합 차
  - (c) POC curl 호스트 일관성 (개요 '테스트 환경' 필드 ↔ POC 호스트)

Usage:
    python3 validate_report.py [건수] [보고서명] [--chain-analysis]
        [--master-list <path>] [--json-output <path>]
"""
import sys, os, re

# --master-list / --json-output <path> 추출
master_list_arg = None
json_output_arg = None
raw = list(sys.argv[1:])
cleaned = []
i = 0
while i < len(raw):
    if raw[i] == '--master-list' and i + 1 < len(raw):
        master_list_arg = raw[i + 1]
        i += 2
        continue
    if raw[i] == '--json-output' and i + 1 < len(raw):
        json_output_arg = raw[i + 1]
        i += 2
        continue
    cleaned.append(raw[i])
    i += 1

args = [a for a in cleaned if not a.startswith('--')]
flags = [a for a in cleaned if a.startswith('--')]

if len(args) < 1:
    print("Usage: python3 validate_report.py [확인됨+후보 건수] [보고서명] [--chain-analysis] [--master-list <path>]")
    sys.exit(1)

try:
    expected = int(args[0])
except ValueError:
    print(f"ERROR: 첫 번째 인자는 정수여야 합니다 (입력: {args[0]!r})", file=sys.stderr)
    sys.exit(1)
report_name = args[1] if len(args) > 1 else "noah-sast-report"
check_chain = '--chain-analysis' in flags

md_path = f"{report_name}.md"
html_path = f"{report_name}.html"

errors = []

import re as _re


def _strip_chain_section(text: str) -> str:
    """`## 연계 시나리오` 섹션을 제거한 본문 반환.
    이 섹션의 체인별 통합 POC는 후보별 POC 카운트와 별개로 취급한다."""
    return _re.sub(
        r"^## 연계 시나리오.*?(?=^## |\Z)", "", text, count=1, flags=_re.M | _re.S
    )


# 1. MD POC 건수 검증 (연계 시나리오 섹션의 체인별 POC는 제외)
if os.path.exists(md_path):
    with open(md_path, encoding="utf-8") as f:
        md_content = f.read()
    md_poc = _strip_chain_section(md_content).count("재현 방법 및 POC")
    if md_poc != expected:
        errors.append(f"MD POC {md_poc}건 != 기대 {expected}건 (누락 {expected - md_poc}건)")
else:
    errors.append(f"{md_path} 파일 없음")
    md_content = ""

# 2. HTML POC 건수 검증 (연계 시나리오 섹션 제외)
if os.path.exists(html_path):
    with open(html_path, encoding="utf-8") as f:
        html_content = f.read()
    # HTML도 헤더 텍스트 기반으로 동일 영역 제외
    html_stripped = _re.sub(
        r"<h2[^>]*>연계 시나리오</h2>.*?(?=<h2|\Z)", "", html_content, count=1, flags=_re.S
    )
    html_poc = html_stripped.count("재현 방법 및 POC")
    if html_poc != expected:
        errors.append(f"HTML POC {html_poc}건 != 기대 {expected}건 (누락 {expected - html_poc}건)")
else:
    errors.append(f"{html_path} 파일 없음")
    html_content = ""

# 3. 심각도 표시 금지 검증
if md_content:
    for keyword in ["HIGH", "MEDIUM", "LOW", "CRITICAL"]:
        lines = md_content.split("\n")
        for i, line in enumerate(lines):
            if keyword in line and not line.strip().startswith(("```", "`", "#", "|")):
                if f"**{keyword}**" in line or f": {keyword}" in line:
                    errors.append(f"심각도 표시 발견: 라인 {i+1}: {line.strip()[:80]}")

# 4. 연계 분석 섹션 검증 (--chain-analysis 플래그 시)
if check_chain:
    if md_content and "## 연계 시나리오" not in md_content:
        errors.append("연계 분석 수행됨(--chain-analysis)이나 '## 연계 시나리오' 섹션이 MD에 없음")
    if html_content and "연계 시나리오" not in html_content:
        errors.append("연계 분석 수행됨(--chain-analysis)이나 '연계 시나리오' 섹션이 HTML에 없음")

# 5. 안전 판정 항목 섹션 검증 (#25 — safe_category 4분류 자동 생성 여부)
# master-list.json에 safe 후보가 있으면 보고서에 "## 안전 판정 항목" 섹션이 존재해야 한다.
# 플레이스홀더 부재·skeleton 미동기화로 조용히 누락되는 경우를 잡는다.
master_list_path = None
if master_list_arg:
    if os.path.isfile(master_list_arg):
        master_list_path = master_list_arg
    else:
        print(f"ERROR: --master-list {master_list_arg} 파일 없음", file=sys.stderr)
        sys.exit(1)
else:
    # fallback: /tmp/phase1_results_*/master-list.json 중 mtime 최신
    import glob
    candidates = glob.glob('/tmp/phase1_results_*/master-list.json')
    if candidates:
        master_list_path = max(candidates, key=os.path.getmtime)
if master_list_path and os.path.exists(master_list_path):
    try:
        import json as _json
        with open(master_list_path, encoding='utf-8') as f:
            _ml = _json.load(f)
        _safe_count = sum(1 for c in _ml.get('candidates', []) if c.get('status') == 'safe')
        # safe 후보 0건이면 '## 안전 판정 항목' 섹션 부재 허용
        # (build_safe_section이 빈 문자열 반환하여 플레이스홀더가 빈 값으로 치환된 정상 동작)
        if _safe_count > 0:
            if md_content and "## 안전 판정 항목" not in md_content:
                errors.append(
                    f"master-list.json에 safe 후보 {_safe_count}건 있으나 '## 안전 판정 항목' 섹션이 MD에 없음 "
                    f"(skeleton에 `<!-- SAFE_SECTION_HERE -->` 플레이스홀더 누락 가능성)"
                )
            if html_content and "안전 판정 항목" not in html_content:
                errors.append(
                    f"master-list.json에 safe 후보 {_safe_count}건 있으나 '안전 판정 항목' 섹션이 HTML에 없음"
                )
    except (OSError, ValueError):
        pass  # master-list.json 없거나 읽기 실패 시 이 검증 스킵

warnings = []  # exit 6 경고 (fail 아님). 파일 유지.

# 6. ID 필드 존재/일치 + 양방향 집합 차 + POC 호스트 일관성 (경고 수준)
# master_list_path가 없으면 이 검증은 스킵.
if master_list_path and os.path.exists(master_list_path) and md_content:
    try:
        import json as _json
        with open(master_list_path, encoding='utf-8') as f:
            _ml_full = _json.load(f)
        _ml_candidates = _ml_full.get('candidates', [])
        # ID → status 맵 (상세 섹션 파싱 시 safe 판정 skip 용도)
        _ml_id_status = {
            c['id']: c.get('status', 'candidate')
            for c in _ml_candidates if c.get('id')
        }
        # confirmed/candidate 대상만 (safe는 별도 테이블 섹션, 상세 검증 대상 아님)
        _ml_reportable_ids = {
            vid for vid, status in _ml_id_status.items()
            if status in ('confirmed', 'candidate', None)
        }

        # 상세 섹션 파싱: #### N. 제목 다음의 **ID**: 값 추출
        # 스캐너별 실행 결과 + AI 자율 탐색 결과 범위 내
        _scanner_section_match = re.search(
            r'## 스캐너별 실행 결과(.*?)(?=\n## (?!스캐너별|AI 자율)|\Z)',
            md_content, re.DOTALL
        )
        _ai_section_match = re.search(
            r'## AI 자율 탐색 결과(.*?)(?=\n## (?!AI 자율)|\Z)',
            md_content, re.DOTALL
        )
        _scan_body = _scanner_section_match.group(1) if _scanner_section_match else ''
        _ai_body = _ai_section_match.group(1) if _ai_section_match else ''
        _combined_body = _scan_body + '\n' + _ai_body

        # 각 상세 섹션(#### N. 제목)별로 **ID**: 값 추출
        _section_pat = re.compile(
            r'^####\s+(\d+)\.\s+(.+?)$(.*?)(?=^####\s+\d+\.|^###\s|\Z)',
            re.MULTILINE | re.DOTALL
        )
        _detail_ids = []  # (section_num, section_title, id_value or None)
        for sm in _section_pat.finditer(_combined_body):
            sec_num = sm.group(1)
            sec_title = sm.group(2).strip()
            sec_body = sm.group(3)
            id_lines = re.findall(r'^\*\*ID\*\*:\s*(.+?)\s*$', sec_body, re.MULTILINE)
            if len(id_lines) == 0:
                _detail_ids.append((sec_num, sec_title, None))
            elif len(id_lines) > 1:
                warnings.append(
                    f"상세 섹션 #{sec_num} ({sec_title[:50]}): **ID** 필드가 {len(id_lines)}회 등장 (섹션 내 1회만 허용)"
                )
                _detail_ids.append((sec_num, sec_title, id_lines[0]))
            else:
                _detail_ids.append((sec_num, sec_title, id_lines[0]))

        # (a) ID 필드 존재 + master-list 일치
        # safe 판정 항목은 별도 "안전 판정 항목" 섹션으로 분리되므로 상세 검증 대상에서 제외
        # (양방향 집합 차의 양쪽 집합 범위를 confirmed/candidate로 대칭화)
        _detail_id_set = set()
        for sec_num, sec_title, vid in _detail_ids:
            if vid is None:
                warnings.append(f"상세 섹션 #{sec_num} ({sec_title[:50]}): **ID** 필드 누락")
                continue
            # safe 판정 항목은 상세 섹션에 있어도 skip (별도 테이블 섹션 소속)
            if _ml_id_status.get(vid) == 'safe':
                continue
            if vid not in _ml_reportable_ids:
                warnings.append(
                    f"상세 섹션 #{sec_num} ({sec_title[:50]}): ID '{vid}'가 master-list에 없음 (오타/고아)"
                )
            _detail_id_set.add(vid)

        # (b) 양방향 집합 차: master-list에만 있는 ID (상세에 누락된 후보)
        _missing_in_detail = _ml_reportable_ids - _detail_id_set
        for mid in sorted(_missing_in_detail):
            warnings.append(f"master-list ID '{mid}'가 상세 섹션에 누락됨 (보고서에서 빠짐)")

        # (c) POC curl 호스트 일관성
        # 개요 **테스트 환경** 필드에서 선언된 호스트 추출
        _env_match = re.search(
            r'\*\*테스트 환경\*\*:\s*(.+?)(?:\s*\n|$)',
            md_content
        )
        _declared_host = None
        if _env_match:
            _env_value = _env_match.group(1).strip()
            # "sandbox-developers.kakao.com" 같은 호스트명만 추출
            _host_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', _env_value)
            if _host_match:
                _declared_host = _host_match.group(1).lower()

        # POC curl 명령어의 호스트 추출
        _curl_hosts = re.findall(
            r'curl[^\n`]*["\']https?://([a-zA-Z0-9.-]+)',
            md_content
        )
        _host_outliers = {}  # {host: count}
        for h in _curl_hosts:
            h_lower = h.lower()
            # 플레이스홀더 허용
            if '<' in h_lower or 'target_host' in h_lower or 'attacker' in h_lower:
                continue
            if _declared_host and h_lower == _declared_host:
                continue
            _host_outliers[h_lower] = _host_outliers.get(h_lower, 0) + 1
        for host, count in sorted(_host_outliers.items()):
            if _declared_host:
                warnings.append(
                    f"POC 호스트 '{host}' (발견 {count}회) — 개요 '테스트 환경' 호스트 "
                    f"'{_declared_host}'와 불일치"
                )
            else:
                warnings.append(
                    f"POC 호스트 '{host}' (발견 {count}회) — 개요 '테스트 환경' 필드에 "
                    f"호스트 선언 없음. 플레이스홀더 <TARGET_HOST>로 통일 권장"
                )

        # (d) 동적 실행 항목 POC 플레이스홀더 검출 (재현성 보증)
        # phase2.md manifest의 evidence.commands가 있는 id = 실제 curl 실행됨 → POC는 실값이어야 한다.
        # 판정 기준은 상태(확인됨/후보)가 아니라 evidence 존재 — 무인증 동적후보도 포함.
        # 정적 후보(commands 부재)는 플레이스홀더 정당하므로 대상 아님(오탐 0).
        # 토큰셋은 고정 화이트리스트(템플릿 유래 + 흔한 신원/페이로드 표지)만 — `<script>`·`<!ENTITY>`·
        # `[ERROR]` 같은 정당 페이로드/로그 토큰 오탐 방지. case-sensitive.
        _poc_ph_re = re.compile(
            r'<(?:TARGET_HOST|API_PATH|SESSION_COOKIE|SESSION|COOKIE|TOKEN|PARAM|PAYLOAD|METHOD'
            r'|HOST|USER_ID|VICTIM|EMAIL|PASSWORD|ID|URL)>'
            r'|\[실제[^\]]*\]'
            r'|\[(?:METHOD|PARAM|PAYLOAD|URL|쿠키|토큰|페이로드|파라미터)\]'
        )
        _id_to_p2 = {c['id']: c.get('source_phase2_file') for c in _ml_candidates if c.get('id')}
        _dynamic_ids = set()
        _p2_cache = {}
        for _vid, _p2 in _id_to_p2.items():
            if not _p2 or not os.path.exists(_p2):
                continue
            if _p2 not in _p2_cache:
                _p2_cache[_p2] = {}
                try:
                    _p2txt = open(_p2, encoding='utf-8').read()
                    _jm = re.search(r'```json\s*(\{.*\})\s*```', _p2txt, re.DOTALL)
                    if _jm:
                        for _r in _json.loads(_jm.group(1)).get('results', []):
                            _ev = _r.get('evidence') or {}
                            if _r.get('id') and _ev.get('commands'):
                                _p2_cache[_p2][_r['id']] = True
                except (OSError, ValueError):
                    pass
            if _p2_cache[_p2].get(_vid):
                _dynamic_ids.add(_vid)

        for _sm in _section_pat.finditer(_combined_body):
            _sbody = _sm.group(3)
            _sids = re.findall(r'^\*\*ID\*\*:\s*(.+?)\s*$', _sbody, re.MULTILINE)
            if not _sids or _sids[0] not in _dynamic_ids:
                continue
            _poc = re.search(r'####\s*재현 방법 및 POC(.*?)(?=\n####|\Z)', _sbody, re.DOTALL)
            if not _poc:
                continue
            _hits = sorted(set(_poc_ph_re.findall(_poc.group(1))))
            if _hits:
                warnings.append(
                    f"POC 플레이스홀더 잔존: {_sids[0]} (동적 실행 항목 — phase2 evidence.commands 존재)에 "
                    f"{', '.join(_hits)} — 실제 실행값으로 교정 필요 (검토자 재현 불가)"
                )
    except (OSError, ValueError, _json.JSONDecodeError):
        pass  # master-list.json 읽기 실패 시 이 검증 스킵

# --json-output: 구조화 로그 덤프
if json_output_arg:
    try:
        import json as _json
        _jout = {
            'errors': errors,
            'warnings': warnings,
            'passed': len(errors) == 0,
            'has_warnings': len(warnings) > 0,
        }
        with open(json_output_arg, 'w', encoding='utf-8') as f:
            _json.dump(_jout, f, ensure_ascii=False, indent=2)
    except (OSError, TypeError) as e:
        print(f"WARNING: --json-output 저장 실패: {e}", file=sys.stderr)

# 결과 출력
if errors:
    print("FAIL:")
    for e in errors:
        print(f"  - {e}")
    # fail-closed: 구조가 깨진 보고서를 canonical 경로에서 치운다(재조립 강제).
    # 단 os.remove로 영구 삭제하지 않고 .invalid 백업으로 rename — 수작업 큐레이션본이
    # 잘못된 카운트로 단독 실행된 경우에도 소실되지 않게 한다.
    import time as _time
    _bak_suffix = f".invalid-{int(_time.time())}.bak"
    for path in [md_path, html_path]:
        if os.path.exists(path):
            _bak = path + _bak_suffix
            try:
                os.rename(path, _bak)
                print(f"  무효 처리(백업 보존): {path} → {_bak}")
            except OSError as _e:
                print(f"  무효 처리 실패({path}): {_e}", file=sys.stderr)
    sys.exit(1)
else:
    parts = [f"MD {md_poc}/{expected}, HTML {html_poc}/{expected}"]
    if check_chain:
        parts.append("chain-analysis ✓")
    if warnings:
        print(f"PASS (경고 {len(warnings)}건): {', '.join(parts)}")
        for w in warnings[:20]:
            print(f"  ⚠  {w}")
        if len(warnings) > 20:
            print(f"  … 외 {len(warnings) - 20}건")
        sys.exit(6)  # 경고 수준, 파일 유지
    print(f"PASS: {', '.join(parts)}")
    sys.exit(0)
