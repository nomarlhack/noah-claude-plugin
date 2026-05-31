import html as html_mod, re, sys, os

_base = os.getcwd()
_skill_dir = os.path.dirname(os.path.abspath(__file__))
_md_path = os.path.join(_base, 'noah-sast-report.md')
_html_path = os.path.join(_base, 'noah-sast-report.html')

with open(_md_path, encoding='utf-8') as f:
    _md_text = f.read()

# --- 리뷰 섹션 자동 제거 (scan-report-review 산출물이 잔류한 경우) ---
_md_text = re.sub(r'\n## (?:보고서 )?(?:리뷰|검증) 결과.*?(?=\n## |\Z)', '', _md_text, flags=re.DOTALL)

# --- 변환 전 요약 테이블·총괄 요약 자동 동기화 ---
# assemble_report.py 의 build_table_from_details 를 임포트하여
# 상세 섹션 → 요약 테이블을 항상 재생성한��.
sys.path.insert(0, _skill_dir)
from assemble_report import build_table_from_details
# 기존 요약 테이블에 비고 컬럼이 있으면 ID→비고 맵을 보존하여 재생성 시 유지한다.
# (build_table_from_details는 상세 섹션에서 재생성하므로 비고를 자체 복원하지 못함)
_existing_remark = {}
_tbl0 = re.search(r'## 취약점 요약 테이블\s*\n\s*\n((?:\|.*\n)+)', _md_text)
if _tbl0:
    _hdr = _tbl0.group(1).splitlines()[0]
    if '비고' in _hdr:
        for _row in _tbl0.group(1).splitlines():
            _cells = [c.strip() for c in _row.split('|')]
            # | # | ID | 제목 | 스캐너 | 상태 | 비고 | → cells[1]=#, cells[2]=ID, cells[6]=비고
            if len(_cells) >= 8 and re.match(r'^\d+$', _cells[1]):
                _existing_remark[_cells[2]] = _cells[6]
_md_text = build_table_from_details(_md_text, None, _existing_remark or None)

# 총괄 요약의 확인됨/후보 건수도 요약 테이블에서 재집계
def _sync_dashboard(md):
    tbl = re.search(r'## 취약점 요약 테이블\s*\n\s*\n((?:\|.*\n)+)', md)
    if not tbl:
        return md
    rows = tbl.group(1)
    confirmed = len(re.findall(r'\|\s*확인됨\s*\|', rows))
    candidate = len(re.findall(r'\|\s*후보\s*\|', rows))
    # 총괄 요약 섹션만 추출하여 그 범위 안에서만 치환
    dashboard_match = re.search(r'(## 총괄 요약\s*\n\s*\n(?:\|.*\n)+)', md)
    if not dashboard_match:
        return md
    old_block = dashboard_match.group(1)
    new_block = re.sub(r'(\|\s*(?:확인된 취약점|확인됨)\s*\|\s*)\d+(?:건)?', rf'\g<1>{confirmed}건', old_block)
    new_block = re.sub(r'(\|\s*후보[^|]*\|\s*)\d+(?:건)?', rf'\g<1>{candidate}건', new_block)
    return md.replace(old_block, new_block, 1)

_md_text = _sync_dashboard(_md_text)

# 동기화된 MD 를 디스크에도 반영 (단일 진실 원천)
with open(_md_path, 'w', encoding='utf-8') as f:
    f.write(_md_text)

lines = [l.rstrip('\n') for l in _md_text.splitlines()]

# 대시보드 수치를 MD에서 동적으로 집계 (suffix 유무 모두 허용, 첫 셀에 괄호 수식어 허용)
def _parse_dashboard(md):
    confirmed = candidate = safe = na = 0
    # 첫 셀이 "확인된 취약점" 또는 "확인됨"으로 시작하면 매칭 (괄호 수식어 허용)
    m = re.search(r'\|\s*(?:확인된 취약점|확인됨)[^|]*\|\s*(\d+)(?:건)?', md)
    if m: confirmed = int(m.group(1))
    m = re.search(r'\|\s*후보[^|]*\|\s*(\d+)(?:건)?', md)
    if m: candidate = int(m.group(1))
    # "스캔 완료 (이상 없음)", "이상 없음 스캐너", "이상 없음" 등 괄호/후행 단어 모두 허용
    m = re.search(r'\|\s*(?:스캔 완료|이상 없음)[^|]*\|\s*(\d+)(?:개)?', md)
    if m: safe = int(m.group(1))
    # "해당 없음 (미적용)", "미적용 스캐너", "미적용" 등 허용
    m = re.search(r'\|\s*(?:해당 없음|미적용)[^|]*\|\s*(\d+)(?:개)?', md)
    if m: na = int(m.group(1))
    return confirmed, candidate, safe, na

_confirmed, _candidate, _safe, _na = _parse_dashboard(_md_text)

def esc(text):
    return html_mod.escape(text)

def inline(text):
    t = esc(text)
    t = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', t)
    t = re.sub(r'`([^`]+)`', r'<code>\1</code>', t)
    t = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', t)
    return t

CSS = '''
@import url('https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable.min.css');
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');
*{box-sizing:border-box}
html{scroll-behavior:smooth}
::selection{background:#e0e7ff;color:#1a1a2e}
body{font-family:'Pretendard Variable',Pretendard,-apple-system,BlinkMacSystemFont,system-ui,'Segoe UI',Roboto,'Apple SD Gothic Neo','Noto Sans KR','Malgun Gothic',sans-serif;max-width:1100px;margin:0 auto;padding:32px 24px;color:#1a1a2e;background:#f0f2f5;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
h2{color:#1a1a2e;margin-top:0;font-size:1.15em;font-weight:700;letter-spacing:-0.01em}
h3{color:#1a1a2e;margin-top:18px;font-size:1em;font-weight:600}
h3.scanner-heading,.chain-card>h3,details.vuln-block>summary h3{color:#4f46e5}
h4{color:#374151;margin-top:16px;font-size:0.92em;font-weight:600}
h5{color:#4b5563;margin-top:12px;font-size:0.88em;font-weight:600}
table{border-collapse:collapse;width:100%;margin:14px 0;background:white;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.06),0 0 0 1px rgba(0,0,0,.04)}
th{background:#1e293b;color:#f1f5f9;padding:11px 16px;text-align:center;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.04em}
td{padding:10px 16px;border-bottom:1px solid #f1f5f9;font-size:13px;color:#334155;word-break:keep-all;overflow-wrap:break-word}
th{word-break:keep-all}
.summary-table td{text-align:center;vertical-align:middle}
.summary-table td:nth-child(3){text-align:left}
.id-table td:first-child{white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:nth-child(even){background:#f8fafc}
tr:hover{background:#eef2ff}
pre{background:#0f172a;color:#e2e8f0;padding:18px 20px;border-radius:10px;overflow-x:auto;font-size:12.5px;line-height:1.6;border:1px solid #1e293b}
code{background:#f1f5f9;color:#334155;padding:2px 6px;border-radius:4px;font-size:12.5px;font-family:'JetBrains Mono','SF Mono',Consolas,monospace}
pre code{background:none;padding:0;color:inherit}
details.scanner-block{background:white;border:1px solid #e2e8f0;border-left:4px solid #e2e8f0;border-radius:12px;margin:14px 0;box-shadow:0 1px 4px rgba(0,0,0,.04)}
details.scanner-block>summary{cursor:pointer;padding:16px 20px;font-weight:600;user-select:none;list-style:none;transition:background .15s}
details.scanner-block>summary:hover{background:#f8fafc}
details.scanner-block>summary::-webkit-details-marker{display:none}
details.scanner-block>summary::before{content:'▸ ';font-size:13px;color:#4f46e5;font-weight:700}
details.scanner-block[open]>summary::before{content:'▾ '}
details.scanner-block[open]>summary{border-bottom:1px solid #e2e8f0}
details.scanner-block>summary h2{display:inline;font-size:1.05em;margin:0}
.scanner-body{padding:8px 20px 20px}
details.vuln-block{background:white;border:1px solid #e2e8f0;border-left:4px solid #e2e8f0;margin:16px 0;border-radius:8px;box-shadow:0 1px 2px rgba(0,0,0,.04);scroll-margin-top:16px}
details.vuln-block>summary{cursor:pointer;padding:12px 16px;list-style:none;transition:background .15s}
details.vuln-block>summary:hover{background:#f8fafc}
details.vuln-block>summary::-webkit-details-marker{display:none}
details.vuln-block>summary::before{content:'▸ ';font-size:11px;color:#4f46e5;font-weight:700}
details.vuln-block[open]>summary::before{content:'▾ '}
details.vuln-block[open]>summary{border-bottom:1px solid #f1f5f9}
details.vuln-block>summary h3{display:inline;font-size:0.95em;margin:0;color:#3730a3}
.vuln-body{padding:8px 16px 16px}
details.chain-block{background:white;border:1px solid #e2e8f0;border-left:4px solid #e2e8f0;border-radius:12px;margin:14px 0;box-shadow:0 1px 4px rgba(0,0,0,.04)}
details.chain-block>summary{cursor:pointer;padding:16px 20px;font-weight:600;user-select:none;list-style:none;transition:background .15s}
details.chain-block>summary:hover{background:#f8fafc}
details.chain-block>summary::-webkit-details-marker{display:none}
details.chain-block>summary::before{content:'▸ ';font-size:13px;color:#4f46e5;font-weight:700}
details.chain-block[open]>summary::before{content:'▾ '}
details.chain-block[open]>summary{border-bottom:1px solid #e2e8f0}
details.chain-block>summary h2{display:inline;font-size:1.05em;margin:0}
.chain-body{padding:8px 20px 20px}
details.chain-card{background:white;border:1px solid #e2e8f0;border-left:4px solid #e2e8f0;margin:14px 0;border-radius:8px}
details.chain-card>summary{cursor:pointer;padding:12px 16px;list-style:none;transition:background .15s}
details.chain-card>summary:hover{background:#f8fafc}
details.chain-card>summary::-webkit-details-marker{display:none}
details.chain-card>summary::before{content:'▸ ';font-size:11px;color:#4f46e5;font-weight:700}
details.chain-card[open]>summary::before{content:'▾ '}
details.chain-card[open]>summary{border-bottom:1px solid #f1f5f9}
details.chain-card>summary h3{display:inline;font-size:0.95em;margin:0;color:#3730a3}
.chain-card-body{padding:8px 16px 16px}
hr{border:none;border-top:1px solid #e2e8f0;margin:20px 0}
strong{color:#1a1a2e}
p{line-height:1.7;margin:8px 0;color:#374151;font-size:14px}
ul,ol{margin:8px 0;padding-left:24px;line-height:1.8;color:#374151;font-size:14px}
li{margin:2px 0}
.dashboard{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}
@media(max-width:640px){.dashboard{grid-template-columns:repeat(2,1fr)}}
.card{background:white;border-radius:12px;padding:24px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.06);border:1px solid #e2e8f0;transition:transform .15s,box-shadow .15s}
.card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.08)}
.card .num{font-size:2.8em;font-weight:800;letter-spacing:-0.02em;line-height:1;font-variant-numeric:tabular-nums}
.card .label{font-size:11px;color:#64748b;margin-top:6px;text-transform:uppercase;letter-spacing:0.06em;font-weight:600}
.card .unit{font-size:10px;color:#a5b1c2;margin-top:3px;letter-spacing:0.03em}
.confirmed .num{color:#dc2626}
.confirmed{border-left:4px solid #dc2626}
.candidate .num{color:#ea580c}
.candidate{border-left:4px solid #ea580c}
.safe .num{color:#16a34a}
.safe{border-left:4px solid #16a34a}
.na .num{color:#94a3b8}
.na{border-left:4px solid #94a3b8}
.always-open{background:white;border:1px solid #e2e8f0;border-left:4px solid #e2e8f0;border-radius:12px;padding:20px 24px;margin:14px 0;box-shadow:0 1px 4px rgba(0,0,0,.04)}
.always-open>h2{margin:0 0 14px;padding-bottom:11px;border-bottom:1px solid #eef2f6}
a.vuln-link{color:#3730a3;text-decoration:none;border-bottom:1px dashed #a5b4fc;transition:border-color .15s,color .15s}
a.vuln-link:hover{color:#4338ca;border-bottom-color:#4338ca}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;letter-spacing:0.02em;white-space:nowrap}
.badge-confirmed{background:#fef2f2;color:#dc2626;border:1px solid #fecaca}
.badge-candidate{background:#fff7ed;color:#ea580c;border:1px solid #fed7aa}
.badge-rk-confirmed{background:#fef2f2;color:#dc2626;border:1px solid #fecaca}
.badge-rk-info{background:#fffbeb;color:#d97706;border:1px solid #fde68a}
.badge-rk-env{background:#f1f5f9;color:#475569;border:1px solid #e2e8f0}
.badge-rk-skip{background:#f8fafc;color:#94a3b8;border:1px solid #e2e8f0}
@media print{
  body{max-width:none;padding:16px;background:white;color:black;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .dashboard{gap:8px}
  .card{box-shadow:none;border:1px solid #d1d5db;break-inside:avoid}
  details.scanner-block,details.vuln-block,details.chain-block{box-shadow:none;border:1px solid #d1d5db;break-inside:avoid}
  details>summary::before{display:none}
  pre{white-space:pre-wrap;word-wrap:break-word;border:1px solid #d1d5db}
}
.overview-card{background:white;border:1px solid #e2e8f0;border-left:4px solid #e2e8f0;border-radius:12px;padding:22px 26px;margin:24px 0;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.ov-grid{display:grid;grid-template-columns:max-content 1fr;gap:11px 22px;align-items:baseline}
.ov-k{color:#334155;font-size:12.5px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;white-space:nowrap}
.ov-v{color:#1e293b;font-size:13.5px;line-height:1.55}
.ov-v code{background:#f1f5f9;color:#334155}
.ov-section{grid-column:1 / -1;border-top:1px solid #eef2f6;margin-top:6px}
.ov-k-sub{font-weight:600;text-transform:none;letter-spacing:0;color:#334155}
.ov-chips{display:flex;flex-wrap:wrap;gap:6px}
.ov-chip{display:inline-block;background:#f1f5f9;color:#334155;border:1px solid #e2e8f0;border-radius:6px;padding:2px 9px;font-size:12px;font-weight:500;white-space:nowrap}
@media(max-width:640px){.ov-grid{grid-template-columns:1fr;gap:4px 0}.ov-k{margin-top:10px}}
'''

JS = '''
document.addEventListener('click',function(e){
  var a=e.target.closest('a[href^="#vuln-"]');
  if(!a)return;
  var vid=a.getAttribute('href').slice(1);
  var target=document.getElementById(vid);
  if(!target)return;
  var el=target;
  while(el){if(el.tagName==='DETAILS'&&!el.open)el.open=true;el=el.parentElement;}
  setTimeout(function(){target.scrollIntoView({behavior:'smooth'});},80);
});
window.addEventListener('beforeprint',function(){
  document.querySelectorAll('details:not([open])').forEach(function(d){d.open=true;d.dataset.po='1';});
});
window.addEventListener('afterprint',function(){
  document.querySelectorAll('details[data-po]').forEach(function(d){d.open=false;delete d.dataset.po;});
});
'''

out = []
out.append(f'''<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>통합 취약점 스캔 보고서</title>
<style>{CSS}</style>
</head>
<body>
<div class="dashboard">
  <div class="card confirmed"><div class="num">{_confirmed}</div><div class="label">확인됨</div><div class="unit">취약점</div></div>
  <div class="card candidate"><div class="num">{_candidate}</div><div class="label">후보</div><div class="unit">취약점</div></div>
  <div class="card safe"><div class="num">{_safe}</div><div class="label">이상 없음</div><div class="unit">스캐너</div></div>
  <div class="card na"><div class="num">{_na}</div><div class="label">미적용</div><div class="unit">스캐너</div></div>
</div>''')

# 파서 상태를 딕셔너리로 관리
state = {
    'in_code': False,
    'code_lang': '',
    'code_buf': [],
    'in_table': False,
    'tbl_header': [],
    'tbl_rows': [],
    'tbl_header_done': False,
    'in_ul': False,
    'in_ol': False,
    'p_buf': [],
    'always_open_div': False,
    'scanner_results_open': False,
    'chain_open': False,
    'chain_card_open': False,
    'vuln_open': False,
    'vuln_counter': 0,
}

def do_flush_p():
    if state['p_buf']:
        out.append('<p>' + ' '.join(state['p_buf']) + '</p>')
        state['p_buf'] = []

def do_flush_list():
    if state['in_ul']:
        out.append('</ul>')
        state['in_ul'] = False
    if state['in_ol']:
        out.append('</ol>')
        state['in_ol'] = False

def split_table_cells(line):
    """테이블 셀을 분리한다.

    - 백틱(인라인 코드) 내부의 | 는 구분자로 처리하지 않는다.
    - 백슬래시로 이스케이프된 \\| 는 셀 내부 리터럴 | 로 처리한다(표준 마크다운 규칙).
    """
    cells = []
    current = []
    in_backtick = False
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        # 테이블 레벨 이스케이프 \| 는 백틱 내부 여부와 무관하게 리터럴 | 로 디코딩한다
        # (GFM 규칙: 표 파서가 코드 스팬보다 먼저 \| 를 처리). 그 외 백슬래시는 보존.
        if ch == '\\' and i + 1 < n and line[i + 1] == '|':
            current.append('|')
            i += 2
            continue
        if ch == '`':
            in_backtick = not in_backtick
            current.append(ch)
        elif ch == '|' and not in_backtick:
            cells.append(''.join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    if current:
        cells.append(''.join(current))
    return [c for c in cells if c != '']

def do_flush_table():
    if not state['in_table']:
        return
    # 헤더 첫 컬럼에 따라 테이블 클래스 부여:
    #  - '순번' → 취약점 요약 테이블(셀 가운데 정렬)
    #  - 'ID'   → ID 컬럼을 가진 테이블(안전 판정 등, 첫 컬럼 줄바꿈 방지)
    _hdr0 = state['tbl_header'][0].strip() if state['tbl_header'] else ''
    if _hdr0 == '순번':
        _tbl_cls = ' class="summary-table"'
    elif _hdr0 == 'ID':
        _tbl_cls = ' class="id-table"'
    else:
        _tbl_cls = ''
    out.append(f'<table{_tbl_cls}>')
    if state['tbl_header']:
        out.append('<thead><tr>' + ''.join(f'<th>{inline(c.strip())}</th>' for c in state['tbl_header']) + '</tr></thead>')
    out.append('<tbody>')
    for row in state['tbl_rows']:
        out.append('<tr>' + ''.join(f'<td>{inline(c.strip())}</td>' for c in row) + '</tr>')
    out.append('</tbody></table>')
    state['in_table'] = False
    state['tbl_header'] = []
    state['tbl_rows'] = []
    state['tbl_header_done'] = False

def do_flush_all():
    do_flush_p()
    do_flush_list()
    do_flush_table()

def close_vuln():
    if state['vuln_open']:
        out.append('</div></details>')
        state['vuln_open'] = False

def close_chain_card():
    if state['chain_card_open']:
        out.append('</div></details>')
        state['chain_card_open'] = False

def close_chain():
    close_chain_card()
    if state['chain_open']:
        out.append('</div></details>')
        state['chain_open'] = False

def open_vuln_block(num, title):
    close_vuln()
    state['vuln_counter'] += 1
    out.append(f'<details class="vuln-block" id="vuln-{num}">')
    out.append(f'<summary><h3>{esc(title)}</h3></summary>')
    out.append('<div class="vuln-body">')
    state['vuln_open'] = True

def close_scanner_results():
    close_vuln()
    if state['scanner_results_open']:
        out.append('</div></details>')
        state['scanner_results_open'] = False

def close_always_open():
    if state['always_open_div']:
        out.append('</div>')
        state['always_open_div'] = False

for line in lines:
    # 코드 블록
    if line.startswith('```'):
        if not state['in_code']:
            do_flush_all()
            state['in_code'] = True
            state['code_lang'] = line[3:].strip()
            state['code_buf'] = []
        else:
            escaped_code = '\n'.join(esc(cl) for cl in state['code_buf'])
            lang = esc(state['code_lang']) if state['code_lang'] else ''
            out.append(f'<pre><code class="language-{lang}">{escaped_code}</code></pre>')
            state['in_code'] = False
            state['code_buf'] = []
        continue
    if state['in_code']:
        state['code_buf'].append(line)
        continue

    # **N번 ...**: 제목 / **N번 ...제목** 형식 → 취약점 블록 (서브에이전트 출력 형식 차이 흡수)
    bold_vuln_match = re.match(r'^\*\*(\d+)번[^\n*]*?[:\-]\s*(.*?)\*{0,2}\s*$', line)
    if bold_vuln_match and state['scanner_results_open'] and not state['in_code']:
        do_flush_all()
        title = bold_vuln_match.group(2).strip().rstrip('*').strip()
        if not title:
            title = re.sub(r'\*', '', line).strip()
        open_vuln_block(bold_vuln_match.group(1), title)
        continue

    # 헤딩
    h_match = re.match(r'^(#{1,4})\s+(.*)', line)
    if h_match:
        do_flush_all()
        level = len(h_match.group(1))
        title = h_match.group(2).strip()

        if level == 1:
            close_scanner_results()
            close_always_open()
            # 최상단 보고서 제목(h1)은 개요 배너로 대체되므로 렌더링하지 않는다.
            continue

        if level == 2:
            # ## N. 제목 → 스캐너별 실행 결과 내부에 있으면 취약점 블록
            num2_match = re.match(r'^(\d+)\.', title) if state['scanner_results_open'] else None
            if num2_match:
                open_vuln_block(num2_match.group(1), title)
                continue
            close_scanner_results()
            close_chain()
            close_always_open()
            if title == '스캐너별 실행 결과':
                out.append('<details class="scanner-block" open>')
                out.append('<summary><h2>스캐너별 실행 결과</h2></summary>')
                out.append('<div class="scanner-body">')
                state['scanner_results_open'] = True
            elif title == 'AI 자율 탐색 결과':
                out.append('<details class="scanner-block" open>')
                out.append('<summary><h2>AI 자율 탐색 결과</h2></summary>')
                out.append('<div class="scanner-body">')
                state['scanner_results_open'] = True
            elif title == '연계 시나리오':
                out.append('<details class="chain-block" open>')
                out.append('<summary><h2>연계 시나리오</h2></summary>')
                out.append('<div class="chain-body">')
                state['chain_open'] = True
            else:
                out.append(f'<div class="always-open"><h2>{esc(title)}</h2>')
                state['always_open_div'] = True
            continue

        if level == 3:
            # ### 체인 #N: ... → chain-card div
            if state['chain_open'] and re.match(r'^체인\s*#', title):
                do_flush_all()
                close_chain_card()
                out.append(f'<details class="chain-card"><summary><h3>{esc(title)}</h3></summary><div class="chain-card-body">')
                state['chain_card_open'] = True
                continue
            # ### [XSS] Scanner 등 스캐너 소제목
            if re.match(r'^\[', title):
                close_vuln()
                out.append(f'<h3 class="scanner-heading">{esc(title)}</h3>')
                continue
            # 스캐너 섹션 내부 + "N." 으로 시작 → 취약점 블록 (실제 번호로 id 부여)
            num3_match = re.match(r'^(\d+)\.', title) if state['scanner_results_open'] else None
            if num3_match:
                open_vuln_block(num3_match.group(1), title)
                continue
            # ### 이상없음 스캐너 이름 등 일반
            close_vuln()
            out.append(f'<h3>{esc(title)}</h3>')
            continue

        if level == 4:
            # 스캐너 섹션 내부 + "N." 으로 시작 → 취약점 블록 (실제 번호로 id 부여)
            # 숫자 없는 헤딩(원인 분석, 재현 방법 및 POC, 권장 조치 등)은 일반 h4
            num4_match = re.match(r'^(\d+)\.', title) if state['scanner_results_open'] else None
            if num4_match:
                open_vuln_block(num4_match.group(1), title)
                continue
            out.append(f'<h4>{inline(title)}</h4>')
            continue

        out.append(f'<h{level}>{inline(title)}</h{level}>')
        continue

    # 수평선
    if re.match(r'^---+$', line.strip()):
        do_flush_all()
        out.append('<hr>')
        continue

    # 빈 줄
    if line.strip() == '':
        do_flush_p()
        do_flush_list()
        do_flush_table()
        continue

    # 테이블
    if line.startswith('|'):
        cells = split_table_cells(line)
        if all(re.match(r'^[\s:-]+$', c) for c in cells):
            state['tbl_header_done'] = True
            continue
        if not state['in_table']:
            do_flush_p()
            do_flush_list()
            state['in_table'] = True
        if not state['tbl_header_done']:
            state['tbl_header'] = cells
        else:
            state['tbl_rows'].append(cells)
        continue
    else:
        do_flush_table()

    # 리스트
    ul_m = re.match(r'^(\s*)[-*]\s+(.*)', line)
    ol_m = re.match(r'^(\s*)\d+\.\s+(.*)', line)
    if ul_m:
        do_flush_p()
        if not state['in_ul']:
            do_flush_list()
            out.append('<ul>')
            state['in_ul'] = True
        out.append(f'<li>{inline(ul_m.group(2))}</li>')
        continue
    if ol_m:
        do_flush_p()
        if not state['in_ol']:
            do_flush_list()
            out.append('<ol>')
            state['in_ol'] = True
        out.append(f'<li>{inline(ol_m.group(2))}</li>')
        continue

    # 일반 텍스트
    do_flush_list()
    do_flush_table()
    # **키**: 값 형식(메타데이터 필드)은 개별 <p>로 분리
    if re.match(r'^\*\*[^*]+\*\*\s*:', line):
        do_flush_p()
    state['p_buf'].append(inline(line))

# 마무리
do_flush_all()
close_scanner_results()
close_chain()
close_always_open()

out.append(f'<script>{JS}</script>')
out.append('</body></html>')

html_out = '\n'.join(out)

# 취약점 요약 테이블 링크 추가 (총괄 요약 테이블 제외, 취약점 요약 테이블만)
# 취약점 요약 테이블: #, 취약점 제목, 유형, 스캐너, 상태 컬럼
# <tr><td>숫자</td><td>제목</td>... 패턴
def add_link(m):
    num = m.group(1)
    title_content = m.group(2)
    rest = m.group(3)
    linked = f'<a href="#vuln-{num}" class="vuln-link">{title_content}</a>'
    return f'<tr><td>{num}</td><td>{linked}</td>{rest}'

html_out = re.sub(
    r'<tr><td>(\d+)</td><td>((?:(?!</td>).)+)</td>(.*?<td>(?:확인됨|후보)</td>(?:<td>[^<]*</td>)*</tr>)',
    add_link,
    html_out,
    flags=re.DOTALL
)

# 상태값을 색상 뱃지로 변환
html_out = html_out.replace('<td>확인됨</td>', '<td><span class="badge badge-confirmed">확인됨</span></td>')
html_out = html_out.replace('<td>후보</td>', '<td><span class="badge badge-candidate">후보</span></td>')

# 비고(후보 유지 사유/확인 구분)값도 색상 뱃지로 변환
_remark_badges = {
    '동적 확인': 'badge-rk-confirmed',
    '정보 부족': 'badge-rk-info',
    '환경 제한': 'badge-rk-env',
    '동적 분석 생략': 'badge-rk-skip',
}
for _label, _cls in _remark_badges.items():
    html_out = html_out.replace(f'<td>{_label}</td>', f'<td><span class="badge {_cls}">{_label}</span></td>')

# 개요 섹션을 다크 배너 + 메타 그리드로 변환
def _build_overview_banner(m):
    body = m.group(1)
    rows = re.findall(r'<p><strong>(.+?)</strong>\s*:\s*(.+?)</p>', body, re.DOTALL)
    if not rows:
        return m.group(0)
    def _chips(s):
        return ''.join(
            f'<span class="ov-chip">{it.strip()}</span>'
            for it in s.split(',') if it.strip()
        )

    parts = []
    for k, v in rows:
        k, v = k.strip(), v.strip()
        if '::' in v:
            # '라벨 :: 항목 ;; 라벨 :: 항목' 컨벤션: 키 글자 없이 구분선만 넣고
            # 카테고리를 메타 행과 같은 라벨 컬럼에 정렬한다 (제목 중첩 방지)
            parts.append('<div class="ov-section"></div>')
            for seg in (s for s in v.split(';;') if s.strip()):
                label, _, items = seg.partition('::')
                parts.append(f'<div class="ov-k ov-k-sub">{label.strip()}</div><div class="ov-v ov-chips">{_chips(items)}</div>')
        else:
            parts.append(f'<div class="ov-k">{k}</div><div class="ov-v ov-chips">{_chips(v)}</div>')
    cells = ''.join(parts)
    return (
        '<div class="overview-card">'
        f'<div class="ov-grid">{cells}</div>'
        '</div>'
    )

# always-open 카드로 감싸인 개요(h2 '개요' ~ </div>)를 배너로 치환
html_out = re.sub(
    r'<div class="always-open">\s*<h2[^>]*>개요</h2>(.*?)</div>',
    _build_overview_banner,
    html_out,
    count=1,
    flags=re.DOTALL,
)

with open(_html_path, 'w', encoding='utf-8') as f:
    f.write(html_out)

poc = html_out.count('재현 방법 및 POC')
vb = html_out.count('class="vuln-block"')
print(f'POC: {poc}, vuln-block: {vb}, 파일: {len(html_out):,}bytes')
