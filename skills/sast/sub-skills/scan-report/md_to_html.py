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

# 첫 컬럼이 스캐너 이름인 표(이상 없음/미적용 스캐너 등)에서도 -scanner 접미사를 제거하여
# 요약 테이블 스캐너 컬럼과 표기를 통일한다. 첫 셀이 숫자/ID인 표(요약·안전)는 매칭되지 않는다.
_md_text = re.sub(r'(?m)^(\|\s*)([A-Za-z0-9][A-Za-z0-9-]*?)-scanner(\s*\|)', r'\1\2\3', _md_text)

# 개요 정규화: '## 개요' 헤딩이 없고 h1 직후에 메타 블록(**키**: 값)이 평문으로 오면
# 그 앞에 '## 개요' 헤딩을 삽입한다. 이렇게 하면 작성 스타일과 무관하게
# 메타 블록이 개요 카드(배너)로 렌더된다.
if not re.search(r'(?m)^##\s*개요\s*$', _md_text):
    _ov_m = re.search(r'(?m)^(#\s+.+\n)((?:[ \t]*\n)*)(\*\*[^\n*]+\*\*[ \t]*:)', _md_text)
    if _ov_m:
        _md_text = (_md_text[:_ov_m.start()] + _ov_m.group(1)
                    + '\n## 개요\n\n' + _ov_m.group(3) + _md_text[_ov_m.end():])

# 동기화된 MD 를 디스크에도 반영 (단일 진실 원천)
with open(_md_path, 'w', encoding='utf-8') as f:
    f.write(_md_text)

# 총괄 요약 섹션은 상단 대시보드 카드와 정보가 동일하므로 HTML 본문에서는 렌더링하지 않는다.
# 대시보드 카드 수치는 아래 _parse_dashboard 가 _md_text 원본(제거 전)에서 파싱하므로
# MD 파일에는 데이터 원천으로 그대로 남는다(디스크 쓰기는 line 66~67에서 _md_text 로 이미 완료).
# 코드펜스(```/~~~)를 추적하면서, 펜스 밖의 '## 총괄 요약' 헤딩 줄부터 다음 ## 헤딩 직전
# (또는 문서 끝)까지 통째로 제거한다. 이렇게 하면 ① 표/불릿/설명문 등 본문 형식과 무관하게
# 섹션 전체가 숨겨지고, ② 코드블록 내부의 동일 문자열은 헤딩으로 오인되지 않아 보존되며,
# ③ '## 총괄 요약 상세' 같은 유사 헤딩(헤딩 텍스트 불일치)은 제거되지 않는다.
def _strip_overview_section(md):
    result, in_fence, fence_tok, skipping = [], False, None, False
    for ln in md.split('\n'):
        fm = re.match(r'^[ \t]*(`{3,}|~{3,})', ln)
        if fm:
            tok = fm.group(1)[0] * 3
            if not in_fence:
                in_fence, fence_tok = True, tok
            elif tok == fence_tok:
                in_fence, fence_tok = False, None
            if not skipping:
                result.append(ln)
            continue
        if not in_fence and re.match(r'^##[ \t]+총괄 요약[ \t]*$', ln):
            skipping = True
            continue
        if skipping:
            if not in_fence and re.match(r'^##[ \t]+', ln):
                skipping = False
                result.append(ln)
            # 그 외(섹션 본문)는 버린다 — 코드펜스 안이면 종료 헤딩으로 보지 않으므로 계속 스킵
            continue
        result.append(ln)
    return '\n'.join(result)

_render_md = _strip_overview_section(_md_text)
lines = [l.rstrip('\n') for l in _render_md.splitlines()]

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
_m_date = re.search(r'\*\*스캔 일시\*\*:\s*([^\n]+)', _md_text)
_scan_date = _m_date.group(1).strip() if _m_date else ''

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
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');
*{box-sizing:border-box}
html{scroll-behavior:smooth}
::selection{background:#fde047;color:#111}
body{font-family:'Pretendard Variable',Pretendard,-apple-system,BlinkMacSystemFont,system-ui,'Segoe UI',Roboto,'Apple SD Gothic Neo','Noto Sans KR',sans-serif;max-width:1080px;margin:0 auto;padding:34px 24px;color:#1a1a1a;background:#f5f4ef;-webkit-font-smoothing:antialiased}
h2{color:#000;margin-top:0;font-size:1.25em;font-weight:800;letter-spacing:-0.02em}
h3{color:#111;margin-top:18px;font-size:1.02em;font-weight:700}
h3.scanner-heading,.chain-card>h3,details.vuln-block>summary h3{color:#7c3aed}
h4{color:#222;margin-top:16px;font-size:0.94em;font-weight:700}
h5{color:#333;margin-top:12px;font-size:0.9em;font-weight:600}
table{border-collapse:collapse;width:100%;margin:20px 0;background:white;border:2px solid #111;box-shadow:4px 4px 0 #111}
th{background:#111;color:#fff;padding:12px 16px;text-align:center;font-size:11.5px;font-weight:800;text-transform:uppercase;letter-spacing:0.05em}
td{padding:11px 16px;border-bottom:1px solid #d8d8d2;font-size:13px;color:#1a1a1a;word-break:keep-all;overflow-wrap:break-word}
th{word-break:keep-all}
.summary-table td{text-align:center;vertical-align:middle}
.summary-table td:nth-child(3){text-align:left}
.summary-table td:nth-child(2){white-space:nowrap}
.id-table td:first-child{white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:nth-child(even){background:#faf9f4}
tr:hover{background:#f3eefe}
pre{background:#1a1a1a;color:#f0f0f0;padding:18px 20px;border:2px solid #111;box-shadow:4px 4px 0 #111;overflow-x:auto;font-size:12.5px;line-height:1.6;border-radius:0}
code{background:#ede9fe;color:#5b21b6;padding:2px 6px;border:1px solid #111;border-radius:0;font-size:12px;font-family:'JetBrains Mono','SF Mono',Consolas,monospace}
pre code{background:none;padding:0;color:inherit;border:none}
details.scanner-block{background:white;border:2px solid #111;border-radius:0;margin:18px 0;box-shadow:4px 4px 0 #111}
details.scanner-block>summary{cursor:pointer;padding:15px 18px;font-weight:700;user-select:none;list-style:none;transition:background .12s}
details.scanner-block>summary:hover{background:#f3eefe}
details.scanner-block>summary::-webkit-details-marker{display:none}
details.scanner-block>summary::before{content:'▸ ';font-size:13px;color:#7c3aed;font-weight:800}
details.scanner-block[open]>summary::before{content:'▾ '}
details.scanner-block[open]>summary{border-bottom:2px solid #111}
details.scanner-block>summary h2{display:inline;font-size:1.04em;margin:0}
.scanner-body{padding:10px 18px 18px}
details.vuln-block{background:white;border:2px solid #111;margin:14px 0;border-radius:0;box-shadow:3px 3px 0 #111;scroll-margin-top:16px}
details.vuln-block>summary{cursor:pointer;padding:12px 16px;list-style:none;transition:background .12s}
details.vuln-block>summary:hover{background:#f3eefe}
details.vuln-block>summary::-webkit-details-marker{display:none}
details.vuln-block>summary::before{content:'▸ ';font-size:11px;color:#7c3aed;font-weight:800}
details.vuln-block[open]>summary::before{content:'▾ '}
details.vuln-block[open]>summary{border-bottom:2px solid #111}
details.vuln-block>summary h3{display:inline;font-size:0.96em;margin:0;color:#5b21b6}
.vuln-body{padding:10px 16px 16px}
details.chain-block{background:white;border:2px solid #111;border-radius:0;margin:18px 0;box-shadow:4px 4px 0 #111}
details.chain-block>summary{cursor:pointer;padding:15px 18px;font-weight:700;user-select:none;list-style:none;transition:background .12s}
details.chain-block>summary:hover{background:#f3eefe}
details.chain-block>summary::-webkit-details-marker{display:none}
details.chain-block>summary::before{content:'▸ ';font-size:13px;color:#7c3aed;font-weight:800}
details.chain-block[open]>summary::before{content:'▾ '}
details.chain-block[open]>summary{border-bottom:2px solid #111}
details.chain-block>summary h2{display:inline;font-size:1.04em;margin:0}
.chain-body{padding:10px 18px 18px}
details.chain-card{background:#faf9f4;border:2px solid #111;margin:14px 0;border-radius:0;box-shadow:3px 3px 0 #111}
details.chain-card>summary{cursor:pointer;padding:12px 16px;list-style:none;transition:background .12s}
details.chain-card>summary:hover{background:#f3eefe}
details.chain-card>summary::-webkit-details-marker{display:none}
details.chain-card>summary::before{content:'▸ ';font-size:11px;color:#7c3aed;font-weight:800}
details.chain-card[open]>summary::before{content:'▾ '}
details.chain-card[open]>summary{border-bottom:2px solid #111}
details.chain-card>summary h3{display:inline;font-size:0.96em;margin:0;color:#5b21b6}
.chain-card-body{padding:10px 16px 16px}
hr{border:none;border-top:2px solid #111;margin:22px 0}
strong{color:#000;font-weight:700}
p{line-height:1.7;margin:9px 0;color:#1a1a1a;font-size:14px}
ul,ol{margin:9px 0;padding-left:24px;line-height:1.8;color:#1a1a1a;font-size:14px}
li{margin:3px 0}
.masthead{background:#fff;border:2px solid #111;border-radius:0;padding:32px 32px;margin-bottom:24px;color:#111;box-shadow:7px 7px 0 #111}
.mh-kicker{font-size:11px;letter-spacing:0.16em;font-weight:800;color:#7c3aed;text-transform:uppercase}
.mh-title{font-size:2.1em;font-weight:800;letter-spacing:-0.02em;margin-top:10px;color:#111}
.mh-sub{font-size:13px;color:#666;margin-top:10px;font-weight:600}
.dashboard{display:grid;grid-template-columns:1fr 1fr;gap:30px;margin:0 0 26px}
.dash-glabel{font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:0.08em;color:#111;margin-bottom:12px;padding-bottom:7px;border-bottom:2px solid #111}
.dash-cards{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:640px){.dashboard{grid-template-columns:1fr}}
.card{background:white;border:2px solid #111;border-radius:0;padding:24px;text-align:center;box-shadow:4px 4px 0 #111;transition:transform .12s,box-shadow .12s}
.card:hover{transform:translate(2px,2px);box-shadow:2px 2px 0 #111}
.card .num{font-size:2.9em;font-weight:800;letter-spacing:-0.03em;line-height:1;font-variant-numeric:tabular-nums}
.card .label{font-size:11px;color:#222;margin-top:8px;text-transform:uppercase;letter-spacing:0.06em;font-weight:800}
.confirmed{background:#fee2e2}
.confirmed .num{color:#dc2626}
.candidate{background:#ffedd5}
.candidate .num{color:#ea580c}
.safe{background:#dcfce7}
.safe .num{color:#16a34a}
.na{background:#f1f1ee}
.na .num{color:#525252}
.always-open{background:white;border:2px solid #111;border-radius:0;padding:22px 24px;margin:18px 0;box-shadow:4px 4px 0 #111}
.always-open>h2{margin:0 0 16px;padding-bottom:12px;border-bottom:2px solid #111}
a.vuln-link{color:#5b21b6;text-decoration:none;border-bottom:2px solid #c4b5fd;font-weight:600;transition:background .12s}
a.vuln-link:hover{background:#fde047;border-bottom-color:#111}
.badge{display:inline-block;padding:2px 9px;border-radius:0;font-size:11px;font-weight:700;letter-spacing:0.02em;white-space:nowrap;border:1.5px solid #111}
.badge-confirmed{background:#fee2e2;color:#b91c1c}
.badge-candidate{background:#ffedd5;color:#c2410c}
.badge-rk-confirmed{background:#fee2e2;color:#b91c1c}
.badge-rk-info{background:#fef9c3;color:#a16207}
.badge-rk-env{background:#ccfbf1;color:#0f766e}
.badge-rk-skip{background:#f1f1ee;color:#666}
@media print{
  body{max-width:none;padding:16px;background:white;color:black;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  table,.card,details.scanner-block,details.vuln-block,details.chain-block,details.chain-card,.always-open,.overview-card,pre,.masthead{box-shadow:none;break-inside:avoid}
  .masthead{background:#7c3aed!important}
  pre{white-space:pre-wrap;word-wrap:break-word}
  details>summary::before{display:none}
}
.overview-card{background:white;border:2px solid #111;border-radius:0;padding:22px 26px;margin:24px 0;box-shadow:4px 4px 0 #111}
.ov-grid{display:grid;grid-template-columns:max-content 1fr;gap:12px 22px;align-items:baseline}
.ov-k{color:#333;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;white-space:nowrap}
.ov-v{color:#111;font-size:13.5px;line-height:1.55}
.ov-v code{background:#ede9fe;color:#5b21b6}
.ov-section{grid-column:1 / -1;border-top:2px solid #111;margin-top:6px}
.ov-k-sub{font-weight:700;text-transform:none;letter-spacing:0;color:#222}
.ov-chips{display:flex;flex-wrap:wrap;gap:7px}
.ov-chip{display:inline-block;background:#ede9fe;color:#5b21b6;border:1.5px solid #111;border-radius:0;padding:2px 9px;font-size:12px;font-weight:600;white-space:nowrap}
@media(max-width:640px){.ov-grid{grid-template-columns:1fr;gap:4px 0}.ov-k{margin-top:10px}}
/* Mermaid 다이어그램: SVG가 컨테이너(열) 폭을 꽉 채우도록 강제.
   mermaid 는 기본적으로 svg 에 max-width:자연폭px 를 인라인으로 박아 자연 크기 이상으로
   확대되지 않으므로(→ 작은 그래프가 좌측에 쏠림), width/max-width 를 100% 로 덮어쓰고
   height:auto 로 viewBox 비율을 유지한다. */
.mermaid{margin:22px 0;text-align:center}
.mermaid svg{width:100%!important;max-width:100%!important;height:auto;display:block;margin:0 auto}
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
<div class="masthead">
  <div class="mh-kicker">SECURITY ASSESSMENT REPORT</div>
  <div class="mh-title">통합 취약점 스캔 보고서</div>
  <div class="mh-sub">{_scan_date}</div>
</div>
<div class="dashboard">
  <div class="dash-group">
    <div class="dash-glabel">취약점</div>
    <div class="dash-cards">
      <div class="card confirmed"><div class="num">{_confirmed}</div><div class="label">확인됨</div></div>
      <div class="card candidate"><div class="num">{_candidate}</div><div class="label">후보</div></div>
    </div>
  </div>
  <div class="dash-group">
    <div class="dash-glabel">스캐너</div>
    <div class="dash-cards">
      <div class="card safe"><div class="num">{_safe}</div><div class="label">이상 없음</div></div>
      <div class="card na"><div class="num">{_na}</div><div class="label">미적용</div></div>
    </div>
  </div>
</div>''')

# 파서 상태를 딕셔너리로 관리
state = {
    'in_code': False,
    'code_lang': '',
    'used_mermaid': False,
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
            if state['code_lang'].lower() == 'mermaid':
                # mermaid 다이어그램: 원본 문법 보존(escape 금지) + .mermaid div로 렌더
                raw_code = '\n'.join(state['code_buf'])
                out.append(f'<div class="mermaid">{raw_code}</div>')
                state['used_mermaid'] = True
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
if state['used_mermaid']:
    out.append('<script type="module">import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs"; mermaid.initialize({ startOnLoad: true });</script>')
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
    '동적 테스트 완료': 'badge-rk-confirmed',
    '동적 확인': 'badge-rk-confirmed',        # 구버전 호환
    '정보 부족': 'badge-rk-info',
    '환경 제한 — 경로 미라우팅': 'badge-rk-env',
    '환경 제한 — 인증 정보 부족': 'badge-rk-env',
    '환경 제한': 'badge-rk-env',              # 부분 매칭 폴백
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
    def _chips(s, multi=False):
        # 칩 경계 분리. 괄호()/대괄호[] 내부의 구분자는 보존하여
        # 'Spring WebFlux (Spring Boot 3.5.0)' 처럼 괄호 안에 슬래시·쉼표가 있어도
        # 칩이 중간에서 끊기거나 괄호 짝이 깨지지 않게 한다.
        # 입력 s 는 이미 HTML 이스케이프된 문자열(`<`→`&lt;`, `&`→`&amp;` 등)이므로
        # 구분자 선정 시 엔티티(`&...;`)를 깨지 않도록 보수적으로 고른다.
        #  - 항상: 쉼표(,) 경계.
        #  - multi=True (스택)만 추가로:
        #     · ';;' (세미콜론 2개) — 카테고리 라벨이 없는 구분 잔재. 엔티티의 단일 ';'는 보존.
        #     · ' / ' (양옆이 공백인 슬래시) — 'A / B' 나열 구분. 'TCP/IP'·'CI/CD' 처럼
        #       이름에 붙은 슬래시나 이스케이프된 '&lt;/script&gt;' 의 '/'는 보존.
        #    대상·테스트 환경(multi=False)은 쉼표만 — 프로젝트명/도메인이 임의로 쪼개지지 않게.
        items, buf, depth, i, n = [], [], 0, 0, len(s)
        while i < n:
            ch = s[i]
            if ch in '([':
                depth += 1; buf.append(ch); i += 1
            elif ch in ')]':
                depth = max(0, depth - 1); buf.append(ch); i += 1
            elif depth == 0 and ch == ',':
                items.append(''.join(buf)); buf = []; i += 1
            elif depth == 0 and multi and ch == ';' and i + 1 < n and s[i + 1] == ';':
                items.append(''.join(buf)); buf = []; i += 2
            elif (depth == 0 and multi and ch == '/'
                  and 0 < i < n - 1 and s[i - 1].isspace() and s[i + 1].isspace()):
                items.append(''.join(buf)); buf = []; i += 1
            else:
                buf.append(ch); i += 1
        items.append(''.join(buf))
        # 양끝의 외톨이 구분자(/ ,)를 정리해 'Kotlin /' 같은 군더더기를 없앤다.
        # ';' 는 절대 제거하지 않는다 — HTML 엔티티('&gt;', '&amp;')의 끝 세미콜론이 깨진다.
        out = []
        for it in items:
            it = it.strip().strip('/,').strip()
            if it:
                out.append(f'<span class="ov-chip">{it}</span>')
        return ''.join(out)

    parts = []
    for k, v in rows:
        k, v = k.strip(), v.strip()
        # 스캔 일시는 상단 마스트헤드에 표기되므로, 스캔 방식은 표기 정책상 개요에서 제외 (MD에는 유지)
        if k in ('스캔 일시', '스캔 방식'):
            continue
        if '::' in v:
            # '라벨 :: 항목 ;; 라벨 :: 항목' 컨벤션: 키 글자 없이 구분선만 넣고
            # 카테고리를 메타 행과 같은 라벨 컬럼에 정렬한다 (제목 중첩 방지)
            parts.append('<div class="ov-section"></div>')
            for seg in (s for s in v.split(';;') if s.strip()):
                label, _, items = seg.partition('::')
                parts.append(f'<div class="ov-k ov-k-sub">{label.strip()}</div><div class="ov-v ov-chips">{_chips(items, multi=True)}</div>')
        else:
            # 스택만 다구분자 분리(슬래시/세미콜론 허용). 대상·테스트 환경 등은 쉼표만.
            parts.append(f'<div class="ov-k">{k}</div><div class="ov-v ov-chips">{_chips(v, multi=(k == "스택"))}</div>')
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
