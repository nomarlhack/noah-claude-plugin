---
id_prefix: PDFGEN
grep_patterns:
  - "wkhtmltopdf"
  - "puppeteer"
  - "WeasyPrint"
  - "PDFKit"
  - "prawn"
  - "html-pdf"
  - "pdf-creator-node"
  - "pdfmake"
  - "html.*pdf"
  - "pdf.*generat"
  - "playwright.*pdf"
---

> ## 핵심 원칙: "PDF에 의도하지 않은 내용이 포함되지 않으면 취약점이 아니다"
>
> PDF 생성 자체는 취약점이 아니다. 사용자 입력이 PDF 생성 HTML에 삽입되어 (1) 로컬 파일 내용이 PDF에 포함되거나, (2) 내부 서비스로 요청이 발생하거나(SSRF), (3) JavaScript가 실행되어야 한다.

## Sink 의미론

PDF Generation sink는 "사용자 입력이 HTML→PDF 변환기의 입력에 포함되고, 변환기가 외부 리소스 fetch/JS 실행/파일 접근을 허용하는 지점"이다. PDF 직접 생성 라이브러리(pdfkit/reportlab/pdf-lib)는 HTML 파싱 안 함 → sink 아님.

| 언어 | HTML 렌더 (위험) | 직접 생성 (안전) |
|---|---|---|
| Node | `puppeteer`, `playwright`, `wkhtmltopdf`, `html-pdf` (deprecated) | `pdf-lib`, `pdfkit`, `pdfmake` |
| Python | `weasyprint`, `pdfkit` (wkhtmltopdf wrapper), `xhtml2pdf`/`pisa` | `reportlab` |
| Java | `Flying Saucer` (xhtmlrenderer), `iText` (HTML 파싱 시), Apache FOP, `pd4ml` | `iText` 직접 API |
| PHP | `dompdf`, `mpdf`, `wkhtmltopdf` wrapper | `tcpdf` 직접 API |
| .NET | `Puppeteer Sharp`, `IronPDF`, `wkhtmltopdf` wrapper | — |

**위험 카테고리:**
- **HTML/CSS 인젝션 → SSRF**: `<img src="http://internal/">` `<link rel="stylesheet" href="...">`
- **HTML/CSS 인젝션 → LFI**: `<img src="file:///etc/passwd">` (PDF에 base64 삽입되거나 메타데이터로 노출)
- **JS 실행 (puppeteer/headless Chrome)**: full DOM XSS surface
- **`<iframe>`**: 외부 페이지 fetch
- **CSS `@import url(file://...)`**

## Source-first 추가 패턴

- 사용자 입력 텍스트가 PDF 본문에 포함 (이름/주소/메모/주문내역)
- 사용자가 HTML/마크다운 직접 입력 (게시글, 리뷰)
- URL 파라미터가 PDF에 반영
- 사용자가 PDF 템플릿 선택/커스터마이징
- 영수증/인보이스 생성에 사용자 데이터 (회사명/주소)
- 보고서 생성 (관리자가 export)
- 이메일 본문 → PDF 변환

## 자주 놓치는 패턴 (Frequently Missed)

- **`file:///` 스킴 LFI**: `<img src="file:///etc/passwd"/>` — wkhtmltopdf, weasyprint 기본 허용. base64로 PDF에 임베드되어 추출 가능.
- **내부 IP SSRF**: `<img src="http://169.254.169.254/latest/meta-data/">` (AWS metadata).
- **wkhtmltopdf `--enable-local-file-access`** 옵션 (또는 deprecated 플래그 미지정 시 기본 허용).
- **puppeteer `page.setContent(html)` + JavaScript 실행**: HTML 안에 `<script>fetch('http://internal/...')</script>` → 결과를 DOM에 출력 → PDF에 캡처.
- **puppeteer `--no-sandbox`** 운영 환경: Chrome sandbox 비활성 → 컨테이너 탈출 위험.
- **iframe redirect chain**: `<iframe src="https://attacker/redirect_to_internal/"`.
- **CSS `@import`/`background: url(...)`**: HTML sanitize했지만 CSS 미점검.
- **SVG inline**: `<svg><image href="file:///..."/></svg>`.
- **dompdf `@font-face src: url(php://filter/...)`** (dompdf RCE CVE-2022-28368).
- **mpdf `<htmlpageheader>` `<watermarkimage src="file://...">`**.
- **CSP가 PDF 렌더에는 적용 안 됨**: 브라우저 CSP는 사용자 브라우저용. 서버 puppeteer는 CSP 무시.
- **Markdown → HTML → PDF 체인**: marked/markdown-it의 raw HTML 허용 옵션이 켜져 있으면 sanitize 우회.
- **xhtml2pdf의 `<pdf:link>` 태그**.
- **Flying Saucer `<img src="...">`** + `_userAgentCallback` 미설정.
- **PDF 자체에 JavaScript 임베드** (`/JS` action): PDF 뷰어에서 실행 — Adobe Reader 등.
- **결과 PDF가 다른 사용자에게 발송**: stored XSS → PDF stored exfiltration.
- **Headless Chrome extension 제거 안 됨**: devtools/extension 활성 시 추가 공격면.
- **PDF annotation `/JavaScript`**: PDF 뷰어에서 실행되는 JS — 내부 네트워크 fetch 가능한 Adobe Reader 등.
- **SVG filter `<feImage href="...">`**: SVG 내부 외부 리소스 fetch — HTML sanitize 통과하는 경우.
- **Chromium `--allow-file-access-from-files`**: puppeteer 옵션 중 file:// 허용 — 잔존 시 LFI 게이트.

## 안전 패턴 (FP Guard)

- **HTML escape (DOMPurify/sanitize-html) 후 템플릿 보간**.
- **wkhtmltopdf `--disable-local-file-access` + `--disable-javascript`**.
- **weasyprint `url_fetcher`** 커스터마이징으로 `file://`/내부 IP 차단.
- **puppeteer**: HTML 직접 컴파일이 아닌 화이트리스트된 데이터 컨텍스트만 사용 + `page.setRequestInterception(true)`로 outgoing 요청 차단.
- **dompdf `DOMPDF_ENABLE_REMOTE = false` + `DOMPDF_ENABLE_PHP = false`**.
- **PDF 직접 생성 라이브러리** (pdfkit/reportlab/pdf-lib) 사용 + 텍스트 API만 호출.
- **변환을 격리된 컨테이너에서 실행** (network egress 없음).
- **고정 템플릿 + 사용자 입력은 데이터 컨텍스트(Mustache 변수)로만**.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| HTML sanitize (DOMPurify) | 부분 가능 | CSS 미점검 시 `@import url(file://)` 또는 SVG `<image href="file://">`로 우회 |
| wkhtmltopdf `--disable-local-file-access` | 부분 가능 | 외부 HTTP fetch는 여전히 가능 — `--disable-javascript` + 네트워크 격리 필요 |
| puppeteer `setRequestInterception(true)` | 가능 | `data:` URL로 내장 리소스 fetch, 또는 `redirect`로 우회 |
| 네트워크 egress 차단 | 부분 가능 | CDN/reverse proxy에 있는 내부 리소스 (예: prometheus 메트릭)는 allowlist에 있으면 접근 가능 |
| `file://` 스킴만 차단 | 가능 | `php://filter`, `gopher://`, `dict://` 등 다른 스킴 누락 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| HTML 렌더 라이브러리 + 사용자 입력 직접 보간 + sanitize 없음 | 후보 |
| wkhtmltopdf + `--disable-local-file-access` 미적용 + 사용자 입력 | 후보 (라벨: `LFI`) |
| puppeteer `setContent` + 사용자 HTML + 네트워크 차단 없음 | 후보 (라벨: `SSRF`/`LFI`) |
| dompdf 1.x 미만 + 사용자 입력 | 후보 (라벨: `RCE`, dompdf font CVE) |
| 직접 생성 라이브러리 (pdfkit/reportlab) + 텍스트 API만 사용 | 제외 |
| 격리된 컨테이너 + 네트워크 egress 차단 확인 | 제외 |
| 화이트리스트 데이터 컨텍스트만 + 고정 템플릿 | 제외 |

## 후보 판정 제한

사용자 입력이 HTML→PDF 변환의 입력에 포함되는 경우만 후보. PDF 직접 생성 라이브러리의 텍스트 API 사용은 제외.
