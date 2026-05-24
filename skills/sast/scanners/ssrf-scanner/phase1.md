---
id_prefix: SSRF
rules_dir: rules/
---

> ## 핵심 원칙: "서버가 요청을 보내지 않으면 취약점이 아니다"
>
> `axios.get(userInput)`이 있다고 SSRF가 아니다. 서버가 사용자 제어 URL로 실제로 요청을 보내야 한다. "내부 API가 노출되면 위험" 같은 가정은 취약점이 아니다.

## Sink 의미론

SSRF sink는 "URL의 호스트/스킴/경로 일부가 사용자 입력에 의해 결정되고, 그 URL로 서버가 발신 요청을 보내는 지점"이다. **요청 주체가 서버인지 클라이언트인지** 구분이 핵심 — presigned URL 생성처럼 클라이언트가 요청자라면 SSRF 아님.

| 언어 | 일반 sink |
|---|---|
| Node.js | `axios`, `node-fetch`, `got`, `request`, `http.get/request`, `https.get/request`, `undici`, `urllib` |
| Python | `requests`, `urllib`, `urllib3`, `httpx`, `aiohttp`, `http.client` |
| Java | `HttpURLConnection`, `HttpClient` (JDK11+), `OkHttp`, `RestTemplate`, `WebClient`, `Jsoup.connect` |
| Ruby | `Net::HTTP`, `open-uri`, `HTTParty`, `Faraday`, `RestClient` |
| Go | `http.Get/Post/NewRequest`, `resty` |
| C#/.NET | `HttpClient.GetAsync/PostAsync(url)`, `WebRequest.Create(url)`, `WebClient.DownloadString(url)` |
| Rust | `reqwest::get(url)`, `hyper::Client` |
| PHP | `file_get_contents(url)`, `fopen(url)`, `curl_init(url)` + `curl_exec`, Guzzle |
| 공통 | proxy 미들웨어 (`http-proxy-middleware`), 이미지 처리/리사이즈, PDF 변환, 웹훅 발송 |

## Source-first 추가 패턴

- HTTP 파라미터: `url`, `link`, `href`, `src`, `dest`, `redirect`, `uri`, `path`, `domain`, `host`, `callback`, `webhook`, `feed`, `proxy`, `target`, `endpoint`, `image`, `avatar`
- 파일 업로드의 "URL로 가져오기" 옵션
- API body의 URL 필드
- Webhook/콜백 URL 등록 기능
- RSS/Atom feed URL
- OpenGraph/메타데이터 크롤링 URL
- OAuth `redirect_uri` (open-redirect와 겹치지만 SSRF로도 평가)
- AWS/GCS bucket name (presigned 만들 때)
- GraphQL resolver argument 중 URL 필드
- API gateway upstream URL 동적 결정
- Health check / 모니터링 설정의 외부 URL 등록

## 자주 놓치는 패턴 (Frequently Missed)

- **PDF 생성 (HTML → PDF)**: `puppeteer.goto(userHTML)`, `wkhtmltopdf`, `weasyprint` — 외부 리소스 로딩으로 SSRF.
- **이미지 변환/썸네일**: `sharp`/`imagemagick`/`Pillow`가 URL 입력을 받거나 SVG 내부 `<image href=...>`를 fetch.
- **Webhook 발송**: 사용자 등록 URL로 이벤트 전송. 보통 서버측에서 직접 호출.
- **OAuth/SSO 콜백 동적 redirect_uri**: 서버가 그 URL로 직접 요청하는 케이스.
- **XML 처리 → XXE → SSRF**: `<!DOCTYPE [<!ENTITY x SYSTEM "http://internal/">]>`. xxe-scanner와 겹치지만 SSRF 영향도로도 등록.
- **리버스 프록시 동적 target**: `http-proxy-middleware`의 `target`이 런타임에 결정.
- **Git clone / SVN checkout**: `git clone ${userUrl}` — 특수 URL(`file://`, `ext::`) 가능.
- **`open-uri`** (Ruby) 의 `Kernel#open(url)`: file:// 도 처리.
- **DNS rebinding**: 검증 시점과 요청 시점 사이 DNS 응답이 바뀌는 공격. `127.0.0.1` 검증 후 실제 요청 시 내부 IP. 화이트리스트 검증만으로는 미흡.
- **URL 파싱 차이 (parser confusion)**: `http://evil.com\@127.0.0.1/`을 `URL.parse`/`urlparse`/`Java.net.URL`이 다르게 해석.
- **Redirect 따라가기**: 외부 도메인으로 시작했다가 30x로 내부 IP로 리다이렉트. `followRedirects: true` + 검증을 first hop에서만.
- **gopher://, dict://, file://, ftp://, ldap://** 스킴 (curl/libcurl, PHP `file_get_contents`).
- **이미지 메타데이터 추출 (exiftool)** 입력에 URL.
- **Cloud metadata 서비스 접근**: AWS `169.254.169.254/latest/meta-data/` (IMDSv1), GCP `metadata.google.internal`, Azure `169.254.169.254/metadata/instance`. SSRF의 가장 흔한 실전 영향 — IAM credential 탈취 가능.
- **CRLF 인젝션 결합**: URL에 `%0d%0a` 삽입으로 추가 헤더/요청 라인 조작 (`http://internal.local/%0d%0aHost:evil.com`).

## 안전 패턴 (FP Guard)

- **Presigned URL 생성**: 서버가 URL 문자열만 만들고 클라이언트에 반환. 서버가 fetch하지 않음.
- **Base URL이 환경변수/상수 + 경로만 사용자 입력**: 그러나 경로 traversal이나 `@` 트릭은 별도 확인.
- **고정 화이트리스트 호스트**: `if (!ALLOWED_HOSTS.includes(parsed.hostname)) reject` — 단, parser confusion 회피 필요.
- **SSRF 방어 라이브러리**: `ssrf-req-filter`, `private-ip`, `is-private-ip` 등이 IP 해석 후 검증.
- **DNS resolution을 직접 수행 후 IP 화이트리스트**: 화이트리스트 통과한 IP만 connect (DNS rebinding 방어).
- **`http://`/`https://` 외 스킴 차단** + Redirect follow 시 매 hop마다 재검증.
- **Egress proxy 강제**: 모든 외부 요청을 검증 프록시 경유 (URL 검증 + 응답 필터링). 클라우드 환경에서 실용.
- **AWS IMDSv2 강제** (EC2 metadata 토큰 요구): SSRF로 IMDSv1 호출 시 차단됨. 단, 다른 cloud(GCP/Azure)는 별도 차단 필요.
- **`SO_BINDTODEVICE` / 네트워크 네임스페이스 격리**: 외부 발신만 허용하는 별도 네임스페이스에서 처리.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `127.0.0.1` 단일 차단 | 가능 | `0.0.0.0`, `localhost`, `127.1`, `127.0.0.0/8` 전체 표기, octal `0177.0.0.1`, decimal `2130706433`, hex `0x7f000001` |
| IPv4만 차단 (IPv6 미차단) | 가능 | `[::1]`, `[::ffff:127.0.0.1]` (IPv4-mapped), `[::ffff:7f00:1]` |
| 도메인 화이트리스트 substring/prefix match | 가능 | `https://allowed.com.attacker.com`, `https://attacker.com#allowed.com`, `https://allowed.com@attacker.com` |
| URL parsing 후 호스트 검증 (parser confusion) | 가능 | `http://evil.com\@127.0.0.1/`, `http://127.0.0.1#@evil.com/` — `URL.parse`/`urlparse`/Java `URL`이 다른 호스트 추출 |
| Redirect follow + first hop만 검증 | 가능 | 외부 도메인 200 응답 후 302 → `http://169.254.169.254/` |
| DNS resolution 시점 != connect 시점 | 가능 | DNS rebinding — TTL 0으로 응답을 매번 다르게 (1차 외부 IP, 2차 내부 IP) |
| 클라우드 metadata IP 단일 차단 (`169.254.169.254`) | 부분 가능 | AWS는 alias `instance-data`, IPv6 표기, IMDSv1 다른 경로 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → URL 호스트/스킴 결정 + 검증 없음 | 후보 |
| 사용자 입력 → URL 경로만 결정 (호스트는 상수) + 경로 정규화 없음 | 후보 (라벨: `PATH_ONLY`, 영향도 낮음) |
| 화이트리스트 검증 있으나 DNS resolution 후 검증 안 함 | 후보 (라벨: `DNS_REBINDING`) |
| Redirect follow + first hop만 검증 | 후보 (라벨: `REDIRECT_BYPASS`) |
| Presigned URL 생성 (서버 fetch 없음) | 제외 |
| 사용자 입력이 URL 파라미터(query)에만 들어감, 호스트/경로 고정 | 영향도 낮음, 후보 유지하되 명시 |

## 후보 판정 제한

사용자 입력이 HTTP 요청의 호스트/스킴을 제어할 수 있는 경우 후보. base URL이 설정 주입이고 경로도 하드코딩이면 제외. 경로에 사용자 입력이 포함되면 후보.
