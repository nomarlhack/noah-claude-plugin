---
id_prefix: OREDIR
grep_patterns:
  - "res\\.redirect\\s*\\("
  - "res\\.writeHead\\s*\\("
  - "HttpResponseRedirect\\s*\\("
  - "redirect\\s*\\("
  - "redirect_to"
  - "redirect_back"
  - "header\\('Location"
  - "http\\.Redirect\\s*\\("
  - "window\\.location\\.href\\s*="
  - "window\\.location\\.replace\\s*\\("
  - "window\\.location\\.assign\\s*\\("
  - "window\\.location\\s*="
  - "location\\.href\\s*="
  - "window\\.open\\s*\\("
  - "router\\.push\\s*\\("
  - "router\\.replace\\s*\\("
  - "navigate\\s*\\("
  - "webview_mount\\s*\\("
  - "webview_load\\s*\\("
  - "postMessage\\s*\\("
  - "searchParams\\.get\\s*\\("
  - "useParams\\s*\\("
  - "useSearchParams"
  - "@RequestParam"
  - "@PathVariable"
  - "req\\.query"
  - "req\\.params"
---

> ## 핵심 원칙: "외부로 리다이렉트되지 않으면 취약점이 아니다"
>
> `window.location.href = userInput`이 있다고 Open Redirect가 아니다. 사용자 제어 URL로 외부 도메인 이동이 실제로 발생해야 한다. URL 검증 로직이 있으면 우회 가능성까지 확인해야 한다.

## Sink 의미론

Open Redirect sink는 "URL을 인자로 받아 그 URL의 콘텐츠를 로드하거나 그 URL로 이동하는 모든 함수"이다. 표준 API뿐 아니라 앱 네이티브 브리지, WebView API, iframe src 할당, 커스텀 네비게이션 함수 포함. 함수명이나 타입 정의에서 첫 번째 인자가 URL이고 페이지 로드/이동 동작을 수행하면 sink로 판정. 목록에 없다는 이유로 제외 금지.

**서버사이드:**
- Node/Express: `res.redirect`, `res.writeHead(302, {location})`, `res.setHeader('Location', ...)`
- Next.js: `getServerSideProps redirect`, `ctx.res.writeHead(302)`
- Django: `HttpResponseRedirect`, `redirect()`, `RedirectView`
- Flask: `redirect()`, `make_response` + Location
- Spring: `RedirectView`, `redirect:` prefix, `sendRedirect`
- Rails: `redirect_to`, `redirect_back`
- PHP: `header('Location: ' . $url)`
- Go: `http.Redirect(w, r, url, 302)`, `http.RedirectHandler`
- C#/.NET: `Response.Redirect(url)`, `RedirectResult(url)` (ASP.NET Core)
- Rust: `axum::response::Redirect::to(url)`, `rocket::response::Redirect::to(url)`
- HTML: `<meta http-equiv="refresh" content="0; url=...">`

**클라이언트사이드:**
- `window.location.href/assign/replace`, `window.location =`, `window.open`
- `document.location =`
- `form.action = url; form.submit()`
- React `<a href={url}>`, `<Link to={url}>`
- 앱 브리지 (`Native.openUrl`, `WebView.load`)

## Source-first 추가 패턴

**직접 source** (요청 시점에 공격자 제어 가능):
- HTTP 파라미터: `redirect`, `redirectUrl`, `returnUrl`, `return_to`, `next`, `url`, `goto`, `target`, `destination`, `continue`, `callback`, `redir`, `redirect_uri`, `return`, `out`, `link`
- HTTP `Referer` 헤더
- URL 경로 자체 (catch-all 라우트)

**간접 source** (이전 단계에서 저장된 값을 경유):
- 쿠키/세션에 저장된 redirect URL
- DB에 저장된 URL (프로필 URL, 콜백 URL)
- OAuth 등록 redirect_uri (DB persisted)

간접 source는 "리다이렉트 sink에서 값을 읽는 시점"이 아니라 "그 값이 최초로 저장되는 시점"까지 추적해야 한다. Step C 참조.

## 자주 놓치는 패턴 (Frequently Missed)

- **URL parser confusion**: `https://allowed.com@evil.com`을 일부 parser는 host=`allowed.com`, 일부는 `evil.com`. WHATWG URL과 Java/Python `urlparse`가 다를 수 있음.
- **Protocol-relative URL `//evil.com`**: 절대 URL 차단했는데 `//`는 통과.
- **Backslash `https:\\evil.com`**: 일부 브라우저가 정규화.
- **Subdomain confusion**: `https://allowed.com.evil.com` (suffix 검증 미흡).
- **Punycode/Unicode 동형**: `https://аllowed.com` (cyrillic a).
- **`javascript:`/`data:` 스킴**: open redirect에서 클라이언트 sink로 갈 때 XSS로 변형.
- **Relative path traversal**: `/safe/../../../evil` 형태.
- **Fragment 우회**: 검증은 query만, fragment에 페이로드.
- **Multi-step OAuth flow**: 1단계 검증 통과 후 2단계에서 다시 사용 (상태 누락).
- **메타 refresh의 동적 URL**: HTML 응답에 사용자 입력으로 `<meta refresh>` 생성.
- **앱 브리지/딥링크**: `myapp://action?url=...` 같은 커스텀 스킴.
- **PostMessage → location.href 체인**: dom-xss-scanner와 겹치지만 redirect로도 등록.
- **CRLF in redirect URL**: `Location: https://evil.com\r\nSet-Cookie: ...` — HTTP 헤더 인젝션과 결합.
- **302 응답 본문에 외부 리소스 fetch**: 일부 브라우저가 redirect 전 본문 처리 — `<script>`/`<iframe>` 실행 가능.
- **Tab-nabbing** (`target="_blank"` 없는 `window.opener` 탈취): open redirect 후 window.opener로 원본 페이지 조작.
- **정규식 `^https://example\.com`** (`.`는 임의 문자 매칭): `https://example-com.attacker.com` 우회.

## 안전 패턴 (FP Guard)

- **상대 경로 강제**: `if (!url.startsWith('/') || url.startsWith('//')) reject`.
- **WHATWG URL 파싱 후 host 화이트리스트**: `new URL(input, base).host` 비교 — 단, base 없이 파싱하면 invalid relative URL이 throw.
- **전체 URL을 접두사로 검증** (`startsWith('https://allowed.com/')`) — 단 `@` trick 회피 위해 host 추출 후 검증이 안전.
- **고정 redirect 맵**: 사용자 입력은 key, 실제 URL은 서버가 매핑.
- **`url.parse(x).protocol === 'https:' && ALLOWED_HOSTS.includes(parsed.host)`** + `parsed.host`가 정확한 host 추출.
- **OAuth `redirect_uri` 사전 등록**: 등록된 URL과 정확 일치 검증.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `startsWith('https://example.com')` | 가능 | `https://example.com.attacker.com`, `https://example.com@attacker.com`, `https://example.com#attacker.com` |
| 정규식 `^https://example\.com` | 가능 | `.`이 임의 문자 매칭 → `https://example-com.attacker.com` 통과 |
| `startsWith('/')` (상대 경로 강제) | 가능 | `//evil.com` (protocol-relative), `/\evil.com` (일부 브라우저 정규화), `/%2f%2fevil.com` |
| Host 화이트리스트 (URL 파싱 후) | 환경 의존 | WHATWG URL vs Python `urlparse` vs Java `java.net.URL` 파싱 차이 — 서버는 A로 파싱, 브라우저는 B로 해석 |
| Scheme 블랙리스트 (`javascript:`) | 가능 | `JavaScript:`, `java\tscript:`, `data:text/html,...`, `vbscript:`, `file:///` |
| Punycode 변환 후 검증 | 부분 가능 | 동형 문자 (`а` 키릴 vs `a` 라틴) — 정규화 안 하면 통과 |
| Fragment만 검증 제외 | 가능 | `/safe?url=...#https://evil.com` — fragment가 location.hash로 들어가면 SPA 라우터 조작 |

## 후보 판정 의사결정

7단계 절차를 따른다.

### Step A: Sink 식별
URL 기반 리다이렉트/네비게이션을 수행하는 모든 sink 식별.

### Step B: Sink 입력값의 직접 출처
- (B1) 현재 요청의 query/path/body/header
- (B2) 세션/쿠키/캐시/DB
- (B3) 외부 API 응답값
- (B4) 상수/하드코딩

(B1) → Step D 직진. (B2)~(B3) → Step C 역추적 필수. (B4) → 안전.

### Step C: Source 역추적 (필수, 깊이 제한 있음)
다음 중 하나에 도달할 때까지:
1. **외부 입력 source 도달** → Step D
2. **상수/하드코딩** → 안전, 종료
3. **이미 방문한 (파일:라인) 재방문** → "추적 한계"로 기록 후 종료
4. **함수 호출 5단계 초과** → `UNKNOWN`으로 분류, "추적 한계(깊이)" 사유 기재 후 종료
5. **외부 의존성 경계** (외부 라이브러리/마이크로서비스/SaaS):
   - 내부 구현은 추적하지 않는다
   - 그 외부로 보내는 인자가 사용자 제어 가능한지 점검 (호출문의 인자 표현식 + 같은 함수 스코프 내 직전 대입문 1회)
   - 인자가 사용자 입력에 닿으면 그 source를 Step D 매트릭스에 입력
   - 인자가 상수/내부 식별자만이면 안전

저장소(세션/DB) 경로는 그 저장소에 값을 쓰는 모든 코드 위치를 Grep으로 찾아 동일한 종료 조건까지 추적. (파일:라인) 집합으로 순환만 막고 저장소 역추적도 함수 호출 5단계 제한을 동일하게 적용한다.

### Step D: 트리거 매트릭스 (악용 가능성 분류)

| 입력 위치 | HTTP 메서드 | 트리거 라벨 | 외부 공격자 트리거 경로 |
|---|---|---|---|
| Query / fragment | GET | `LINK` | 링크 1개로 피해자 트리거 |
| Form body | POST (`application/x-www-form-urlencoded`, `multipart/form-data`) | `FORM` | auto-submit `<form>` (CSRF형) |
| JSON/XML body | POST/PUT/DELETE (`application/json` 등) | `SCRIPT` | preflight 발생, 동일 origin 코드 실행 필요 |
| Header (Referer/Host/Custom) | 무관 | `HEADER` | 직접 HTTP 클라이언트 필요 |
| 인증 사용자 자신의 입력 | 무관 | `SELF` | 본인 입력 (Stored면 별도 표시) |
| 종점 미도달 | - | `UNKNOWN` | Step C-3 (순환/외부 경계) |

### Step E: 트리거 가능성 보정
- **CSRF 토큰 미적용**: `FORM` → 사실상 `LINK`
- **CORS cross-origin + credentials 허용**: `SCRIPT` → 사실상 `LINK`
- **SameSite=None/미설정 + 쿠키 인증**: `FORM` 격상
- **Bearer/Authorization 헤더 인증**: SameSite 무관, `FORM`/`SCRIPT` 격상
- **모바일 앱/S2S가 1차 사용자**: `HEADER` 격상
- **CDN/프록시가 헤더 다시 쓰는 경로**: `HEADER` 격상

보정 결과는 보고서에 명시 (`SCRIPT → LINK (CORS *,credentials)` 형식).

### Step F: 위협 모델 명시
- 외부 공격자 → 일반 사용자 (기본)
- 악의적 내부자 / 침해된 파트너
- 악의적 사용자 → 다른 사용자 (Stored): Step C에서 저장소 경로 발견 + 읽는 측이 다른 사용자
- 서버 간 호출 (S2S)

### Step G: 판정

| 보정 후 라벨 | 위협 모델 적용 | 판정 |
|---|---|---|
| `LINK` | 임의 | **후보 유지** |
| `FORM` (보정 전) | 외부 공격자 | **후보 유지** |
| `SCRIPT` (보정 전) | 외부 공격자만 | **제외 가능** (단, 동일 페이지 XSS 후보 존재 시 "체인 후보"로 유지) |
| `SCRIPT` (보정 후 격상) | 임의 | **후보 유지** |
| `HEADER` | 외부 공격자만 | **제외 가능** |
| `HEADER` (격상 또는 S2S/내부자) | 적용 모델 있음 | **후보 유지** |
| `SELF` | Stored 활성화 | **후보 유지** (2차 피해자) |
| `SELF` | Stored 미적용 | **후보 제외** |
| `UNKNOWN` | 임의 | **추적 한계 후보**로 별도 분류 |

"추적 한계 후보"는 일반 후보와 분리. 어디서 멈췄는지(파일:라인), 멈춘 사유(Step C 종료 조건), 추가 정보 시 재평가 가능성을 명시.

## 후보 판정 제한

보고서에는 모든 후보에 대해: (1) Source 역추적 경로 단계별 파일:라인, (2) 최종 도달 source + 매트릭스 라벨 (보정 전/후), (3) 적용 위협 모델, (4) 판정 근거.
