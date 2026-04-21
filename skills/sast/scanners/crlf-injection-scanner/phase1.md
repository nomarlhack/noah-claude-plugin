---
id_prefix: CRLF
grep_patterns:
  - "res\\.setHeader\\s*\\("
  - "res\\.writeHead\\s*\\("
  - "res\\.header\\s*\\("
  - "res\\.set\\s*\\("
  - "res\\.cookie\\s*\\("
  - "res\\.attachment\\s*\\("
  - "response\\.headers\\["
  - "response\\.set_cookie\\s*\\("
  - "HttpResponseRedirect\\s*\\("
  - "response\\.setHeader\\s*\\("
  - "response\\.addHeader\\s*\\("
  - "redirect_to"
  - "cookies\\["
  - "header\\s*\\("
  - "setcookie\\s*\\("
  - "@RequestParam"
  - "@RequestBody"
  - "req\\.query"
  - "req\\.body"
---

> ## 핵심 원칙: "헤더가 분리되지 않으면 취약점이 아니다"
>
> `res.setHeader('Location', userInput)`이 있다고 CRLF Injection이 아니다. `\r\n`이 실제로 헤더에 삽입되어 응답이 분리되거나 새 헤더/본문이 추가되어야 한다. **대부분 최신 런타임은 헤더값에 개행이 들어가면 차단**하므로, 프레임워크 버전 확인이 핵심이다.

## Sink 의미론

CRLF Injection sink는 "사용자 입력이 HTTP 응답 헤더값에 도달하고, 런타임이 개행 검증을 하지 않거나 우회 가능한 지점"이다.

| 런타임 | 내장 방어 도입 시점 |
|---|---|
| Node.js | v4.6.0+ `http.ServerResponse`에서 `\r`/`\n` 차단 (`ERR_INVALID_CHAR`) |
| Express/Next.js | Node.js HTTP 모듈 의존 → Node 버전에 종속 |
| Python Django | 1.x+ `HttpResponse` 헤더값 개행 차단 |
| Python Flask/Werkzeug | 0.9+ 차단 |
| Java Spring | 5.x+ `HttpServletResponse` 차단 (Tomcat/Jetty도 차단) |
| Ruby Rails | 5.x+ 차단 |
| PHP | 5.1.2+ `header()` 개행 차단, 8.0+ 완전 차단 |

| 언어 | sink 함수 |
|---|---|
| Node/Express | `res.setHeader`, `res.writeHead`, `res.header`, `res.set`, `res.redirect`, `res.cookie`, `res.attachment` |
| Next.js | `ctx.res.setHeader`, `getServerSideProps` headers, `next.config.js` `headers()` |
| Django | `HttpResponse['H']`, `set_cookie`, `HttpResponseRedirect` |
| Flask | `response.headers['H']`, `make_response`, `redirect` |
| Spring | `response.setHeader`, `addHeader`, `sendRedirect` |
| Rails | `response.headers['H']`, `redirect_to`, `cookies[]` |
| PHP | `header()`, `setcookie()` |
| Go | `w.Header().Set(...)`, `w.Header().Add(...)`, `http.SetCookie(w, &http.Cookie{Value: x})` (Go 1.8+ 차단) |
| C#/.NET | `Response.Headers.Add(...)`, `Response.Cookies.Append(...)` (.NET Core는 차단) |
| Rust | `hyper::header::HeaderValue::from_str(x)` (`\r\n` 포함 시 Err 반환 — 안전) |

## Source-first 추가 패턴

- 리다이렉트 URL 파라미터 (open-redirect와 겹침)
- `Set-Cookie` 값에 사용자 입력 반영 (사용자명, 언어 코드 등)
- `Content-Disposition` filename (다운로드명에 업로드 원본 파일명)
- 커스텀 응답 헤더 (`X-User-Name`, `X-Locale`)
- CORS `Access-Control-Allow-Origin`이 동적으로 결정
- `Link`/`Refresh` 헤더

## 자주 놓치는 패턴 (Frequently Missed)

- **레거시 런타임**: Node.js < 4.6.0, PHP < 5.1.2, Java < Servlet 3.1 — 내장 방어 없음.
- **URL-encoded CRLF**: `%0d%0a` — 디코딩이 헤더 설정 후/전 어디서 일어나는지 확인. 직접 디코딩하는 코드 존재 시 후보.
- **Double encoding**: `%250d%250a` — 일부 프록시가 디코딩.
- **Unicode CRLF (`\u000d\u000a`)**: 일부 파서가 정규화.
- **`Content-Disposition` filename**: filename에 `\r\n`이 들어가면 헤더 split. RFC 6266 인코딩(`filename*=UTF-8''...`) 미적용 시 위험.
- **로그 인젝션**: HTTP 응답 split이 아니어도 로그 파일에 CRLF 삽입으로 가짜 로그 생성. 별도 라벨.
- **3rd-party HTTP 클라이언트 라이브러리에서 outgoing 요청 헤더 split**: 사용자 입력이 outgoing 요청의 헤더값으로 들어가는 경우 (SSRF 변형).
- **`raw` 응답 작성**: `res.write("HTTP/1.1 ...\r\n...")` 형태로 raw 응답을 직접 작성하면 런타임 방어 우회.
- **HTTP/2 환경**: HTTP/2는 바이너리 프레이밍이라 CRLF split 자체는 불가능 — 단, gateway가 HTTP/1.1로 변환하면 다시 노출.
- **Cookie value에 `;`/`,` 삽입**: 헤더 split은 아니지만 cookie 분리. RFC 6265 미준수 라이브러리.
- **SMTP/LDAP 헤더 인젝션**: 메일 발송 시 `To:` 헤더에 CRLF 삽입 → 추가 수신자. LDAP bind DN에 CRLF.
- **Redis/Memcached protocol injection**: 키/값에 `\r\n` → 추가 명령어 실행 (Redis `SET`/`FLUSHALL`).
- **AWS S3 metadata `x-amz-meta-*`**: 사용자 입력이 메타데이터 헤더값이면 CRLF로 추가 요청.
- **Log4j/Winston 로거 CRLF**: 로그 파일 형식을 위조해 SIEM/분석 도구 혼란 유발.

## 안전 패턴 (FP Guard)

- **현대 런타임 (위 표 기준 이상 버전)** + 코드가 런타임 API를 거쳐 헤더 설정.
- **헤더 설정 전 명시적 `\r`/`\n` 제거 또는 검증**.
- **`Content-Disposition` RFC 6266 인코딩** 사용.
- **화이트리스트 검증** (예: language 코드 `^[a-z]{2}(-[A-Z]{2})?$`).

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `\r\n` 차단만 | 가능 | `\n` 단독 (LF only — 일부 서버 허용), `\r` 단독 |
| URL-encoded 차단 (`%0d%0a`) | 가능 | Double encoding (`%250d%250a`), Unicode (`\u000d\u000a`), UTF-8 overlong |
| `replace("\\r\\n", "")` | 가능 | 순차 replace 후 `\n`/`\r` 단독 잔존. Split/filter 후 `%0a` 우회 |
| 런타임 내장 방어 (Node 4.6+, PHP 8+) | 부분 가능 | `res.write()` 같은 raw 작성 시 우회. HTTP/2 환경에서 HTTP/1.1 변환 gateway 있으면 노출 |
| Content-Disposition RFC 5987 | 부분 가능 | `filename*=UTF-8''...` 적용 안 하면 원본 filename에 CRLF 가능 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → 헤더 sink + 레거시 런타임 (위 표 미만) | 후보 |
| 현대 런타임 + 헤더 sink + 검증 없음 | 후보 유지 (런타임 우회 가능성, 라벨: `RUNTIME_DEPENDENT`) |
| `res.write` 등으로 raw 응답 직접 작성 | 후보 |
| 명시적 `\r`/`\n` 제거 확인 | 제외 |
| 화이트리스트 통과 후 사용 | 제외 |
| Outgoing HTTP 헤더값에 입력 직접 삽입 | 후보 (라벨: `OUTGOING_HEADER`) |
| 로그 파일에 사용자 입력 직접 기록 (CRLF 미제거) | 후보 (라벨: `LOG_INJECTION`) |

## 후보 판정 제한

사용자 입력이 HTTP 응답 헤더에 반영되는 경우 후보. 프레임워크 내장 방어 + 인코딩 적용이 확인되면 제외. 확인 불가하면 후보 유지.
