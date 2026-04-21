---
id_prefix: CSRF
grep_patterns:
  - "csrf_exempt"
  - "skip_before_action.*verify_authenticity_token"
  - "csrf\\.disable"
  - "csurf"
  - "csrf-csrf"
  - "csrf-sync"
  - "protect_from_forgery"
  - "SameSite"
  - "X-CSRF-Token"
  - "X-Requested-With"
  - "verify_authenticity_token"
  - "@csrf_exempt"
  - "csrf\\s*\\(\\s*\\)\\.disable"
  - "@PostMapping"
  - "@PutMapping"
  - "@DeleteMapping"
  - "WebSecurityConfigurerAdapter"
  - "SecurityFilterChain"
  - "HttpSecurity"
  - "ignoringRequestMatchers"
---

> ## 핵심 원칙: "위조된 cross-origin 요청이 처리되지 않으면 취약점이 아니다"
>
> CSRF 토큰이 없다고 즉시 취약점이 아니다. SameSite 쿠키, Origin/Referer 검증, 커스텀 헤더 등 다른 방어가 있을 수 있다. 외부 사이트에서 위조된 요청이 실제로 서버에 처리되어야 한다.

## Sink 의미론

CSRF sink는 "쿠키 기반 인증으로 호출되는 상태 변경 엔드포인트인데 cross-origin 요청 차단 메커니즘이 없는 지점"이다. Bearer 토큰만 사용하는 API는 브라우저가 자동 첨부하지 않으므로 sink 아님.

| 프레임워크 | 내장 방어 |
|---|---|
| Express | `csurf` (deprecated), `csrf-csrf`, `csrf-sync` — 명시 적용 필요 |
| Next.js / React SPA | 기본 방어 없음 — API 라우트에 별도 구현 |
| Django | `CsrfViewMiddleware` 기본 활성, `@csrf_exempt`로 비활성화 가능 |
| Spring | `CsrfFilter` 기본 활성 (Spring Security), `csrf().disable()`로 비활성 |
| Rails | `protect_from_forgery` 기본 활성, `skip_before_action :verify_authenticity_token` |
| Laravel | `VerifyCsrfToken` 기본 활성, `$except` 배열로 제외 |
| Flask | `Flask-WTF` 또는 직접 구현 |
| FastAPI | 기본 방어 없음 |
| Go (Gin/Echo/Chi) | 기본 방어 없음 — `gorilla/csrf` 미들웨어 명시 적용 필요 |
| Phoenix (Elixir) | `Plug.CSRFProtection` 기본 활성, `:protect_from_forgery` plug |
| ASP.NET Core | `AddAntiforgery()` + `[ValidateAntiForgeryToken]` 또는 `[AutoValidateAntiforgeryToken]` |
| Nest.js | 기본 방어 없음 — `csurf`/`csrf-csrf` 명시 적용 |

## Source-first 추가 패턴

- POST/PUT/DELETE/PATCH 라우트 중 쿠키 인증 사용
- 비밀번호 변경 endpoint
- 이메일 변경 endpoint
- 결제/주문/취소
- 관리자 권한 변경
- 게시글 작성/수정/삭제
- GET으로 상태 변경하는 endpoint (안티 패턴이지만 흔함)
- API gateway에서 쿠키 통과하는 라우트
- WebSocket upgrade (CSWSH)

## 자주 놓치는 패턴 (Frequently Missed)

- **GET으로 상태 변경**: SameSite=Lax도 GET cross-site 허용 (top-level navigation). `<img src="...">`로도 트리거.
- **`SameSite` 미설정 (Lax 기본 적용은 Chrome 80+ 한정)**: 구버전 브라우저/Safari 일부에서 None 동작.
- **`SameSite=None; Secure`**: 명시 None은 cross-site 허용 → CSRF 가능. 의도적이지 않은 경우 후보.
- **CSRF 토큰을 cookie에 저장하지만 검증 시 body/header에서 안 받음**: double submit cookie 패턴 미완성.
- **CSRF 토큰이 사용자 세션과 무관하게 전역 동일**: 토큰 추출 후 재사용.
- **`@csrf_exempt`/`csrf().disable()` 광범위 적용**: 디버깅 후 잔존.
- **API JSON endpoint가 쿠키 인증 + Content-Type 검증 없음**: `Content-Type: text/plain`으로 cross-origin POST 가능 (CORS preflight 우회).
- **CORS `Access-Control-Allow-Origin: *` + `Allow-Credentials: true`**: 사양상 불가능 조합이지만 일부 잘못 설정. 또는 `Origin` echo + credentials.
- **CORS Origin 화이트리스트가 substring match**: `evil-allowed.com.attacker.com` 통과.
- **Origin 검증 시 null origin 허용**: `<iframe sandbox>` → `Origin: null`.
- **Subdomain takeover로 same-site 우회**: 신뢰 서브도메인 takeover → CSRF 가능.
- **CSWSH (Cross-Site WebSocket Hijacking)**: WebSocket handshake에 SameSite 미적용 (구 브라우저).
- **Login CSRF**: 공격자 계정으로 피해자 강제 로그인. 로그인 endpoint에 CSRF 토큰 미적용.
- **Logout CSRF**: 강제 로그아웃 (DoS).
- **Flash CSRF (`crossdomain.xml`)**: 레거시.
- **HTTP 메서드 override + CSRF skip 차이**: method-tampering과 결합 — POST에는 CSRF 검증, GET → method override → POST 동작.
- **GraphQL endpoint**: GET vs POST 처리 다름. mutation을 GET으로 허용하면 CSRF.
- **Multipart form-data CSRF**: preflight 트리거 안 되는 simple request.
- **JSON CSRF via Flash/구 브라우저**: 현대 브라우저는 막히지만 레거시.
- **`/admin/*` 라우트에 CSRF 미적용** (다른 인증 방식 가정).
- **Referer 단독 검증**: `Referrer-Policy: no-referrer` 메타 태그/링크 속성으로 Referer 제거 가능 → 검증 우회.
- **Token rotation 없음 (정적 token)**: 세션 동안 동일 토큰 → 한번 노출되면 영구 사용. XSS/Referer 누출 시 위험.
- **CSRF token이 GET URL에 포함**: 응답 페이지에서 외부 링크 클릭 시 Referer로 token 누출.
- **method override (POST `_method=DELETE`)와 CSRF 적용 범위 불일치**: POST에 CSRF 검증, override 후 DELETE 동작이 검증 우회.

## 안전 패턴 (FP Guard)

- **세션 쿠키 `SameSite=Strict` 또는 `Lax`** + 모든 unsafe method가 POST 이상.
- **CSRF 토큰 검증 미들웨어 + 세션별 unique** + body/header에서 검증.
- **Double submit cookie + 토큰 일치 검증**.
- **`Authorization: Bearer` 헤더만 사용** (쿠키 없음): CSRF 면역.
- **Origin/Referer 화이트리스트 검증** (모든 unsafe method).
- **Content-Type `application/json` 강제 + simple request 차단**: preflight 발생 → CORS 보호.
- **`X-Requested-With` 같은 커스텀 헤더 요구**: simple request 아니므로 preflight.
- **`Sec-Fetch-Site` 헤더 검증**: 모던 브라우저(Chrome/Firefox/Safari)가 자동 첨부. `cross-site` 차단으로 방어.
- **HMAC-signed CSRF token (서버 무상태)**: `HMAC(secret, sessionId + nonce)` 검증.
- **Per-request one-time token**: 토큰을 1회 사용 후 무효화 — 노출 영향 최소화.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| Naive double submit (cookie와 body 일치만 검증) | 가능 | 공격자가 임의 token을 cookie와 body에 동일 값으로 설정 (cookie 주입 가능 시) — HMAC 미적용이면 임의 값 통과 |
| Origin 화이트리스트 substring/prefix match | 가능 | `startsWith("https://example.com")` → `https://example.com.attacker.com` 또는 `evil-example.com` 통과 |
| Referer 단독 검증 | 가능 | `<meta name="referrer" content="no-referrer">`, `rel="noreferrer"`, HTTPS→HTTP 다운그레이드로 Referer 제거 |
| `SameSite=Lax` (기본값) + GET 상태 변경 | 가능 | Lax는 top-level GET 허용 — `<a>` 클릭/`<img src>` 트리거 |
| 토큰 검증을 unsafe method 일부에만 적용 | 가능 | POST에만 적용, PUT/DELETE/PATCH 누락. method override 결합 가능 |
| 토큰을 GET URL/body에서 모두 받음 | 가능 | GET URL에 포함된 토큰이 Referer로 외부 누출 → 재사용 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 쿠키 인증 + unsafe method + CSRF 토큰/SameSite/Origin 검증 모두 없음 | 후보 |
| GET으로 상태 변경 + 쿠키 인증 + SameSite=Lax | 후보 (Lax는 GET 허용) |
| `SameSite=None; Secure` 명시 + CSRF 토큰 없음 | 후보 |
| `@csrf_exempt`/`csrf().disable()` 적용 + unsafe method | 후보 |
| Bearer 토큰만 + 쿠키 미사용 | 제외 |
| `SameSite=Strict` + 쿠키 인증 | 제외 (단 이메일 링크 first request 사용성 제약) |
| CSRF 토큰 검증 확인 + 세션별 unique | 제외 |
| Login endpoint에 CSRF 미적용 | 후보 (라벨: `LOGIN_CSRF`) |
| WebSocket handshake에 Origin 검증 없음 | 후보 (라벨: `CSWSH`) |
| GraphQL mutation을 GET으로 허용 | 후보 |

## 후보 판정 제한

쿠키만으로 인증이 완료되는 endpoint만 후보. 커스텀 헤더 기반 인증/Bearer 토큰은 CSRF 면역이므로 제외.
