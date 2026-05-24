---
id_prefix: HMT
rules_dir: rules/
---

> ## 핵심 원칙: "메서드 변경으로 보안이 우회되어야 취약점이다"
>
> 405가 아닌 200을 받는 것만으로는 부족하다. HTTP 메서드를 변경했을 때 인증/인가가 실제로 우회되어 보호된 리소스에 접근하거나 상태를 변경할 수 있어야 한다.

## Sink 의미론

HTTP Method Tampering sink는 "라우트의 일부 메서드에는 인증/인가 미들웨어가 적용되고, 다른 메서드에는 적용되지 않거나 다르게 적용되는 지점"이다. 또는 method override 헤더(`X-HTTP-Method-Override`, `_method`)가 미들웨어 검증을 우회하는 지점.

| 프레임워크 | 라우트 정의 패턴 |
|---|---|
| Express | `app.get/post/put/delete`, `app.all`, `app.use`, `router.route('/p').get(...).post(...)` |
| Next.js API | `pages/api/` 핸들러의 `req.method` 분기 |
| Django | `@require_http_methods`, CBV `http_method_names`, `if request.method == 'POST'` 수동 |
| Spring | `@GetMapping`/`@PostMapping`/`@RequestMapping(method=...)`, `@RequestMapping` (메서드 미지정 → 모든 메서드 허용) |
| Rails | `routes.rb` `get`/`post`/`resources`, `match ... via:` |
| FastAPI | `@app.get/post/...`, `@app.api_route(methods=[...])` |

## Source-first 추가 패턴

- 인증 미들웨어 라우트별 적용 코드 (`app.post('/admin', auth, handler)`)
- `app.all(...)` vs `app.get(...)` 혼용
- `req.method === 'POST'` 분기에서만 권한 체크
- Next.js `pages/api/` 핸들러에서 method 분기 누락
- Spring `@RequestMapping`에 method 미지정
- nginx `limit_except` / Apache `<LimitExcept>` 설정
- Rack/Express `method-override` 미들웨어
- 커스텀 `X-HTTP-Method-Override`/`X-Method-Override`/`_method` 처리

## 자주 놓치는 패턴 (Frequently Missed)

- **`app.post('/admin', auth, ...)` + `app.get('/admin', ...)` 인증 누락**: GET으로 같은 라우트 호출 시 인증 미적용.
- **Spring `@RequestMapping("/admin")` 메서드 미지정**: 모든 HTTP 메서드(`HEAD`/`OPTIONS`/`TRACE` 포함) 허용. Spring Security가 `HttpMethod.GET`만 보호하면 우회.
- **Next.js API route에서 `req.method` 분기 누락**: GET/POST/PUT/DELETE 모두 동일 핸들러 → DELETE로 호출 시 의도치 않은 동작.
- **`HEAD` 메서드 우회**: 일부 미들웨어가 GET만 검사. `HEAD`는 GET과 동일 핸들러 호출이지만 미들웨어에서 미체크.
- **`OPTIONS` preflight 핸들러가 인증 우회**: CORS 처리 시 OPTIONS는 인증 통과시키는 패턴이 다른 메서드로 누설.
- **`TRACE` 메서드** (Cross-Site Tracing): 헤더 echo로 HttpOnly 쿠키 노출. 대부분 비활성화되어 있으나 잔존.
- **`method-override` 미들웨어 + 인증 미들웨어 순서**: override가 인증 후에 적용되면, 인증은 GET으로 통과 → 핸들러는 DELETE로 동작.
- **`_method` 폼 필드**: Rails `Rack::MethodOverride` 기본 활성. CSRF 토큰 검증이 GET에 적용 안 되면 form으로 우회.
- **`X-HTTP-Method-Override: PUT` + GET**: WAF가 GET만 검사.
- **case sensitivity**: `Get`/`get`/`GET` 처리. 일부 파서가 다르게 인식.
- **숨겨진 메서드** (`PROPFIND`, `MKCOL` 등 WebDAV): 활성화된 백엔드에서 의도치 않게 동작.
- **gateway/CDN과 백엔드의 메서드 처리 차이**: gateway는 GET 허용, 백엔드는 모두 허용 → gateway 우회.
- **Reverse proxy `proxy_method` 변경 미들웨어**: gateway가 메서드 변환.
- **GraphQL endpoint**: GET vs POST에 따라 mutation 허용 차이.
- **HTTP/2 `:method` pseudo-header**: HTTP/1.1 Method와 다른 경로 — 일부 서버/gateway 처리 차이.
- **`CONNECT` 메서드 남용**: 일부 프록시 환경에서 raw tunnel 생성 가능.
- **WebDAV 메서드 (`PROPFIND`, `COPY`, `MOVE`, `LOCK`)**: 활성화 잔존 시 의도치 않게 파일 조작.
- **Kubernetes API `PATCH` vs `PUT`**: strategic merge patch가 의도와 다르게 객체 수정.

## 안전 패턴 (FP Guard)

- **`app.use('/admin', authMiddleware)` + `app.use('/admin', adminRouter)`**: 라우터 단위 미들웨어 → 모든 메서드에 적용.
- **`router.all('/admin/*', authMiddleware)`** (Express).
- **Spring Security `antMatchers("/admin/**").authenticated()`**: 메서드 무관 매칭.
- **Django `LoginRequiredMixin` 또는 `dispatch` 오버라이드**: CBV 모든 메서드에 적용.
- **명시적 메서드 화이트리스트**: `if (req.method !== 'POST') return res.status(405).end()`.
- **method-override 미들웨어 미사용** 또는 인증 후 적용.
- **CSRF 미들웨어가 모든 unsafe method (POST/PUT/DELETE/PATCH)에 적용**.
- **gateway/WAF에서 메서드 화이트리스트** (`limit_except GET POST { deny all; }`).

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| GET/POST만 화이트리스트 | 가능 | `HEAD`는 GET 핸들러 호출 (응답 본문만 생략) — GET 핸들러에 상태 변경 로직이 있으면 HEAD로 트리거 |
| method-override 미들웨어 비활성화 | 부분 가능 | 프레임워크 기본 활성 (Rails `Rack::MethodOverride`) 잔존 가능 |
| 인증 미들웨어 적용 후 method-override | 가능 | 적용 순서가 역전되면 인증 GET 통과 → override로 DELETE |
| Spring Security `.antMatchers("/x", POST)` | 가능 | 다른 메서드(GET/PUT/DELETE 등) 누락 — `HttpMethod.GET` 별도 설정 |
| gateway가 특정 메서드만 허용 | 부분 가능 | gateway-backend 메서드 처리 차이 — HTTP smuggling 결합 시 우회 |
| Case-sensitive 메서드 검증 | 가능 | `get`/`Get`/`GET` 중 하나만 차단, 대소문자 변형 통과 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 라우트의 일부 메서드에만 인증 미들웨어 적용 | 후보 |
| `app.all`/`app.use` 사용하지만 일부 핸들러가 별도 등록 | 후보 |
| Spring `@RequestMapping` 메서드 미지정 + 보안 설정도 메서드 미지정 | 후보 |
| Next.js API route에서 `req.method` 분기 없음 + 권한 체크도 없음 | 후보 |
| method-override 미들웨어가 인증 미들웨어 이후에 적용 | 후보 (라벨: `OVERRIDE_BYPASS`) |
| HEAD/OPTIONS가 GET 핸들러 호출 + 인증 미체크 | 후보 (라벨: `HEAD_BYPASS`) |
| 모든 메서드에 동일 미들웨어 chain 확인 | 제외 |
| CSRF 토큰이 모든 unsafe method에 적용 | 제외 (CSRF 한정) |

## 후보 판정 제한

라우트별 메서드 적용에 차이가 있고, 그 차이가 인증/인가/CSRF 보호에 영향을 미치는 경우만 후보.
