---
id_prefix: COOKIE
rules_dir: rules/
---

> ## 핵심 원칙: "민감 쿠키에 보안 속성이 누락되면 후보이다"
>
> 이 스캐너는 쿠키 설정 코드와 설정 파일을 분석하여, 세션/인증 쿠키에 보안 속성(Secure, HttpOnly, SameSite 등)이 올바르게 적용되었는지 점검한다. 또한 세션/인증 쿠키가 Persistent(Max-Age/Expires 설정)로 운용되는 경우의 탈취 위험을 평가한다.

## Sink 의미론

쿠키가 **설정(Set)되는 지점**이 Sink이다.

| 언어/프레임워크 | Sink API |
|----------------|----------|
| Java/Spring | `ResponseCookie.from()`, `new Cookie()` + `response.addCookie()`, `server.servlet.session.cookie.*` 설정 |
| Java/JAX-RS | `NewCookie()`, `Response.ok().cookie()` |
| Node.js/Express | `res.cookie()`, `res.setHeader('Set-Cookie', ...)`, `express-session` cookie 옵션 |
| Python/Django | `response.set_cookie()`, `settings.SESSION_COOKIE_*` |
| Python/Flask | `response.set_cookie()`, `app.config['SESSION_COOKIE_*']` |
| Python/FastAPI | `response.set_cookie()` |
| Ruby/Rails | `cookies[:name]=`, `cookies.permanent`, `Rails.application.config.session_store` 옵션 |
| PHP | `setcookie()`, `session_set_cookie_params()`, `php.ini session.cookie_*` |
| Go | `http.SetCookie()`, `http.Cookie{}` 구조체 |
| 클라이언트 JS | `document.cookie=` (서버 쿠키 설정은 아니지만, HttpOnly 미설정 쿠키 접근 경로로 참고) |

## Source-first 추가 패턴

패턴 인덱스 외에 아래 경로를 추가 탐색한다:
- 로그인/인증 핸들러 (세션 쿠키 발행 지점)
- remember-me / "로그인 유지" 기능 (Persistent 쿠키 발행 지점)
- OAuth 콜백 핸들러 (토큰 쿠키 저장 지점)
- 세션 미들웨어/설정 (글로벌 쿠키 옵션)

## 자주 놓치는 패턴 (Frequently Missed)

1. **remember-me Persistent 쿠키**: `maxAge: 30 * 24 * 60 * 60 * 1000` 같은 장기 유효 쿠키가 세션 ID를 그대로 저장
2. **서브도메인 쿠키 공유**: `domain: '.example.com'`으로 설정하여 다른 서브도메인에서 쿠키 접근 가능
3. **__Host- 접두사 오용**: `__Host-` 접두사를 쓰면서 `Domain` 속성을 설정 (브라우저가 거부하지만 의도와 다른 동작)
4. **프레임워크 기본값 오인**: Express `express-session`의 `cookie.secure` 기본값은 `false`
5. **개발/운영 설정 혼용**: `if (env === 'production') cookie.secure = true` 분기에서 else 경로 누락
6. **refresh_token 쿠키**: access_token은 메모리에 두면서 refresh_token을 쿠키에 저장할 때 보안 속성 누락
7. **Partitioned 쿠키 (CHIPS)**: Chrome 3rd-party cookie 차단 대응으로 `Partitioned` 속성 사용 — 속성 오용 시 세션 분리 실패
8. **Cookie Store API vs Set-Cookie 헤더 불일치**: 브라우저 Cookie Store API와 HTTP 헤더 설정 차이 — 동기화 누락
9. **Load balancer affinity cookie 보안 속성 누락**: AWS ALB `AWSALB`, nginx `sticky` 쿠키 — HttpOnly/Secure 자동 미적용
10. **Shared cookie via `document.domain` 설정**: 레거시 top-level domain 설정으로 의도치 않은 쿠키 공유
11. **Session fixation via pre-auth 쿠키**: 로그인 전 발급된 세션 ID가 로그인 후에도 유지 (session regenerate 누락)

---

## 점검 라벨 및 판정 테이블

### COOKIE_NO_SECURE

Secure 플래그가 없으면 HTTP 평문 통신에서 쿠키가 노출된다.

| 패턴 | 판정 |
|------|------|
| 민감 쿠키에 `secure: false` 또는 `secure` 미설정 | 후보 |
| `secure: true` 또는 프레임워크 설정에서 활성화 | 제외 |
| `__Secure-` 또는 `__Host-` 접두사 사용 | 제외 (브라우저가 Secure 강제) |

### COOKIE_NO_HTTPONLY

HttpOnly가 없으면 XSS 시 `document.cookie`로 세션 탈취가 가능하다.

| 패턴 | 판정 |
|------|------|
| 세션/인증 쿠키에 `httpOnly: false` 또는 미설정 | 후보 |
| `httpOnly: true` 또는 프레임워크 기본값이 true | 제외 |
| 클라이언트 JS에서 읽어야 하는 비세션 쿠키 (CSRF 토큰 등) | 제외 |

### COOKIE_SAMESITE_NONE

SameSite=None이면 cross-site 요청에 쿠키가 전송된다.

| 패턴 | 판정 |
|------|------|
| `sameSite: 'None'` 명시 | 후보 |
| `sameSite` 미설정 (브라우저 기본값 Lax) | 제외 |
| `sameSite: 'Lax'` 또는 `'Strict'` | 제외 |

### COOKIE_PERSISTENT

세션/인증 쿠키에 Max-Age 또는 Expires가 설정되면 브라우저를 닫아도 쿠키가 유지되어, 탈취 시 장기간 악용이 가능하다.

| 패턴 | 판정 |
|------|------|
| 세션/인증 쿠키에 `maxAge` > 0 또는 `expires` 설정 (7일 초과) | 후보 |
| `maxAge` 값이 7일 이하 | 제외 (단, 세션 쿠키 전환 권고 기재) |
| `maxAge` 미설정 또는 -1 (세션 쿠키 = 브라우저 종료 시 삭제) | 제외 |
| remember-me 전용 쿠키이며 별도 토큰(세션 ID 아닌)을 사용 | 제외 |
| Django `SESSION_COOKIE_AGE` 기본값 사용 (1209600초 = 2주) | 후보 |

**Persistent 쿠키 위험 시나리오:**
- 공용 PC에서 브라우저 종료 후에도 세션 유지
- 쿠키 탈취(XSS, 네트워크 스니핑) 시 장기간 유효
- 디바이스 분실 시 세션 재사용 가능

### COOKIE_LOOSE_SCOPE

| 패턴 | 판정 |
|------|------|
| `domain: '.example.com'` (상위 도메인으로 설정) | 후보 |
| `domain` 미설정 (현재 호스트에만 한정) | 제외 |
| `path: '/'` + 민감 쿠키 (하위 경로 한정 권고 상황) | 후보 판정 보류 — Path=/는 일반적이므로 단독으로는 후보 아님. Domain과 결합 시에만 후보. |

### COOKIE_PREFIX_MISUSE

`__Host-`/`__Secure-` 접두사는 브라우저가 쿠키 속성을 강제하는 메커니즘이다.

| 패턴 | 판정 |
|------|------|
| `__Host-` 접두사 사용 + `Domain` 속성 설정 (브라우저 거부) | 후보 |
| `__Host-` 접두사 사용 + `Path=/` + `Secure` + `Domain` 미설정 | 제외 (올바른 사용) |
| `__Secure-` 접두사 사용 + `Secure` 미설정 | 후보 |
| `__Secure-` 접두사 사용 + `Secure` 설정 | 제외 |
| 접두사 미사용 (일반 쿠키명) | 후보 아님 (접두사는 권고 사항) |

---

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 민감 쿠키에 `Secure` 플래그 없음 | 후보 (라벨: `COOKIE_NO_SECURE`) |
| 민감 쿠키에 `HttpOnly` 플래그 없음 | 후보 (라벨: `COOKIE_NO_HTTPONLY`) |
| 민감 쿠키에 `SameSite=None` 또는 미설정 + HTTPS | 후보 (라벨: `COOKIE_SAMESITE_NONE`) |
| 세션/인증 쿠키에 장기 `Max-Age`/`Expires` 설정 (24시간 초과) | 후보 (라벨: `COOKIE_PERSISTENT`) |
| 민감 쿠키 `Path`/`Domain`이 과도하게 넓음 | 후보 (라벨: `COOKIE_LOOSE_SCOPE`) |
| `__Secure-`/`__Host-` 접두사에 필수 속성 불일치 | 후보 (라벨: `COOKIE_PREFIX_MISUSE`) |
| 프레임워크 기본값이 안전 (Spring Boot `HttpOnly=true` 등) | 제외 |
| 비민감 쿠키 (`theme`, `lang`, `_ga` 등) 속성 누락 | 제외 |
| CSRF Double Submit 패턴용 HttpOnly 해제 (세션 쿠키 아님) | 제외 |
| 프록시 레벨에서 Secure 플래그 추가 확인 | 제외 |
| 환경 분기로 production에서만 Secure 설정 확인 | 제외 |

## 안전 패턴 (FP Guard)

- **프레임워크 기본 보안**: Spring Boot 2.x+ `HttpOnly=true` 기본, Django `SESSION_COOKIE_HTTPONLY=True` 기본, Rails 세션 쿠키 `HttpOnly=true` 기본
- **프록시 레벨 설정**: Nginx `proxy_cookie_flags`나 Cloudflare 등에서 Secure 플래그 추가
- **비민감 쿠키**: `theme`, `lang`, `locale`, `timezone`, `_ga`, `_gid`, `cookie_consent` 등 탈취 영향이 없는 쿠키
- **의도적 클라이언트 접근**: CSRF Double Submit 패턴에서 CSRF 토큰 쿠키를 JS가 읽도록 HttpOnly 해제 (세션 쿠키는 예외 없이 후보)
- **환경 분기 확인**: `if (process.env.NODE_ENV === 'production') secure: true` — production 경로에서 설정되면 제외

## 후보 판정 제한

- **비민감 쿠키에 대한 속성 누락은 후보가 아니다.** UI 설정, 분석 트래커 등은 점검 대상에서 제외.
- **민감 쿠키 판별 기준**: 쿠키 이름에 `session`, `sess`, `sid`, `token`, `auth`, `jwt`, `csrf`, `xsrf`, `remember`, `login`, `refresh` 포함. 또는 프레임워크 세션 쿠키 (`JSESSIONID`, `connect.sid`, `sessionid`, `PHPSESSID`).
- **프레임워크 기본값을 숙지한다.** 설정 파일에 명시되지 않아도 프레임워크 기본값이 안전하면 제외.
- **Persistent 쿠키 자체가 취약점은 아니다.** 세션/인증 쿠키가 Persistent인 경우에만 후보.
