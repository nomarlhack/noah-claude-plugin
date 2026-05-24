---
id_prefix: OAUTH
rules_dir: rules/
---

> ## 핵심 원칙: "OAuth 흐름 조작으로 인증이 우회되어야 취약점이다"
>
> `state` 미검증 자체가 즉시 취약점이 아니다. 공격자가 흐름을 조작하여 다른 계정 접근, 인가 코드 탈취, 토큰 발급 우회 등 실제 영향이 발생해야 한다.

## Sink 의미론

OAuth sink는 "OAuth 흐름의 검증 단계(state/nonce/PKCE/redirect_uri 검증, 토큰 교환, id_token 검증)에서 검증이 누락되거나 우회 가능한 지점"이다.

| 언어 | 라이브러리 |
|---|---|
| Node | `passport-oauth2`, `passport-google-oauth20`, `passport-kakao`, `openid-client`, `next-auth`/`auth.js`, `grant`, 직접 구현 |
| Python | `authlib`, `python-social-auth`/`social-django`, `oauthlib` + `requests-oauthlib`, `Flask-OAuthlib`, `Flask-Dance` |
| Java | Spring Security OAuth2 (`spring-boot-starter-oauth2-client`), `scribejava` |
| Ruby | `omniauth` + provider gems |
| PHP | `league/oauth2-client`, `hybridauth` |

**검증 차원:**
1. `state` 생성 + 세션 저장 + 콜백에서 비교
2. `nonce` (OIDC) 생성 + id_token에서 비교
3. PKCE `code_challenge`/`code_verifier` (public client/모바일/SPA 필수)
4. `redirect_uri` 정확 매칭 (exact match, 등록된 URI만)
5. `id_token` 서명/iss/aud/exp/nonce 검증
6. token scope 검증
7. 인가 코드 1회용 강제 (provider 책임이지만 client도 race 처리)

## Source-first 추가 패턴

- OAuth callback 라우트 (`/auth/callback`, `/oauth/callback`, `/auth/google/callback`)
- `passport.authenticate('strategy', ...)` 호출
- `next-auth` `[...nextauth].ts`
- `redirect_uri` 동적 생성 코드
- `state` 생성/저장 코드
- `id_token` 검증 코드
- token 교환 (`/token` endpoint POST)
- 사용자 정보 endpoint (`/userinfo`) 호출
- 클라이언트 시크릿 사용 코드

## 자주 놓치는 패턴 (Frequently Missed)

- **`state` 미검증 = CSRF 로그인 고정**: 공격자가 자기 인가 코드를 피해자 브라우저에 강제 → 피해자가 공격자 계정에 로그인 → 공격자가 다시 입장 시 피해자 데이터 본인 계정에 저장.
- **`state` 검증하지만 세션 외 위치 (URL/쿠키 client-side)**: 공격자가 양쪽 모두 제어 가능.
- **`state`가 예측 가능 (timestamp, sequential)**: 우회.
- **PKCE 미적용 (모바일/SPA)**: 인가 코드 가로채기. RFC 7636 권고.
- **PKCE `plain` 메서드**: SHA256 강제 필요.
- **`redirect_uri` 부분 매칭/와일드카드**: `https://app.com/callback`이 등록되어 있는데 `https://app.com/callback/../../evil`도 통과.
- **`redirect_uri` 검증을 authorization request에서만 수행, token request에서 누락**: 같은 URI를 두 요청 모두에 검증해야 RFC 6749.
- **`redirect_uri`에 사용자 입력 path 추가**: `https://app.com/callback?next=evil` → 콜백 후 `next`로 redirect (open-redirect 결합).
- **`id_token` 서명 미검증**: JWT scanner와 겹치지만 OIDC 컨텍스트에서 특히 주의.
- **`id_token` `aud`가 자기 client_id가 아닌데 통과**.
- **`id_token` `nonce` 미검증**: replay 가능.
- **`id_token` `iss` 미검증**: 다른 IdP 토큰 통과.
- **Authorization Code 재사용**: client는 한 번 교환 후 재사용 불가하지만, race로 두 번 교환 시도. provider 측 책임이지만 client 코드에 race window 있으면 후보.
- **Client secret이 SPA 코드에 노출**: public client는 시크릿 없음 (PKCE 사용해야).
- **`response_type=token` (Implicit Flow)**: deprecated. 모바일/SPA는 Authorization Code + PKCE.
- **`scope` 검증 누락**: 발급된 토큰 scope이 요청과 다른지 확인 안 함 → 권한 상승.
- **로그인 후 세션 fixation**: OAuth 콜백 처리 시 session ID 회전 안 함.
- **`prompt=none`** + 광범위 권한: 무경고 인증.
- **사용자 동의 화면 우회** (`require_consent` 조작).
- **Account linking 취약점**: 동일 이메일을 가진 다른 IdP 계정을 자동 연결 → 이메일 검증 안 한 IdP로 takeover.
- **Refresh token rotation 없음**: 탈취된 refresh token 영구.
- **Logout 시 IdP session 미종료**: SLO 미구현.
- **Authorization endpoint에 추가 파라미터 인젝션**: `redirect_uri=...&prompt=none&login_hint=victim@x`.
- **Mix-up attack (다중 IdP)**: 여러 IdP 지원 환경에서 공격자가 IdP 응답을 다른 IdP로 속여 인가 코드 교환 — iss 검증으로 방어.
- **Covert redirect (RFC 6749 §10.15)**: 사용자 동의 후 redirect_uri fragment에 token 노출.
- **FAPI (Financial-grade API) 요구 미준수**: PAR (Pushed Authorization Request), JARM (JWT-secured Authorization Response Mode) 등 강화 요구 누락.
- **Device Authorization Grant (RFC 8628) user_code 추측**: 짧은 user_code의 brute force.
- **Token introspection response 캐싱**: 폐기된 토큰이 캐시로 유효 유지.

## 안전 패턴 (FP Guard)

- **`state` 생성 (CSPRNG) + 세션 저장 + 콜백에서 strict 비교**.
- **PKCE S256** (모든 client).
- **`redirect_uri` 등록 목록과 strict equal**.
- **OIDC `id_token` 검증**: 서명 + iss + aud (== client_id) + exp + nonce.
- **외부 OIDC 라이브러리에 위임** (`openid-client`, `authlib`) + 옵션을 strict로.
- **세션 fixation 방어**: 콜백 후 `req.session.regenerate()`.
- **Account linking은 이메일 verified 플래그 확인** + 사용자 명시 동의.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `redirect_uri` prefix 매칭 | 가능 | `https://app.com/callback` 등록 → `https://app.com/callback/../../evil`, `https://app.com/callback?@evil.com` 통과 |
| `state` 값을 예측 가능하게 생성 | 가능 | timestamp/sequential — 공격자가 동일 값 예측 가능 |
| `state` 값을 세션 아닌 쿠키로 저장 | 가능 | 공격자가 쿠키 주입 가능하면 양쪽 모두 제어 |
| PKCE S256 적용했지만 `code_verifier` 예측 가능 | 가능 | verifier가 약한 난수(Math.random)면 brute force |
| id_token `iss` 검증 후 `aud` 누락 | 가능 | 다른 client용 토큰 재사용 (audience confusion) |
| Account linking + 이메일 verified 체크 | 부분 가능 | 일부 IdP의 verified 플래그 자체가 신뢰 불가 (자체 발행 플래그) |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| `state` 생성 또는 검증 누락 | 후보 (라벨: `STATE_MISSING`) |
| `state` 검증하지만 세션 외 저장소 | 후보 (라벨: `STATE_WEAK_STORAGE`) |
| 모바일/SPA에서 PKCE 미적용 | 후보 (라벨: `PKCE_MISSING`) |
| `redirect_uri` 부분 매칭/와일드카드 | 후보 (라벨: `REDIRECT_URI_LOOSE`) |
| `id_token` 검증 누락 (서명/iss/aud/nonce 중 하나) | 후보 (라벨: `IDTOKEN_VALIDATION`) |
| Account linking + 이메일 verified 미확인 | 후보 (라벨: `ACCOUNT_TAKEOVER`) |
| Implicit flow (`response_type=token`) | 후보 (라벨: `IMPLICIT`) |
| `openid-client` strict 옵션 사용 확인 | 제외 |
| 외부 BaaS (Auth0/Cognito/Firebase Auth) 위임 + client 코드는 token만 검증 | 라이브러리 옵션 확인 후 판단 |
| Client secret이 클라이언트 빌드에 포함 | 후보 (라벨: `SECRET_EXPOSURE`) |

## 후보 판정 제한

OAuth 프로토콜을 직접 구현하거나 검증 옵션이 결함인 코드만 후보. 외부 서비스에 완전 위임하는 경우 제외 (단 callback 코드는 확인).
