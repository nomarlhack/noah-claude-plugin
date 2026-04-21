---
id_prefix: JWT
grep_patterns:
  - "jwt\\.verify\\s*\\("
  - "jwt\\.decode\\s*\\("
  - "jwt\\.sign\\s*\\("
  - "JWT\\.decode\\s*\\("
  - "JWT\\.encode\\s*\\("
  - "jsonwebtoken"
  - "express-jwt"
  - "passport-jwt"
  - "PyJWT"
  - "python-jose"
  - "ruby-jwt"
  - "firebase/php-jwt"
  - "ignoreExpiration"
  - "algorithms.*none"
  - "bearer"
  - "ExpiredJwtException"
  - "ExpiredSignatureError"
  - "TokenExpiredError"
  - "ExpiredSignature"
  - "parseClaimsJwt"
  - "parseSignedClaims"
  - "Jwts\\.parser"
  - "Jwts\\.builder"
  - "signWith"
  - "verifyWith"
  - "JWTVerifier"
  - "SignedJWT"
  - "\\bjose\\b"
  - "jose4j"
  - "nimbus-jose-jwt"
  - "secretOrKey"
  - "golang-jwt"
  - "jwt-go"
  - "jwt\\.Parse\\s*\\("
  - "jwt\\.ParseWithClaims\\s*\\("
  - "verify_signature.*false"
  - "verify\\s*=\\s*[Ff]alse"
  - "algorithms\\s*=\\s*\\[?\\s*['\"]none"
  - "alg\\s*:\\s*['\"]none"
---

> ## 핵심 원칙: "변조된 토큰이 수락되지 않으면 취약점이 아니다"
>
> JWT 라이브러리 사용 자체는 취약점이 아니다. 페이로드를 변조하거나 서명을 조작한 토큰을 서버가 유효하다고 수락하여 인증/인가가 우회되어야 한다.

## Sink 의미론

JWT sink는 "사용자 제공 토큰을 검증/디코딩하는 함수가 호출되며, 그 결과 클레임이 권한 결정에 사용되는 지점"이다. 검증 옵션 누락, 알고리즘 미명시, 서명 미검증 디코더 사용이 핵심 결함.

| 언어 | 라이브러리 | 검증 옵션 |
|---|---|---|
| Node | `jsonwebtoken` `jwt.verify(t, key, {algorithms: [...]})` | algorithms 미지정 시 헤더 alg 신뢰 |
| Node | `jose` (modern) | 기본 안전 |
| Node | `express-jwt`/`koa-jwt`/`passport-jwt` | strategy 옵션 |
| Python | `PyJWT` `jwt.decode(t, key, algorithms=[...], options={...})` | algorithms 필수 (최신 버전) |
| Python | `python-jose`, `authlib` | 동일 |
| Java | `jjwt` `parserBuilder().setSigningKey(...)` | `setSigningKeyResolver` 사용 시 신중 |
| Java | `nimbus-jose-jwt` `JWSVerifier` | 알고리즘 명시 |
| Java | `auth0/java-jwt` `JWT.require(Algorithm.X)` | Algorithm 객체로 강제 |
| Ruby | `ruby-jwt` `JWT.decode(t, key, true, {algorithm: 'X'})` | verify=false 위험 |
| PHP | `firebase/php-jwt` `JWT::decode(t, key, ['X'])` | 알고리즘 배열 필수 |
| Go | `golang-jwt/jwt` `jwt.Parse(t, keyFunc)` | keyFunc에서 alg 검증 필수 — `token.Method` 명시 확인 |
| Rust | `jsonwebtoken` `decode::<Claims>(t, &key, &Validation::new(Algorithm::RS256))` | `Validation` 명시 — 기본은 HS256 |
| C#/.NET | `JwtSecurityTokenHandler.ValidateToken(t, validationParameters)` | `ValidAlgorithms` 명시 권장 (.NET 6+) |

## Source-first 추가 패턴

- HTTP `Authorization: Bearer ...` 헤더
- 쿠키에 JWT 저장
- WebSocket 핸드셰이크 token 파라미터
- query string `?token=...` (안티 패턴이지만 흔함)
- 푸시 알림 토큰
- 임베드/위젯 인증 토큰
- CSRF double submit token이 JWT인 경우
- gRPC metadata `Authorization` 헤더
- GraphQL Apollo Server context의 token 처리 코드

## 자주 놓치는 패턴 (Frequently Missed)

- **Algorithm `none`**: `verify` 옵션이 `none` 허용 시 서명 없는 토큰 통과. `jsonwebtoken` < 9.0.0 일부 버전.
- **Algorithm Confusion (RS256 → HS256)**: 서버는 RSA 공개키로 검증한다고 가정, 공격자는 공개키를 HMAC 시크릿으로 사용해 HS256으로 서명. `algorithms` 미지정 시 가능. 공개키가 GitHub/JWKS 노출되면 즉시 RCE급.
- **`jwt.decode()` (서명 미검증)** vs `jwt.verify()`: decode는 검증 없이 페이로드만 추출. 권한 결정에 decode 결과 사용 시 우회.
- **`ignoreExpiration: true`**: 만료 토큰 영구 사용.
- **만료 예외 catch 후 클레임 재사용**: `try { verify } catch (TokenExpired) { use claim from error }` — 만료된 토큰의 sub로 인증 통과.
- **`jku` 헤더 신뢰**: 토큰 헤더의 `jku` URL에서 JWKS fetch → 공격자가 자신의 jku 지정 → 자기 키로 서명. URL 화이트리스트 필수.
- **`jwk` 헤더 직접 신뢰**: 토큰에 공개키가 들어있고 그걸로 검증 → 누구나 유효한 토큰 생성.
- **`kid` 헤더 SQLi/Path traversal**: `kid`를 DB 쿼리/파일 경로로 사용 → SQLi/LFI.
- **`kid`로 임의 파일 검증 키 강제**: `/dev/null` 또는 빈 파일을 키로 → HMAC 검증 통과.
- **하드코딩 시크릿** (`'secret'`, `'password'`, `'changeme'`): brute force.
- **약한 시크릿 (8자 미만)**: HS256 시크릿 사전 공격.
- **`iss` 미검증**: 다른 발급자가 만든 토큰 통과.
- **`aud` 미검증**: 다른 서비스용 토큰 재사용.
- **`exp` 미검증**.
- **시계 skew 과대** (`clockTolerance` 너무 큼): 만료 토큰 장기 통용.
- **JWKS 캐시 무효화 부재**: 키 회전 시 stale 캐시 사용.
- **블랙리스트(로그아웃) 미구현**: 탈취된 토큰 영구 유효.
- **Refresh token rotation 부재**: 한 번 발급된 refresh token 재사용 가능.
- **Bearer token in URL**: 로그/Referer 노출.
- **localStorage 저장**: XSS로 탈취 가능 (JWT 자체는 아니지만 함께 점검).
- **`HS256` + 공개 키 정보 (RSA) 혼용**: nimbus-jose 등에서 키 타입 확인 미흡.
- **Embedded `x5c` chain**: 토큰 헤더의 인증서 체인을 신뢰 → 공격자 자체 서명 인증서로 검증 통과.
- **JWE를 JWS로 혼동**: 암호화된 JWT를 검증 없이 decrypt만 하고 클레임 사용. 암호화는 무결성을 보장하지 않음 (AES-GCM 등 AEAD 명시 필요).
- **`crit` 헤더 무시**: critical extension(`crit`)을 무시하면 의도와 다른 처리 — RFC 7515 위반.
- **`typ` 헤더 미검증**: `JWT` vs `at+jwt` (OAuth2 access token, RFC 9068) vs 다른 타입 구분 누락 시 토큰 혼동 공격.
- **CVE-2022-21449 (Java Psychic Signature)**: Java 15-18의 ECDSA P-256 검증에서 `(r=0, s=0)` 서명이 통과 — `auth0/java-jwt` 등에 영향. 패치 버전 확인.
- **`jwt.get_unverified_header()`로 alg 추출 후 동적 검증**: 헤더 신뢰 사실상 동일 — alg confusion 가능.

## 안전 패턴 (FP Guard)

- **`algorithms` 명시 + 단일 알고리즘**: `jwt.verify(t, key, {algorithms: ['RS256']})`.
- **`auth0/java-jwt`**: `Algorithm` 객체로 검증 → confusion 자체 불가.
- **`jose` (modern)** 사용.
- **시크릿이 환경변수 + 32 byte 이상 random**.
- **`iss`/`aud`/`exp`/`nbf` 모두 검증** (`jwt.verify` 옵션).
- **JWKS endpoint 화이트리스트** (jku 미사용, 서버 설정 endpoint만).
- **블랙리스트/세션 store + 짧은 TTL** (5~15분) + refresh token rotation.
- **`Authorization: Bearer` 헤더만 사용** (URL/cookie 미사용 또는 `HttpOnly; Secure; SameSite=Strict`).
- **Asymmetric algorithm (RS256/ES256/EdDSA) + JWKS endpoint 화이트리스트**: 키 분리로 confusion 차단. 단, JWKS URL이 자체 호스팅이고 변경 불가해야 함.
- **DPoP (RFC 9449) Token binding**: 클라이언트 keypair와 토큰 결합 — 탈취 토큰 단독 사용 불가.
- **`typ: at+jwt` 검증** (OAuth2 access token, RFC 9068): ID token vs access token 혼동 차단.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `algorithms` 명시했지만 RS256+HS256 둘 다 허용 | 가능 | RSA 공개키를 HS256 시크릿으로 사용 (alg confusion) — 대칭/비대칭 혼합 금지 |
| JWKS endpoint URL이 사용자 입력 또는 `kid`로 결정 | 가능 | 임의 JWKS endpoint 가리키기 → 자기 키로 서명한 토큰 통과 |
| `exp`만 검증 (nbf/iat 미검증) | 부분 가능 | 미래 발급 토큰 (`nbf` 미래)도 통과, 재발급 추적 불가 |
| 토큰 검증 후 `sub`만 사용 (`aud`/`iss` 미체크) | 가능 | 다른 서비스용 토큰 재사용 (audience confusion) — 같은 IdP의 다른 클라이언트 토큰 |
| `jjwt` `setSigningKey(Object)` (구 API) | 가능 | Object 타입으로 받아 키 길이/타입 검증 누락 — `parseClaimsJws` 내부에서 alg 신뢰 |
| Java 15-18 ECDSA 검증 (CVE-2022-21449) | 가능 | `(r=0, s=0)` 서명이 통과 — 패치 미적용 시 우회 |
| `kid` lookup이 캐시 (TTL 무한) | 가능 | 키 회전 후 stale 키로 검증 — 회전 전 탈취된 키 재사용 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| `verify`/`decode` 호출 시 `algorithms` 미지정 | 후보 (라벨: `ALG_CONFUSION`) |
| `none` 허용 또는 `verify: false` 옵션 | 후보 (라벨: `NONE_ALG`) |
| `decode` (서명 미검증)을 권한 결정에 사용 | 후보 (라벨: `UNVERIFIED_DECODE`) |
| 만료 예외 catch 후 클레임을 권한에 사용 | 후보 (라벨: `EXPIRED_REUSE`) |
| `jku`/`jwk` 헤더 신뢰 + 화이트리스트 없음 | 후보 (라벨: `JKU_TRUST`) |
| `kid`를 SQL/path/key lookup에 직접 사용 | 후보 (라벨: `KID_INJECTION`) |
| 하드코딩/약한 시크릿 (HS*) | 후보 (라벨: `WEAK_SECRET`) |
| `algorithms` 명시 + 강한 시크릿 + iss/aud/exp 검증 | 제외 |
| 외부 IdP 위임 (Auth0/Cognito/Okta) + 토큰 검증을 라이브러리에 위임 | 라이브러리 옵션 확인 후 판단 |

## 후보 판정 제한

JWT 검증/디코딩 코드가 직접 구현되거나, 라이브러리 사용 시 옵션 결함이 있는 경우만 후보. 외부 IdP에 완전 위임하면 제외.
