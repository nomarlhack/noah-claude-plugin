### Phase 2: 동적 테스트 (검증)

**도구 선택:** 응답 헤더 점검이 본질 — curl만 사용. Playwright는 사용하지 않는다.

**기본 원칙:**
- 모든 판정은 **실제 응답 헤더** 기반
- 코드/설정에 있어도 응답에 없으면 확인됨, 반대도 성립
- 각 라벨 검증은 phase1 후보 **path별로 반복** (루트 1회로 전체 판정 금지)
- Cache-Control은 **인증 세션 쿠키 동반** 요청만 유효
- CORS는 정상 GET + 공격자 Origin GET + Preflight OPTIONS **3회 비교** 필수

---

## 라벨별 테스트

### 정찰 — 후보 path별 헤더 일괄 조회

```bash
# phase1 후보의 각 URL에 대해 한 번씩 실행
curl -sIv "https://target/<path>" 2>&1 | grep -iE '^< (content-security-policy|content-security-policy-report-only|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|feature-policy|access-control-|cache-control|pragma|expires|cross-origin-)'
```

### `CSP_MISSING` / `CSP_UNSAFE_INLINE` / `CSP_UNSAFE_EVAL` / `CSP_WILDCARD` / `CSP_REPORT_ONLY`

```bash
curl -sI "https://target/<html-path>" | grep -i '^content-security-policy:'
```

| 응답 | 판정 |
|---|---|
| HTML 페이지에 `Content-Security-Policy` 없음 | 확인됨 (`CSP_MISSING`) |
| `script-src` 또는 `default-src`에 `'unsafe-inline'` | 확인됨 (`CSP_UNSAFE_INLINE`) — `strict-dynamic` + nonce/hash와 함께면 제외 |
| `script-src` 또는 `default-src`에 `'unsafe-eval'` | 확인됨 (`CSP_UNSAFE_EVAL`) |
| `default-src` 또는 `script-src`에 단독 `*` | 확인됨 (`CSP_WILDCARD`) |
| `Content-Security-Policy-Report-Only`만 (강제 CSP 부재) | 확인됨 (`CSP_REPORT_ONLY`) |

### `CORS_WILDCARD_CRED` / `CORS_REFLECT` / `CORS_NULL`

3회 요청 비교:
```bash
# 정상 Origin
curl -sI -H "Origin: https://target" "https://target/api/<endpoint>" | grep -iE '^access-control-'

# 공격자 Origin
curl -sI -H "Origin: https://evil.com" "https://target/api/<endpoint>" | grep -iE '^access-control-'

# null Origin
curl -sI -H "Origin: null" "https://target/api/<endpoint>" | grep -iE '^access-control-'

# Preflight OPTIONS
curl -sI -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: authorization,content-type" \
  "https://target/api/<endpoint>" | grep -iE '^access-control-'
```

| 응답 | 판정 |
|---|---|
| `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` | 확인됨 (`CORS_WILDCARD_CRED`) |
| 공격자 Origin 반사 + Credentials 허용 | 확인됨 (`CORS_REFLECT`) |
| `Access-Control-Allow-Origin: null` 반사 + Credentials | 확인됨 (`CORS_NULL`) |

### `CLICKJACK_UNPROTECTED`

```bash
curl -sI "https://target/<html-path>" | grep -iE '^(x-frame-options|content-security-policy):'
```

| 응답 | 판정 |
|---|---|
| `X-Frame-Options` 부재 AND CSP `frame-ancestors` 부재 | 확인됨 |
| `X-Frame-Options: ALLOW-FROM ...` (비표준) | 확인됨 (`CLICKJACK_ALLOWFROM`) |

### `MIME_SNIFF`

```bash
# 사용자 업로드 URL (파일 업로드 후 응답에서 URL 추출)
curl -sI "https://target/<user-upload-url>" | grep -i '^x-content-type-options:'
```

| 응답 | 판정 |
|---|---|
| 출력 없음 또는 `nosniff` 외 값 | 확인됨 |

### `REFERRER_LEAK` / `REFERRER_UNSAFE`

```bash
curl -sI "https://target/" | grep -i '^referrer-policy:'
```

| 응답 | 판정 |
|---|---|
| 출력 없음 + 외부 링크에 민감 URL 파라미터 | 확인됨 (`REFERRER_LEAK`) |
| `unsafe-url` 또는 `no-referrer-when-downgrade` | 확인됨 (`REFERRER_UNSAFE`) |
| `strict-origin-when-cross-origin` 이상 | 안전 |

### `PERMISSIONS_MISSING`

```bash
curl -sI "https://target/" | grep -iE '^(permissions-policy|feature-policy):'
```

| 응답 | 판정 |
|---|---|
| 출력 없음 + 민감 기능(카메라/마이크/위치) 사용 | 확인됨 |

### `CACHE_SENSITIVE`

```bash
# 인증 세션 쿠키 동반 필수
curl -sI -H "Cookie: <세션쿠키>" "https://target/<auth-required-path>" | grep -iE '^(cache-control|pragma|expires):'
```

| 응답 | 판정 |
|---|---|
| 인증 응답에 `Cache-Control` 부재이거나 `public`/`max-age>0` | 확인됨 |
| `no-store` 또는 `private, no-cache` | 안전 |

### `COOP_MISSING` / `CORP_MISSING` (Cross-Origin)

```bash
curl -sI "https://target/" | grep -iE '^cross-origin-(opener|embedder|resource)-policy:'
```

| 응답 | 판정 |
|---|---|
| SharedArrayBuffer 사용 + COOP/COEP 없음 | 확인됨 |
| `Cross-Origin-Opener-Policy: same-origin` + `Cross-Origin-Embedder-Policy: require-corp` | 안전 |

### `CLEAR_SITE_DATA_MISSING` (로그아웃)

```bash
curl -sI -X POST "https://target/logout" -H "Cookie: <세션>" | grep -i 'clear-site-data'
```

| 응답 | 판정 |
|---|---|
| 출력 없음 (로그아웃 시 클라이언트 데이터 명시 제거 안 함) | 확인됨 (영향도 약함) |

---

**참고사항:**

- 모든 판정은 **실제 응답 헤더** 기반 — 코드에 있어도 응답에 없으면 확인됨, 반대도 성립
- 각 라벨 검증은 phase1 후보 **path별로 반복** — 루트 1회로 전체 판정 금지 (SPA shell만 CSP 붙는 사례 흔함)
- Cache-Control 검증은 **인증 세션 쿠키 동반** 요청으로만 유효
- CORS는 정상 GET + 공격자 Origin GET + Preflight OPTIONS **3회 비교** 필수 (preflight에서 분기되는 경우 다수)
- HSTS는 HTTPS 응답에서만 의미 — HTTP 환경에선 판정 제외
- Feature-Policy는 deprecated — Permissions-Policy로 교체 확인
- COOP/COEP는 SharedArrayBuffer 사용 환경에서만 필수 — 일반 페이지엔 권장 수준
- CSP `strict-dynamic` + nonce/hash 조합은 `unsafe-inline` 무력화 — 제외 판정
- `X-XSS-Protection`은 최신 브라우저에서 deprecated — 설정 부재가 결함 아님
- CSP report-only 모드는 실제 차단 없음 — 강제 모드 미적용 시 `CSP_REPORT_ONLY` 후보
- 다수 Set-Cookie/응답 헤더는 개별 판정 — cookie-security-scanner와 별도
- CDN/프록시/웹서버 계층에서 헤더 추가 가능 — 코드에 없어도 응답에 있으면 안전
- Cache poisoning은 응답이 cache header 포함 + Host가 cache key 미포함일 때 — host-header-scanner 결합
- Frame-ancestors는 X-Frame-Options 대체 — CSP만으로도 clickjacking 방어 가능
- COEP `require-corp`는 cross-origin resource를 모두 CORP 헤더 요구 — 호환성 영향 큼
