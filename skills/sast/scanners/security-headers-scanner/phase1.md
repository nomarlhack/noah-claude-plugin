---
id_prefix: SECHDR
rules_dir: rules/
---

> ## 핵심 원칙: "코드 + 설정 파일 + 인프라 구성을 종합하여 보안 헤더의 실제 적용 상태를 판단한다"
>
> 보안 헤더는 애플리케이션 코드, 웹서버 설정, CDN/프록시 설정에 분산되어 있을 수 있다. 하나의 계층에서 설정되지 않았다고 바로 취약하다고 판단하지 않는다.

## Sink 의미론

이 스캐너의 "Sink"는 HTTP 응답 헤더를 설정하는 모든 지점이다. 전통적인 Source→Sink 모델보다는 **"설정 완전성 평가"** 모델을 따른다.

| 카테고리 | 패턴 |
|---|---|
| Node.js/Express 미들웨어 | `helmet()`, `app.use(cors(...))`, `res.setHeader()`, `res.set()` |
| Java/Spring | `@CrossOrigin`, `CorsConfiguration`, `HttpServletResponse.setHeader()`, Spring Security `headers()` |
| Python/Django | `SECURE_*` 설정, `django-cors-headers`, `SecurityMiddleware` |
| Python/Flask | `flask-cors`, `@after_request` 헤더 설정 |
| Ruby/Rails | `SecureHeaders` gem, `config.action_dispatch.default_headers` |
| 웹서버 설정 | nginx `add_header`, Apache `Header set`, Caddy `header` |
| 인프라 설정 | Terraform `custom_header`, CloudFront `response_headers_policy` |

## 분석 대상: 7대 보안 헤더

아래 7개 헤더 각각에 대해 설정 여부 + 설정 강도를 평가한다.

### 1. Content-Security-Policy (CSP)

| 설정 | 판정 |
|---|---|
| CSP 헤더 없음 | 후보 (라벨: `CSP_MISSING`) |
| `unsafe-inline` 포함 (script-src) | 후보 (라벨: `CSP_UNSAFE_INLINE`) |
| `unsafe-eval` 포함 | 후보 (라벨: `CSP_UNSAFE_EVAL`) |
| `*` 와일드카드 origin 허용 | 후보 (라벨: `CSP_WILDCARD`) |
| nonce/hash 기반 + strict-dynamic | 제외 |
| report-only 모드만 적용 | 후보 (라벨: `CSP_REPORT_ONLY`) |

### 2. CORS (Access-Control-Allow-Origin)

| 설정 | 판정 |
|---|---|
| `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` | 후보 (라벨: `CORS_WILDCARD_CRED`) |
| Origin 동적 반사 (요청 Origin을 그대로 응답) + Credentials | 후보 (라벨: `CORS_REFLECT`) |
| `null` origin 허용 + Credentials | 후보 (라벨: `CORS_NULL`) |
| 화이트리스트 기반 Origin 검증 | 제외 |
| 정규식 기반 Origin 검증 (우회 가능성 확인) | 후보 판단 보류 → 정규식 패턴 분석 |
| `*` 단독 (Credentials 없음) — 공개 API | 제외 (공개 API 확인 필요) |

### 3. X-Frame-Options / frame-ancestors

| 설정 | 판정 |
|---|---|
| X-Frame-Options + CSP frame-ancestors 모두 없음 | 후보 (라벨: `CLICKJACK_UNPROTECTED`) |
| `ALLOWFROM` (비표준, 브라우저 미지원) | 후보 (라벨: `CLICKJACK_ALLOWFROM`) |
| `DENY` 또는 `SAMEORIGIN` 또는 CSP `frame-ancestors 'self'` | 제외 |

### 4. X-Content-Type-Options

| 설정 | 판정 |
|---|---|
| `nosniff` 미설정 + 사용자 업로드 파일 서빙 존재 | 후보 (라벨: `MIME_SNIFF`) |
| `nosniff` 미설정 + 사용자 업로드 없음 | 정보 수준 |
| `nosniff` 설정됨 | 제외 |

### 5. Referrer-Policy

| 설정 | 판정 |
|---|---|
| Referrer-Policy 없음 + 외부 링크에 민감 URL 파라미터 존재 | 후보 (라벨: `REFERRER_LEAK`) |
| `unsafe-url` 또는 `no-referrer-when-downgrade` | 후보 (라벨: `REFERRER_UNSAFE`) |
| `strict-origin-when-cross-origin` 이상 | 제외 |

### 6. Permissions-Policy (구 Feature-Policy)

| 설정 | 판정 |
|---|---|
| 민감 기능 사용 (카메라, 마이크, 위치) + Policy 없음 | 후보 (라벨: `PERMISSIONS_MISSING`) |
| 민감 기능 미사용 | 제외 |
| 적절한 Policy 설정됨 | 제외 |

### 7. Cache-Control (민감 응답)

| 설정 | 판정 |
|---|---|
| 인증 필요 API 응답에 `Cache-Control` 없음 | 후보 (라벨: `CACHE_SENSITIVE`) |
| `no-store` 또는 `private, no-cache` 설정 | 제외 |
| 정적 자산 (CSS/JS/이미지)에 캐시 없음 | 제외 (해당 없음) |

### 8. Cross-Origin-* (COOP/COEP/CORP)

Spectre/Meltdown 류 side-channel 완화. SharedArrayBuffer 사용 시 필수.

| 설정 | 판정 |
|---|---|
| SharedArrayBuffer / cross-origin isolation 필요 환경 + COOP/COEP 없음 | 후보 (라벨: `COOP_MISSING`) |
| COEP `require-corp` + 모든 cross-origin 리소스에 CORP 없음 | 후보 (라벨: `CORP_MISSING`) |
| `Cross-Origin-Opener-Policy: same-origin` + `Cross-Origin-Embedder-Policy: require-corp` 설정 | 제외 |

### 9. Clear-Site-Data (로그아웃)

| 설정 | 판정 |
|---|---|
| 로그아웃 엔드포인트에서 `Clear-Site-Data: "cache", "cookies", "storage"` 미설정 | 후보 (라벨: `CLEAR_SITE_DATA_MISSING`, 심각도 낮음) |
| 로그아웃 시 클라이언트 데이터 명시 제거 | 제외 |

## Source-first 추가 패턴

- nginx.conf, apache.conf, httpd.conf, .htaccess 등 웹서버 설정 파일
- Terraform/CloudFormation에서 CDN 헤더 설정
- Kubernetes Ingress annotation의 헤더 설정
- Docker/docker-compose에서 프록시 설정
- 환경별 설정 파일 (production.rb, settings.py 등)

## 안전 패턴 (FP Guard)

- **helmet (Node.js)**: `app.use(helmet())` — 주요 보안 헤더를 기본값으로 설정. 개별 옵션을 확인하여 비활성화된 헤더가 있는지 체크.
- **Spring Security headers()**: 기본 설정으로 X-Frame-Options, X-Content-Type-Options 등 포함.
- **Django SecurityMiddleware**: `SECURE_CONTENT_TYPE_NOSNIFF` 등 설정 확인.
- **Rails default_headers**: Rails 5+에서 기본 보안 헤더 포함.
- **nginx snippet include**: 공통 보안 헤더를 별도 파일로 분리하여 include하는 패턴.
- **CDN/프록시 계층 설정**: 코드에 없어도 인프라 계층에서 추가될 수 있음 — 판단 불가 시 "인프라 계층 확인 필요"로 기재.
- **브라우저/HTTP 표준 기본 동작**: 명시 부재가 곧 취약이 아닌 경우 — 최신 브라우저 기본값이 동등 효과를 제공하거나, 인증 요청이 HTTP 표준상 공유 캐시 차단 대상인 경우. 명시 권고로 격하.

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| CSP 없음 + XSS 후보 존재 (다른 스캐너 결과) | 후보 (높은 실효성) |
| CSP 없음 + XSS 후보 없음 | 후보 (방어 심층 관점) |
| CORS 와일드카드 + Credentials | 후보 |
| CORS 와일드카드 + Credentials 없음 + 공개 API | 제외 |
| 프레임워크 기본 보안 헤더 활성화 확인 | 제외 |
| helmet/Spring Security 사용하지만 일부 비활성화 | 후보 (비활성화된 항목만) |
| 코드에 없지만 인프라 설정 파일에서 설정 확인 | 제외 |
| 코드/설정 어디에도 없음 + 인프라 확인 불가 | 후보 (전제조건: "인프라 계층 미확인" 명시) |

## 후보 판정 제한

보안 헤더 미설정은 직접적인 공격 벡터가 아닌 방어 심층(defense-in-depth) 부재이다. 코드 또는 접근 가능한 설정 파일에서 설정을 확인할 수 없는 경우 후보로 등록하되, "인프라 계층(웹서버/CDN/프록시)에서 설정될 수 있음"을 전제조건으로 명시한다.
