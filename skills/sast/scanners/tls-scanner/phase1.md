---
id_prefix: TLS
rules_dir: rules/
---

> ## 핵심 원칙: "안전하지 않은 TLS 설정이 프로덕션 환경에 적용되어야 취약점이다"
>
> 테스트/개발 환경 한정 설정(`if (process.env.NODE_ENV === 'test')` 등)은 후보에서 제외한다. Managed TLS (AWS ALB, CloudFront, Cloudflare 등)는 코드 제어 범위 밖이므로 판단 불가로 처리한다.

## Sink 의미론

이 스캐너의 "Sink"는 **TLS/SSL 연결을 설정하거나 구성하는 지점으로, 프로토콜 버전·cipher suite·인증서 검증 설정이 보안에 영향을 미치는 곳**이다.

| 카테고리 | 패턴 |
|---|---|
| Node.js | `tls.createServer()`, `https.createServer()`, `new tls.TLSSocket()`, `secureProtocol`, `minVersion`, `ciphers` |
| Python | `ssl.create_default_context()`, `ssl.wrap_socket()`, `SSLContext()`, `requests.get(verify=False)` |
| Java | `SSLContext.getInstance()`, `setEnabledProtocols()`, `TrustManagerFactory`, custom `X509TrustManager` |
| Go | `tls.Config{}`, `MinVersion`, `MaxVersion`, `CipherSuites`, `InsecureSkipVerify` |
| Ruby | `OpenSSL::SSL::SSLContext`, `verify_mode = OpenSSL::SSL::VERIFY_NONE` |
| .NET | `ServicePointManager.SecurityProtocol`, `ServerCertificateValidationCallback` |
| nginx | `ssl_protocols`, `ssl_ciphers`, `ssl_prefer_server_ciphers`, `proxy_ssl_verify` |
| Apache | `SSLProtocol`, `SSLCipherSuite`, `SSLVerifyClient` |

## 후보 라벨 (12종)

### TLS_WEAK_VERSION — 취약 프로토콜 버전 허용

| 설정 | 판정 |
|---|---|
| SSLv2, SSLv3, TLS 1.0, TLS 1.1 허용 (`SSLv3_method`, `TLSv1_method`, `TLSv1_1_method`, `ssl_protocols TLSv1;` 등) | 후보 |
| `minVersion: 'TLSv1.2'` 또는 `'TLSv1.3'` 명시 | 제외 |
| `ssl_protocols TLSv1.2 TLSv1.3;` | 제외 |
| 프레임워크/플랫폼 기본값 사용 (최신 Node.js 18+, Go 1.18+, Python 3.10+ 기본 TLS 1.2 이상) | 제외 |

### TLS_WEAK_CIPHER — 취약 cipher suite 허용

| 설정 | 판정 |
|---|---|
| RC4, DES, 3DES, NULL, EXPORT, anon cipher suite 허용 | 후보 |
| `ciphers: 'NULL:eNULL:aNULL'`, `ssl_ciphers 'RC4:DES'` 등 | 후보 |
| ECDHE/DHE + AES-GCM/ChaCha20 조합만 허용 | 제외 |
| 프레임워크 기본 cipher suite 사용 (최신 버전) | 제외 |

### TLS_NO_CERT_VERIFY — 인증서 검증 비활성화

| 설정 | 판정 |
|---|---|
| `rejectUnauthorized: false` | 후보 |
| `verify=False` (Python requests) | 후보 |
| `CERT_NONE`, `CERT_OPTIONAL` | 후보 |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | 후보 |
| `check_hostname = False` | 후보 |
| `InsecureSkipVerify: true` (Go) | 후보 |
| `ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, errors) => true` (.NET) | 후보 |
| 테스트/개발 환경 조건부 설정 | 제외 |
| `ssl.create_default_context()` 단독 사용 (Python — 기본 안전) | 제외 |

### TLS_TRUST_ALL — 모든 인증서 수락 TrustManager

| 설정 | 판정 |
|---|---|
| 커스텀 `X509TrustManager`에서 `checkServerTrusted()`가 빈 메서드 (Java) | 후보 |
| `TrustSelfSignedStrategy` 사용 | 후보 |
| `TrustAllCerts` 패턴 | 후보 |
| 올바른 인증서 체인 검증 구현 | 제외 |

### TLS_COMPRESSION — TLS 압축 활성화 (CRIME/BREACH)

| 설정 | 판정 |
|---|---|
| TLS 압축 활성화 (SSL_OP_NO_COMPRESSION 미설정) | 후보 |
| `op_no_compression` 미설정 (Python) | 후보 |
| 명시적으로 `SSL_OP_NO_COMPRESSION` 설정 | 제외 |
| 최신 OpenSSL (1.1.0+) — 기본 압축 비활성화 | 제외 |

### TLS_HEARTBLEED_VER — Heartbleed 취약 OpenSSL 버전

| 설정 | 판정 |
|---|---|
| OpenSSL 1.0.1 ~ 1.0.1f 버전 사용 확인 (Dockerfile, package-lock.json, requirements.txt 등) | 후보 |
| OpenSSL 1.0.1g 이상 또는 1.0.0 이하 | 제외 |
| heartbeat 확장 명시적 비활성화 | 제외 |

### TLS_WEAK_KEY — 약한 키 강도

| 설정 | 판정 |
|---|---|
| RSA 키 < 2048비트 | 후보 |
| ECDSA 키 < 256비트 | 후보 |
| RSA 2048+ 또는 ECDSA 256+ | 제외 |

### TLS_NO_PFS — Perfect Forward Secrecy 미지원

| 설정 | 판정 |
|---|---|
| ECDHE/DHE 없는 cipher만 허용 (RSA 키 교환만 사용) | 후보 |
| cipher suite에 ECDHE 또는 DHE 포함 | 제외 |

### TLS_PADDING_ORACLE — CBC 모드 패딩 오라클 가능성

| 설정 | 판정 |
|---|---|
| CBC 모드 cipher만 사용 + TLS 1.0/1.1 | 후보 |
| GCM/ChaCha20 cipher 사용 또는 TLS 1.3 | 제외 |
| CBC 사용하나 TLS 1.2 + encrypt-then-MAC 확장 | 제외 |

### HSTS_MISSING — HSTS 헤더 부재

| 설정 | 판정 |
|---|---|
| HTTPS 사이트에 `Strict-Transport-Security` 헤더 없음 | 후보 |
| HSTS 헤더 존재 (`max-age` 1년 이상) | 제외 |
| HTTP 전용 사이트 (HTTPS 미지원) | 해당 없음 |

### HSTS_SHORT_MAXAGE — HSTS max-age 부족

| 설정 | 판정 |
|---|---|
| `max-age` < 31536000 (1년) | 후보 |
| `max-age` >= 31536000 | 제외 |
| `includeSubDomains` 미포함 | 정보 수준 (후보 아님, 참고 사항으로 기재) |

### TLS_DOWNGRADE — 다운그레이드 방지 미설정

| 설정 | 판정 |
|---|---|
| 최소 프로토콜 버전 미강제 (`minVersion` 미설정) + TLS 1.0/1.1 허용 | 후보 |
| `minVersion: 'TLSv1.2'` 명시 | 제외 |
| 서버가 TLS 1.2/1.3만 지원 | 제외 |

## Source-first 추가 패턴

- Dockerfile, docker-compose.yml에서 OpenSSL 버전 확인
- nginx.conf, apache2.conf, httpd.conf에서 TLS 설정 블록
- Terraform/CloudFormation에서 ALB/NLB TLS 정책
- Kubernetes Ingress annotation의 TLS 설정
- 환경별 설정 파일 (production.yml, application-prod.properties 등)
- CI/CD 파이프라인에서 TLS 인증서 배포 설정

## 자주 놓치는 패턴 (Frequently Missed)

- **TLS 1.3 0-RTT (early data) 재생 공격**: `ssl_early_data on` (nginx) + 멱등 아닌 POST 요청 처리 → replay로 중복 처리.
- **OCSP stapling 미활성화**: 클라이언트가 CA에 직접 OCSP 쿼리 → privacy/DoS 영향.
- **certificate transparency (CT) 로그 미확인**: 발급된 인증서가 로그 없으면 브라우저 차단.
- **SNI 누락으로 default certificate 반환**: 공유 호스팅에서 다른 사이트 인증서 노출.
- **TLS session resumption 없이 모든 연결마다 full handshake**: DoS 증폭.
- **HPKP (Public Key Pinning) 오용**: deprecated. 잘못된 pin으로 사이트 접근 불능.
- **`ssl_dhparam` 미설정 (2048-bit 미만)**: DH 키 교환 시 Logjam 공격.
- **mTLS client cert 검증 누락**: `ssl_verify_client optional` + 서버 측 코드에서 cert chain 미검증.
- **gRPC TLS cipher 제한 미검증**: ALTS 또는 TLS 옵션이 cipher를 양쪽에서 제한 못 하면 downgrade.
- **외부 HTTP 클라이언트 SNI 강제**: `Host` 헤더 변조로 SNI 분리 (Domain Fronting).

## 안전 패턴 (FP Guard)

- **`minVersion: 'TLSv1.2'`** 또는 **`'TLSv1.3'`** 명시 — 최신 프로토콜만 허용
- **프레임워크/플랫폼 기본값**: 최신 Node.js (18+), Go (1.18+), Python (3.10+)는 기본적으로 TLS 1.2 이상만 허용
- **`ssl.create_default_context()`** 단독 사용 (Python) — 기본적으로 안전한 설정
- **`rejectUnauthorized: false`가 테스트/개발 환경 조건부**: `if (process.env.NODE_ENV !== 'production')` 블록 내부
- **nginx `ssl_protocols TLSv1.2 TLSv1.3;`** + 강력한 `ssl_ciphers` 설정
- **Managed TLS** (AWS ALB/CloudFront, Cloudflare, GCP HTTPS LB 등) — 코드 제어 범위 밖, 판단 불가로 처리
- **Let's Encrypt 자동 갱신** — 인증서 관리가 자동화된 환경
- **상위 계층 동등 조치 확인**: 하위 계층(예: 내부 nginx/openresty)에 명시 부재지만, 상위 계층(ingress/ALB/CDN)이 동일 HSTS·프로토콜·cipher를 제공하는 경우 하위 계층은 권고로 격하.

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 코드에서 명시적으로 취약 프로토콜/cipher 설정 | 후보 |
| 인증서 검증 비활성화가 프로덕션 코드에 존재 | 후보 |
| 설정 파일에서 TLS 1.0/1.1 허용 | 후보 |
| 프레임워크 기본값 사용 (최신 버전) | 제외 |
| 테스트/개발 환경 한정 설정 | 제외 |
| Managed TLS 사용 (코드 제어 범위 밖) | 제외 |

## 후보 판정 제한

- **인프라 계층 설정 추론 금지**: 코드에 TLS 설정이 없다고 "TLS 미설정"으로 판정하지 않는다. 인프라 계층(ALB, nginx 등)에서 처리될 수 있다.
- **버전 추측 금지**: OpenSSL 버전을 코드만으로 확인할 수 없으면 Heartbleed 후보로 판정하지 않는다. 명시적 버전 참조가 있는 경우에만 판정한다.
- **프레임워크 기본값 신뢰**: 최신 LTS 버전의 프레임워크를 사용하는 경우, 명시적 약화 설정이 없으면 기본 안전으로 판단한다.
