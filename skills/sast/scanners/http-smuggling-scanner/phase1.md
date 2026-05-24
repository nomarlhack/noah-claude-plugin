---
id_prefix: HSMG
rules_dir: rules/
---

> ## 핵심 원칙: "요청 경계 불일치가 발생해야 취약점이다"
>
> 프록시/백엔드 구성 자체는 취약점이 아니다. `Content-Length`/`Transfer-Encoding` 해석 차이로 하나의 HTTP 요청 안에 숨겨진 두 번째 요청이 백엔드에서 별도로 처리되어야 한다.
>
> **소스코드에 프록시 설정이 없어도 Phase 1을 "해당 없음"으로 종료하지 않는다.** 프록시 설정은 인프라 레벨이며 소스코드에 없는 것이 일반적. Phase 2 동적 테스트로 검증.

## Sink 의미론

HTTP Smuggling sink는 "프론트엔드(프록시)와 백엔드(앱 서버)가 같은 TCP 커넥션을 재사용하면서, CL/TE 헤더를 다르게 해석하는 지점"이다. 코드 sink가 아닌 **인프라 sink** — 분석 대상이 코드보다 설정.

| 카테고리 | 위험 조합 |
|---|---|
| CL.TE | 프론트엔드는 `Content-Length` 사용, 백엔드는 `Transfer-Encoding` 사용 |
| TE.CL | 프론트엔드는 `Transfer-Encoding` 사용, 백엔드는 `Content-Length` 사용 |
| TE.TE | 양쪽 모두 `Transfer-Encoding` 처리하지만 obfuscated 헤더 (`Transfer-encoding: xchunked`) 처리 다름 |
| HTTP/2 downgrade | gateway가 HTTP/2 → HTTP/1.1 변환 시 헤더 매핑 실수 |
| H2.CL / H2.TE | HTTP/2 frame 해석과 HTTP/1.1 변환 사이 불일치 |

## Source-first 추가 패턴

- nginx `proxy_pass` 설정 (`nginx.conf`, `/etc/nginx/sites-*`)
- Apache `ProxyPass`, `mod_proxy`
- HAProxy `frontend`/`backend` 설정
- Envoy/Istio sidecar
- AWS ALB/ELB 설정 (인프라 코드 IaC)
- Cloudflare/CloudFront/Fastly 설정
- Express `http-proxy-middleware` 사용
- Kubernetes Ingress 설정
- 백엔드 서버 (Node `http`, Gunicorn, Tomcat, IIS, Puma) 옵션
- `--insecure-http-parser` 플래그 사용

## 자주 놓치는 패턴 (Frequently Missed)

- **Node.js `--insecure-http-parser`**: 엄격한 파서 우회. 운영 환경에서 사용 시 즉시 후보.
- **HTTP/2 → HTTP/1.1 downgrade**: ALB/Cloudflare가 HTTP/2 수신 후 백엔드에 HTTP/1.1로 전달. HTTP/2의 `:authority` pseudo-header 또는 헤더값 검증이 약하면 백엔드에 CL/TE 인젝션.
- **`Transfer-Encoding: chunked\r\nTransfer-Encoding: x`** (다중 헤더): 일부 파서가 첫 번째, 일부가 마지막을 사용.
- **`Transfer-Encoding : chunked`** (공백 트릭): 헤더 이름 검증.
- **`Transfer-Encoding: chunkedX`** vs **`Transfer-Encoding: xchunked`**: 일부 파서가 substring 매칭.
- **`Content-Length: 0\r\nContent-Length: 100`**: 다중 CL.
- **`Content-Length` + `Transfer-Encoding` 동시 존재 시 RFC는 TE 우선이지만 미준수 서버 다수**.
- **WebSocket upgrade with body**: smuggling 변형.
- **gRPC over HTTP/1.1 fallback**: 헤더 변환 버그.
- **Apache Traffic Server, IIS, F5 BIG-IP** 등 특정 벤더 알려진 CVE.
- **CDN 캐시 poisoning과 결합**: smuggle된 요청이 캐시 응답으로 다른 사용자에게.
- **`http-proxy-middleware` `changeOrigin` + 커넥션 풀링**: Node 백엔드와 Node 프록시 사이.
- **CRLF in path**: `/path\r\nX-Header: x` — request line injection.
- **CL.0 smuggling (James Kettle, 2024)**: `Content-Length: 0`이지만 body 존재 — 프론트가 0 신뢰, 백엔드는 다음 요청으로 해석.
- **0.CL smuggling**: 프론트가 CL 없는 요청을 신뢰, 백엔드가 CL을 요구하면 다음 요청에 합쳐짐.
- **Expect: 100-continue 처리 차이**: 100 응답 없이 본문 전송 시 프록시/백엔드 처리 차이.
- **HTTP/3 (QUIC) → HTTP/1.1 downgrade**: CDN에서 QUIC 수신 후 백엔드에 HTTP/1.1 — 최신 취약점 변형.
- **Cache deception + smuggling**: 정적 확장자 (`/user.js`) 경로로 smuggle된 요청이 캐시되어 재사용.

## 안전 패턴 (FP Guard)

- **HTTP/2 end-to-end**: 프론트엔드와 백엔드 모두 HTTP/2 → CL/TE 개념 자체 없음 (대신 H2C smuggling 별도 점검).
- **단일 서버 (프록시 없음)**: smuggling 불가능.
- **프록시가 매 요청마다 새 TCP 커넥션** (keep-alive 비활성화): 부담 크지만 smuggling 차단.
- **백엔드가 엄격한 HTTP 파서** (Node 엄격 파서, Gunicorn 최신): TE/CL 동시 헤더 거부.
- **WAF/gateway에서 TE 헤더 차단** 또는 TE chunked 정규화.
- **nginx `proxy_http_version 1.1` + `proxy_set_header Connection ""`** + 백엔드 동기화.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| TE 헤더 제거 (WAF) | 가능 | obfuscated 헤더 (`Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`) 누락 시 통과 |
| 다중 CL 헤더 거부 (RFC 준수) | 부분 가능 | `Content-Length` + `Content_Length` (underscore) — 파서별 처리 차이 |
| HTTP/1.1 엄격 파서 | 부분 가능 | HTTP/2 downgrade 경로가 존재하면 HTTP/2 측에서 인젝션 |
| Keep-alive 비활성화 | 가능 | 매 요청마다 새 TCP 커넥션 — smuggling 자체는 차단되나 성능 대가 큼 |
| End-to-end HTTP/2 | 환경 의존 | 일부 백엔드는 내부적으로 HTTP/1.1로 변환 (gRPC→REST adapter 등) — 변환 지점에 인젝션 |

## 후보 판정 의사결정

소스코드만으로는 확정 어려움. Phase 2 동적 테스트가 결정적.

| 조건 | 판정 |
|---|---|
| 프록시 체인 존재 (코드 또는 명시적 설정) | 후보 (Phase 2 필수) |
| Node.js `--insecure-http-parser` 플래그 운영 환경 | 후보 (라벨: `INSECURE_PARSER`) |
| HTTP/2 gateway + HTTP/1.1 백엔드 | 후보 (라벨: `H2_DOWNGRADE`, Phase 2 필수) |
| `http-proxy-middleware` + 백엔드 Node | 후보 (Phase 2) |
| 단일 서버, 프록시 없음 확인 | 제외 |
| 인프라 레벨 정보 부재 | 후보 유지 (라벨: `UNKNOWN_INFRA`, Phase 2로 확인) |

## 후보 판정 제한

프록시 체인이 존재하거나 인프라 정보 부재 시 후보. 단일 서버 확인 시 제외. 결정적 판정은 Phase 2 동적 테스트.
