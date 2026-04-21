---
id_prefix: WSOCK
grep_patterns:
  - "new WebSocket\\s*\\("
  - "socket\\.io"
  - "WebSocket"
  - "ActionCable"
  - "io\\.on\\('connection'"
  - "io\\.of\\s*\\("
  - "verifyClient"
  - "allowedOrigins"
  - "wss://"
  - "ws://"
  - "express-ws"
  - "gorilla/websocket"
---

> ## 핵심 원칙: "악용 가능해야 취약점이다"
>
> WebSocket Origin 검증 부재 자체가 즉시 취약점이 아니다. CSWSH로 피해자 연결 하이재킹, 또는 인증 없이 민감 데이터 조회/조작이 실제로 가능해야 한다.

## Sink 의미론

WebSocket sink는 두 카테고리:

1. **핸드셰이크 sink**: Origin/인증/CORS 검증이 누락되거나 우회 가능한 upgrade 핸들러
2. **메시지 sink**: 수신 메시지가 검증/인가 없이 다른 sink(SQL/HTML/명령어/브로드캐스트)로 흘러가는 지점

| 언어 | 라이브러리 |
|---|---|
| Node | `ws`, `socket.io`, `express-ws`, `uWebSockets.js`, `@nestjs/websockets` |
| Python | `websockets`, Django `channels`, `Flask-SocketIO`, FastAPI WebSocket |
| Java | `javax.websocket`, Spring WebSocket, Netty |
| Go | `gorilla/websocket`, `nhooyr.io/websocket` |
| Ruby | Rails `ActionCable`, `faye-websocket` |
| .NET | SignalR |

## Source-first 추가 패턴

- 서버 WebSocket 라우트 등록 (`io.on('connection')`, `app.ws('/path')`, `@MessageMapping`)
- 클라이언트 `new WebSocket(url)`/`io.connect(url)`/`SockJS` 호출 (대응 서버 라우트)
- `upgrade` 핸들러
- Socket.IO `io.use()` 미들웨어
- WebSocket 메시지 라우팅 (`socket.on('event', handler)`)
- 채널 구독 코드 (`subscribe('/topic/...')`)
- 브로드캐스트 코드 (`io.emit`, `socket.broadcast.emit`, `wss.clients.forEach`)

## 자주 놓치는 패턴 (Frequently Missed)

- **CSWSH (Cross-Site WebSocket Hijacking)**: Origin 검증 없음 + 쿠키 인증. 공격자 사이트에서 `new WebSocket('wss://victim/...')` → 브라우저가 자동으로 victim 쿠키 첨부 → 공격자 코드가 victim 세션으로 메시지 송수신.
- **`ws` 라이브러리는 기본적으로 Origin 검증 안 함**: `verifyClient` 콜백 미설정 시 모든 origin 허용.
- **Socket.IO 4.x `cors` 옵션**: 명시 필요. 기본은 cross-origin 허용.
- **인증을 핸드셰이크가 아닌 첫 메시지에 위임**: 첫 메시지 전에는 인증 없이 연결 가능 → 정보 노출/DoS.
- **JWT를 query string으로 전달**: 로그/Referer/proxy 노출. 또는 만료 토큰 첫 연결 후 영구 유지.
- **인증 토큰 만료 후 연결 유지**: 토큰 검증은 핸드셰이크 1회만, 만료 후에도 채널 유지.
- **메시지 핸들러에서 권한 미체크**: 핸드셰이크는 인증, 메시지는 무인가. `socket.on('admin:delete', ...)` 처리에 admin 체크 없음.
- **다른 사용자 채널 구독 가능**: `subscribe('/user/<other_id>/notifications')` — id 검증 없음.
- **메시지 broadcast 전 sanitize 없음**: 한 사용자의 XSS 페이로드가 모두에게 전달 → stored XSS.
- **수신 메시지가 SQL/NoSQL/명령어 sink로**: 별도 scanner와 결합.
- **Subprotocol 검증 누락** (`Sec-WebSocket-Protocol`): 클라이언트가 임의 subprotocol 지정.
- **메시지 크기/빈도 제한 없음**: DoS.
- **JSON.parse 후 prototype pollution**: prototype-pollution-scanner와 결합.
- **`socket.handshake.query.token`**: query 인증 + Origin 미검사.
- **`socket.io` namespace 인증 차이**: `/admin` namespace에는 인증, default namespace에는 누락.
- **STOMP over WebSocket**: SUBSCRIBE 권한 검사 누락.
- **Unauthenticated 진입 후 escalation 메시지**: 첫 메시지에서 user_id 자가 선언.
- **WebSocket secure (wss) 미사용**: 평문 ws://로 인증 토큰 노출.
- **Compression attack (CVE-2017-7526 류)**: permessage-deflate 활성 + 피해자 데이터 예측 공격 — CRIME의 WS 변형.
- **WebSocket frame smuggling**: fragmented frame을 악용한 메시지 경계 혼동.
- **SignalR long polling fallback**: WebSocket 차단 환경에서 HTTP로 fallback — 각 전송 수단별 인증 차이.
- **gRPC-Web over WebSocket**: proto 기반이지만 프록시가 ws로 변환 시 동일 문제.

## 안전 패턴 (FP Guard)

- **`verifyClient`** (ws) 또는 **`cors.origin`** (socket.io) 화이트리스트 + 정확 매칭.
- **핸드셰이크 시 인증 검증** (쿠키 또는 Authorization 헤더 또는 ticket 토큰).
- **Ticket 토큰 패턴**: HTTP endpoint로 단기 토큰 발급 → WebSocket 연결 시 첫 메시지로 제출 → 검증 후 통신 시작.
- **메시지 핸들러에 권한 체크** + 채널 구독 시 owner 검증.
- **메시지 sanitize 후 broadcast**.
- **메시지 크기/빈도 제한** (rate limit).
- **`wss://` 강제** + HSTS.
- **JWT 만료 시 자동 disconnect** + 클라이언트가 재인증 후 재연결.
- **subprotocol 화이트리스트**.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| Origin 화이트리스트 substring | 가능 | `https://allowed.com.attacker.com`, `https://allowed.com@attacker.com` |
| `null` Origin 허용 (파일 업로드 폼 호환용) | 가능 | `<iframe sandbox>` 안에서 WebSocket 연결 시 Origin null — 공격자 도메인에서 iframe으로 CSWSH |
| 핸드셰이크 인증만 + 연결 유지 | 가능 | 세션/토큰 만료 후에도 연결 유지 — 재검증 필요 |
| 메시지 rate limit per connection | 가능 | 여러 connection 동시 생성 — per user/IP rate limit 필요 |
| 채널 구독 owner 검증 (핸드셰이크 시) | 가능 | 검증 후 다른 채널 ID로 메시지 송신 시 서버가 cross-check 안 하면 우회 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 쿠키 인증 + Origin 검증 없음 | 후보 (라벨: `CSWSH`) |
| Origin 검증 substring/wildcard | 후보 |
| 핸드셰이크 인증 없음 + 첫 메시지로 인증 | 후보 (라벨: `LATE_AUTH`) |
| 메시지 핸들러에 권한 체크 없음 (특히 admin/delete 액션) | 후보 (라벨: `MESSAGE_AUTHZ`) |
| 채널 구독 시 owner 검증 없음 | 후보 (라벨: `CHANNEL_IDOR`) |
| broadcast 전 sanitize 없음 | 후보 (라벨: `BROADCAST_XSS`) |
| `ws://` 평문 + 인증 정보 전송 | 후보 |
| `verifyClient` + 화이트리스트 + 핸드셰이크 인증 + 메시지 권한 체크 | 제외 |
| Bearer 토큰 ticket + 짧은 TTL + 만료 시 disconnect | 제외 |

## 후보 판정 제한

WebSocket 연결을 직접 생성/관리하는 코드가 있는 경우만 분석. 외부 WebSocket 클라이언트만 사용하는 경우 제외.
