---
id_prefix: HOSTHDR
rules_dir: rules/
---

> ## 핵심 원칙: "헤더 변조로 보안이 우회되지 않으면 취약점이 아니다"
>
> Host 헤더 변조 가능성 자체는 취약점이 아니다. 변조된 헤더가 실제로 보안에 영향(내부 자산 접근, 캐시 포이즈닝, URL 조작, 접근제어 우회 등)을 미쳐야 한다.

## Sink 의미론

Host Header / IP Spoofing sink는 두 카테고리:

1. **Host 헤더가 URL 생성에 사용**: 패스워드 리셋 메일, 이메일 인증 링크, OAuth 콜백 등의 절대 URL 생성. 공격자가 Host 헤더를 조작하면 피해자에게 공격자 도메인 링크가 발송됨.
2. **클라이언트 IP 식별이 X-Forwarded-For/X-Real-IP 등 변조 가능 헤더에 의존**: IP 화이트리스트, rate limiting, geo-blocking 우회.

| 언어 | Host 헤더 sink | IP 헤더 sink |
|---|---|---|
| Node/Express | `req.headers.host`, `req.hostname`, `req.get('host')`, `req.protocol+'://'+req.get('host')` | `req.ip`/`req.ips` (`trust proxy` 의존), `req.headers['x-forwarded-for']`, `x-real-ip`, `x-client-ip`, `req.connection.remoteAddress` |
| Django | `request.get_host`, `META['HTTP_HOST']`, `build_absolute_uri` (ALLOWED_HOSTS 없으면 위험) | `META['REMOTE_ADDR']`, `META.get('HTTP_X_FORWARDED_FOR','').split(',')[0]` |
| Flask | `request.host`, `request.host_url`, `url_for(_external=True)` | `request.remote_addr`, `request.access_route`, `ProxyFix` |
| Spring | `request.getServerName`, `request.getHeader("Host")`, `ServletUriComponentsBuilder.fromCurrentRequest` | `request.getRemoteAddr`, `getHeader("X-Forwarded-For")` |
| Rails | `request.host`, `request.host_with_port`, mailer `default_url_options` | `request.remote_ip`, `request.ip` |
| Go | `r.Host`, `r.Header.Get("Host")`, `r.Header.Get("X-Forwarded-Host")` | `r.RemoteAddr`, `r.Header.Get("X-Forwarded-For")` |
| C#/.NET | `Request.Host`, `HttpContext.Request.Headers["Host"]`, `Url.Action(...)` | `HttpContext.Connection.RemoteIpAddress`, `Request.Headers["X-Forwarded-For"]` |

## Source-first 추가 패턴

- 패스워드 리셋 토큰 메일 발송 코드
- 이메일 인증 메일 발송 코드
- OAuth/SSO redirect_uri 생성 코드
- 첨부 파일 다운로드 절대 URL 생성
- 푸시 알림 deep link
- 관리자 페이지 IP 화이트리스트 미들웨어
- Rate limiting 키 (IP 기반)
- Geo-blocking 미들웨어
- 로그인 실패 카운트 (IP 기반)

## 자주 놓치는 패턴 (Frequently Missed)

- **패스워드 리셋 이메일 host injection**: 가장 흔한 케이스. 공격자가 `Host: evil.com` 헤더로 리셋 요청 → 피해자 메일에 `https://evil.com/reset?token=...` 링크 → 피해자 클릭 시 토큰 탈취.
- **`X-Forwarded-Host` 헤더**: Host 헤더는 변경 안 하고 `X-Forwarded-Host`로 우회. Express `trust proxy` true면 사용됨.
- **`Forwarded` 헤더 (RFC 7239)**: `X-Forwarded-For`보다 신뢰성 있다고 오해되지만 동일하게 클라이언트 위조 가능.
- **Cache poisoning via Host 헤더**: CDN이 Host를 캐시 키에 포함하지 않으면, 변조된 호스트로 만든 응답이 다른 사용자에게 캐시 응답으로 전달.
- **`X-Forwarded-For` chain의 순서 혼동**: 첫 번째 IP를 클라이언트로 가정하지만, `X-Forwarded-For: attacker_fake, real_client, proxy1` 형태로 위조 가능. 마지막 trusted proxy로부터 역으로 carve해야 정확.
- **`X-Real-IP` 단일 헤더 신뢰**: nginx 설정에 따라 다름. 단일 헤더를 그대로 신뢰하면 위조 가능.
- **`req.connection.remoteAddress`도 프록시 뒤에서는 프록시 IP**: 직접 사용 시 IP 화이트리스트 무력화.
- **Python `META['REMOTE_ADDR']` + 미들웨어 부재**: 프록시 환경에서 항상 프록시 IP.
- **`ALLOWED_HOSTS` 미설정 (Django)**: Django는 미설정 시 모든 호스트 허용.
- **Spring `forwardedHeaderTransformer` 미적용**: gateway 뒤에서 잘못된 호스트.
- **`Host: 127.0.0.1` 으로 SSRF + cache poisoning 결합**.
- **메일 본문에 `Reply-To` 인젝션**: Host 헤더 외에 메일 헤더 자체 인젝션 (CRLF와 겹침).
- **WebSocket origin 검증**: WebSocket 핸드셰이크에서 `Host` 검증 없이 `Origin`만 검증하면 우회.
- **HTTP/2 `:authority` pseudo-header**: HTTP/1.1 Host 헤더와 다른 경로로 도달 — 일부 서버는 `:authority`만 검증하고 `Host`는 미검증.
- **CRLF in Host**: `Host: evil.com\r\nAdditional-Header: ...` — 일부 서버 파서가 관대할 때.
- **Web cache deception**: `/profile.css` 같은 정적 확장자로 캐시 강제 + Host 변조.
- **ASN/GeoIP spoof via X-Forwarded-For**: IP chain에 특정 국가 IP 삽입으로 geo-restriction 우회.

## 안전 패턴 (FP Guard)

- **고정 base URL**: `BASE_URL = process.env.BASE_URL` 같은 환경변수 + 코드에서 Host 헤더 미사용.
- **Django `ALLOWED_HOSTS`** 명시 + `build_absolute_uri` 사용.
- **Express `trust proxy`** 정확한 hop count 또는 신뢰 IP CIDR 지정 + 그 후 `req.ip` 사용.
- **Spring `ForwardedHeaderFilter`** 등록 + reverse proxy 신뢰.
- **`X-Forwarded-For` carve from right**: trusted proxy 수만큼 오른쪽에서 잘라내고 그 직전을 클라이언트 IP로.
- **Cache key에 Host 헤더 포함** (CDN 설정).
- **이메일 링크 host를 환경변수로 강제** (사용자 요청 host와 무관).
- **mailer `default_url_options = {host: ENV['HOST']}`** (Rails).

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `ALLOWED_HOSTS` substring match | 가능 | `allowed.com.attacker.com`, `allowed.com:80.attacker.com` |
| Host 헤더만 검증 (X-Forwarded-Host 미검증) | 가능 | `trust proxy` 활성 시 `X-Forwarded-Host: evil.com` 그대로 사용 |
| X-Forwarded-For 첫 번째 IP 신뢰 | 가능 | `X-Forwarded-For: fake_trusted_ip, real_client, proxy` — 오른쪽 carve 방식으로만 정확 |
| `X-Real-IP` 단일 헤더 신뢰 | 환경 의존 | nginx 설정이 실제 `X-Real-IP`를 overwrite해야 안전. 미설정 시 클라이언트 위조 통과 |
| HTTP/1.1 Host만 검증 | 가능 | HTTP/2 `:authority` 경로로 다른 값 전달 가능 |
| Cache key에 Host 미포함 (CDN) | 가능 | Web cache poisoning — Host 변조 응답이 다른 사용자에게 캐시됨 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 패스워드 리셋/인증 메일 URL이 `req.host`/`Host 헤더` 사용 + 화이트리스트 없음 | 후보 (라벨: `MAIL_HOST_INJECTION`) |
| `X-Forwarded-Host` 사용 + `trust proxy` 미설정 또는 과도 신뢰 | 후보 |
| IP 화이트리스트가 `X-Forwarded-For[0]` 또는 헤더 직접 신뢰 | 후보 (라벨: `IP_SPOOF`) |
| Rate limit 키가 사용자 변조 가능 헤더 IP | 후보 (라벨: `RATELIMIT_BYPASS`) |
| Django + `ALLOWED_HOSTS` 명시 확인 | 제외 (Host 인젝션 한정) |
| Express `trust proxy` 정확 설정 + `req.ip` 사용 | 제외 |
| 절대 URL이 환경변수 base URL 사용 | 제외 |
| WebSocket 핸드셰이크에서 Host 미검증 | 후보 (라벨: `WS_HOST`) |

## 후보 판정 제한

클라이언트 제어 가능 헤더가 보안 결정(URL 생성, 접근제어, rate limit, cache key)에 사용되는 경우만 후보. 단순 로깅 용도 사용은 제외.
