---
id_prefix: DOMXSS
grep_patterns:
  - "location\\.hash"
  - "location\\.search"
  - "document\\.referrer"
  - "window\\.name"
  - "addEventListener.*message"
  - "onmessage"
  - "localStorage\\.getItem"
  - "sessionStorage\\.getItem"
  - "\\.innerHTML"
  - "\\.outerHTML"
  - "document\\.write"
  - "\\beval\\s*\\("
  - "setTimeout\\s*\\("
  - "setInterval\\s*\\("
  - "new Function\\s*\\("
  - "insertAdjacentHTML"
  - "\\.html\\s*\\("
  - "\\.append\\s*\\("
  - "\\.prepend\\s*\\("
  - "location\\.href\\s*="
  - "location\\.assign\\s*\\("
  - "location\\.replace\\s*\\("
  - "searchParams\\.get\\s*\\("
  - "useParams\\s*\\("
  - "useSearchParams"
---

> ## 핵심 원칙: "사용자 제어 클라이언트 source가 DOM sink에 도달하지 않으면 취약점이 아니다"
>
> 패턴 인덱스에 source/sink가 잡혔다고 바로 보고하지 않는다. 데이터 흐름을 직접 추적하고, sanitizer 부재와 source 제어 가능성을 함께 확인해야 후보다.

## Sink 의미론

DOM XSS sink는 "클라이언트 측에서 문자열을 코드/마크업으로 해석하는 지점"이다. 실행 컨텍스트별로 필요한 sanitizer 종류가 다르다.

| 컨텍스트 | sink 예시 | 필요 sanitizer |
|---|---|---|
| HTML parse | `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`, jQuery `.html`/`.append`/`.prepend`/`.after`/`.before`/`.replaceWith` | HTML sanitizer (DOMPurify) |
| 프레임워크 HTML bypass | React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `[innerHTML]`/`bypassSecurityTrust*`, Svelte `{@html}` | 동일 |
| JS eval | `eval`, `new Function`, 문자열 인자 `setTimeout`/`setInterval` | 차단 또는 화이트리스트 |
| URL navigation | `location.href=`/`assign`/`replace`, `anchor.href` | 스킴 검증 (`javascript:`/`data:` 차단) |
| 동적 import/script | `import(x)`, `new Worker(x)`, `<script src=x>` | URL origin 검증 |

## Source-first 추가 패턴

| 카테고리 | 예시 | 신뢰 등급 |
|---|---|---|
| URL-derived | `location.href/search/hash`, `URLSearchParams`, `document.URL`/`documentURI` | 직접 제어 |
| Cross-window | `postMessage` (origin 검증 없음), `window.name`, `document.referrer` | origin 검증 여부 |
| Storage-derived | `localStorage`/`sessionStorage`/`IndexedDB` | 2차 (선행 주입 전제) |
| WebSocket | `event.data` from `WebSocket.onmessage` | 서버/MITM 신뢰도 |
| DOM clobbering | `document.X` 가 HTML 요소에 의해 덮어쓰임 | 별도 |

## 자주 놓치는 패턴 (Frequently Missed)

- **`location.hash` → `decodeURIComponent` → sink**: hash는 서버로 전송되지 않아 WAF/서버 로그에 안 잡힘.
- **`postMessage`에서 origin 검증 누락**: `window.addEventListener('message', e => element.innerHTML = e.data)` — 어떤 origin이라도 메시지 전송 가능.
- **`window.name` persistence**: 탭을 가로질러 유지되는 `window.name`을 사용하는 코드.
- **jQuery `$(userInput)`**: selector에 `<img src=x onerror=...>` 같은 HTML이 들어가면 sink로 작동.
- **`history.pushState`/`replaceState`의 URL 인자에 사용자 입력**: 자체로 XSS는 아니지만 후속 hash 처리가 sink면 연결.
- **template literal로 HTML 조립 후 innerHTML**: ``` `<div>${x}</div>` ``` → `el.innerHTML = ...`. taint 추적이 함수 경계를 넘어야 함.
- **DOMParser + innerHTML**: `new DOMParser().parseFromString(x, 'text/html')` 자체는 안전하지만 결과를 `appendChild`하면 sink.
- **CSP report-only 모드**: 차단 안 되고 보고만. enforce가 아니면 방어 아님.
- **Trusted Types report-only**: 동일.
- **Vue `v-bind:href`/`:href` + `javascript:` 스킴**: Vue 자동 escape는 텍스트만 적용, href 스킴 차단 안 함 (Vue 2 일부 버전).
- **Angular DomSanitizer `bypassSecurityTrustHtml/Url/Script/ResourceUrl`**: 명시적 우회.
- **`document.write` after page load**: 페이지 전체를 덮어씀.
- **`eval` in JSON.parse fallback**: legacy `eval('(' + json + ')')`.

## 안전 패턴 (FP Guard)

- **React JSX 텍스트 보간 `{value}`**: 자동 escape.
- **Vue `{{ value }}` mustache, `v-text`**: 자동 escape.
- **Angular `{{ value }}` interpolation**: 자동 escape.
- **`element.textContent`/`innerText` 할당**: HTML 파싱 안 함.
- **DOMPurify.sanitize 직전 호출** + 옵션 기본값.
- **Trusted Types enforce 모드** + sink별 정책 정의 + CSP `require-trusted-types-for 'script'`.
- **`URL` 객체로 파싱 후 origin/protocol 화이트리스트 검증**.
- **`postMessage` 핸들러에서 `event.origin` 화이트리스트 검증**.
- **CSP `script-src` strict (`'self'` 또는 nonce/hash 기반)** + `unsafe-inline`/`unsafe-eval` 미허용.

## 후보 판정 의사결정

아래 4 조건을 **모두** 만족해야 후보:

1. Source → Sink 경로가 코드상 연결되어 있다.
2. 경로 중간에 sanitizer/이스케이프가 없다. 프레임워크 HTML bypass sink는 자동 escape가 무력화되므로 sanitizer 부재로 간주.
3. Source가 공격자 제어 가능 등급. URL-derived는 무조건 가능, postMessage는 origin 검증 없을 때, storage는 선행 주입 경로 식별 시.
4. Sink 실행 컨텍스트에 맞는 sanitizer가 부재. 컨텍스트별 필요 sanitizer 종류가 다르므로 적용된 sanitizer가 컨텍스트와 맞아야 한다.

CSP `script-src`/Trusted Types가 sink 실행을 코드상 명백히 차단(enforce + sink별 정책)하는 경우에 한해 등급을 한 단계 낮출 수 있다.

## 후보 판정 제한

위 4 조건을 모두 만족하는 경우만 후보. reflected XSS 케이스(서버 응답에 페이로드 반사)는 xss-scanner 범주이므로 제외.
