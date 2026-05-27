---
id_prefix: XSS
rules_dir: rules/
exclusion_policy: capability
capability_via_sink_rule: true
---

> ## 핵심 원칙: "실행되지 않으면 취약점이 아니다"
>
> 위험해 보이는 패턴(`dangerouslySetInnerHTML`, `html_safe` 등)을 찾는 것만으로 취약점이 아니다. 사용자가 직접 제어할 수 있는 입력으로 스크립트가 실행되어야 한다. "서버가 침해되면", "API 응답이 변조되면" 같은 가정은 취약점이 아니다.
>
> **단, "즉시 실행되지 않음"을 "결코 실행되지 않음"으로 해석하지 않는다.** `ReactDOMServer.renderToStaticMarkup()`/`renderToString()` 내부의 `dangerouslySetInnerHTML`은 그 시점에 DOM에 삽입되지 않지만, 반환된 HTML 문자열이 이후 `$(el).html()`/`innerHTML`/다른 `dangerouslySetInnerHTML`로 전달되면 XSS가 발생한다. **반환값이 어디로 흘러가는지 추적을 완료하기 전까지 안전하다고 판단하지 않는다.**

## Sink 의미론

XSS Sink는 "공격자가 제어 가능한 문자열이 HTML 파서/JS 파서에 의해 코드로 해석되는 지점"이다. 즉 `.textContent` 같은 텍스트 전용 API는 sink가 아니고, HTML로 파싱되는 모든 API가 sink다.

**렌더링 구조에 따라 sink 위치가 갈린다 (XSS 고유):**
- **SPA (React/Vue/Angular)**: 서버는 JSON만 반환 → sink는 프론트엔드 JS 코드에 집중. 서버사이드에 `html_safe` 헬퍼가 있어도 호출되지 않으면 공격 가능한 sink가 아니다.
- **SSR (ERB/Slim/Jinja2/JSP/Thymeleaf)**: 서버 템플릿이 sink.
- **하이브리드**: 양쪽 모두 검색.
- **백엔드 전용 (렌더 sink가 분석 범위 밖 — 별도 프론트/웹뷰/앱 repo)**: 서버는 JSON만 반환하고 실제 렌더 sink(`innerHTML` 등)는 **이 repo에 없는 소비자**에 있다. **[필수] 이 경우 "repo에 렌더 sink 없음"을 "XSS 없음/이상 없음"으로 종결하지 말 것.** 대신 아래 "## Egress Sink 아키타입"을 적용하여, 사용자 제어 free-text가 escape/sanitize 없이 서비스를 떠나는 egress 경계(저장·API 응답)를 sink-of-record로 삼아 Stored XSS 후보로 등록한다. (이번 클래스 누락의 직접 원인이 이 분기 부재였다.)

**프론트엔드 Sink 패턴:**

| 프레임워크 | Sink |
|-----------|------|
| React | `dangerouslySetInnerHTML` |
| Vue | `v-html` |
| Angular | `[innerHTML]`, `bypassSecurityTrustHtml` |
| jQuery | `.html(`, `.append(`, `.prepend(`, `.after(`, `.before(`, `.replaceWith(` (변수가 인자) |
| Vanilla | `innerHTML`, `outerHTML`, `document.write(`, `insertAdjacentHTML(` |
| iframe | `srcDoc` (`sandbox` 없음 또는 `allow-scripts allow-same-origin` 동시 → 후보) |
| Svelte | `{@html value}` |
| Solid | `innerHTML={value}` |
| Astro | `set:html={value}` |
| Lit / Web Components | `unsafeHTML(value)` directive |
| 공통 | `eval(`, `Function(`, `setTimeout(문자열)`, `setInterval(문자열)` |

**서버사이드 Sink 패턴:**

| 프레임워크 | Sink |
|-----------|------|
| Rails | `html_safe`, `raw()`, `<%== %>` (ERB), `==` (Slim) |
| Django | `\|safe`, `mark_safe()`, `{% autoescape off %}` |
| Spring | `th:utext` (Thymeleaf), JSP `<%= %>` (no `c:out`) |
| Express | `res.send(userInput)` (Content-Type: text/html) |
| Laravel Blade | `{!! $value !!}` (`{{ $value }}`는 안전) |
| Go templates | `template.HTML(userInput)` 강제 캐스트 (자동 escape 우회) |
| ASP.NET Razor | `@Html.Raw(value)`, `@(new HtmlString(value))` |

## Egress Sink 아키타입 (백엔드 전용 repo — 렌더 소비자 분리 시)

렌더 sink가 분석 범위 밖(별도 프론트/웹뷰/앱)일 때 Stored XSS를 놓치지 않기 위한 보조 sink 정의. **아래 활성 조건을 모두 만족할 때만 적용**한다(과탐 방지).

**활성 게이트 (AND):**
1. 이 repo가 JSON API를 반환하는 백엔드이고, repo 내에 in-repo 렌더 sink(프론트 JS/SSR 템플릿)가 없다(프론트 소스 파일 0건 등).
2. 출력이 별도 소비자(웹/웹뷰/앱)에서 렌더링됨이 코드/아키텍처상 자명하다.

위 게이트가 거짓이면(=in-repo sink가 있거나 풀스택 repo) 본 아키타입을 적용하지 않고 기존 sink 규칙을 그대로 쓴다. — **기존 same-repo 탐지 동작은 변경하지 않는다.**

**sink 재정의 (egress 경계):**
- 사용자 제어 free-text가 escape/sanitize 없이 **DB 영속**(`repository.save(...)` 등)되거나 **응답 DTO로 반환**되는 지점을 sink-of-record로 본다.

**source 한정 (콘텐츠성 free-text만):**
- 대상: 자유 서술 문자열 필드 — `content`, `comment`, `title`, `description`, `nickname`, `memo`, `reason`, `answer` 등.
- **제외**: ID/숫자/enum/날짜/Boolean/URL-스킴 검증된 필드, 길이가 구조적으로 제한된 코드값. (이들은 egress 후보로 올리지 않는다.)

**sanitizer (있으면 제외):** `HtmlUtils.htmlEscape` / `Jsoup.clean` / OWASP `Encode.forHtml` / 정책 기반 sanitizer가 저장·반환 전에 적용됨이 코드로 확인되면 제외.

**[필수] 출력 형식 — 단일 통합 후보:** egress 필드를 **필드마다 개별 후보로 쪼개지 말 것.** 한 서비스의 "escape 없이 나가는 free-text 필드 목록"을 **하나의 STORED 후보**로 묶어 등록한다(예: "Stored XSS — 무가공 free-text egress: content, title, …"). 라벨은 STORED, 신뢰도는 저신뢰("sink=외부 소비자 렌더, 확인 필요")로 명시한다.

**[필수] 권장 조치 문구:** "출력 인코딩은 렌더링 소비자가 **출력 컨텍스트에 맞게**(textContent/프레임워크 기본 escape) 수행, 백엔드는 **정책 기반 sanitize(허용 태그 화이트리스트)**로 방어 심화"로 기재한다. **"무조건 서버사이드 HTML escape"는 이중 인코딩·저장 데이터 오염을 유발하므로 권하지 않는다.**

**dom-xss-scanner와의 경계:** 본 egress 아키타입은 xss-scanner(STORED)가 소유한다. dom-xss-scanner는 클라이언트 완결 DOM XSS 전용이므로 백엔드 전용 repo에서는 본 아키타입을 중복 등록하지 않는다(이중 카운트 방지).

## Source-first 추가 패턴

XSS source는 일반적인 HTTP 입력 외에 다음을 포함한다 (인덱스에 안 잡힐 수 있음):

- **API 응답 데이터**: SPA에서 fetch 결과를 sink로 흘리는 코드. **DB를 거쳐 API 응답으로 돌아오는 모든 데이터는 source로 취급한다.** 작성자가 일반 사용자/관리자/파트너인지와 무관.
- **Cookie / localStorage / sessionStorage 읽기**: 공격자가 다른 채널로 주입할 수 있는 storage값이 sink에 도달하는 경로
- **`window.location.hash` / `search` / `pathname`**: DOM XSS는 dom-xss-scanner에서 다루지만, hash/search값을 서버 sink로 보내는 reflected 케이스는 여기서 확인
- **`postMessage` 수신부의 `event.data`**
- **`URLSearchParams` / `new URL().searchParams`**
- **ServiceWorker / SharedWorker `postMessage` 수신**: `event.data`가 sink로 흐르는 경로
- **WebSocket 메시지 본문**: `ws.onmessage` 핸들러가 메시지를 sink에 직접 전달
- **IndexedDB / localForage 저장값 읽기**: 다른 출처에서 주입된 값이 저장되어 후속 sink에 흐르는 경우

각 source에서 시작해 위 sink 패턴까지 도달하는 경로가 인덱스에 없는지 grep으로 보강한다.

## 자주 놓치는 패턴 (Frequently Missed)

- **`renderToStaticMarkup()`/`renderToString()` 체인**: 컴포넌트 내부 `dangerouslySetInnerHTML`이 `renderToStaticMarkup` 안에 있다는 이유로 안전하다고 판단하면 안 됨. 반환 문자열이 이후 `$(el).html()`/`innerHTML`로 전달되는 경로 전수 추적 필수.
- **`stripTags`/`sanitize` 후 허용 태그의 이벤트 핸들러**: `<img>`/`<a>` 태그를 허용하는 sanitize는 `onerror`/`onclick` 같은 이벤트 핸들러 속성을 막지 않으면 우회됨. 허용 태그 화이트리스트만으로 안전하다고 판단 금지.
- **에디터 컨텐츠 (CKEditor/TinyMCE/Quill 등)**: 에디터 입력값을 그대로 `dangerouslySetInnerHTML`로 렌더링하는 패턴. 서버에서 sanitize 안 하면 stored XSS.
- **모달/알림/토스트 메시지**: `dangerouslySetInnerHTML={{__html: message}}` 형태에서 `message`가 i18n 키가 아니라 user-controlled string인 경우.
- **에러 메시지 반사**: `throw new Error(userInput)` 후 클라이언트가 `error.message`를 `innerHTML`로 출력하는 경우.
- **JSON.stringify 후 HTML 컨텍스트 삽입**: `<script>var data = ${JSON.stringify(userInput)}</script>` 패턴에서 `</script>`가 escape 안 되면 XSS.
- **markdown 렌더러**: `marked`/`markdown-it`의 `html: true` 옵션 또는 raw HTML 허용 설정.
- **SVG 업로드 렌더링**: 사용자 업로드 SVG를 `<img>`가 아닌 `<object>`/inline으로 렌더링.
- **링크 href에 `javascript:` 스킴**: `<a href={userInput}>` 패턴.
- **mXSS (Mutation XSS)**: 브라우저 HTML 재파싱 시점에 변형되어 sanitizer 우회 (DOMPurify 구버전 CVE-2020-26870 등). sanitize 호출이 보여도 라이브러리 버전·옵션 확인 필요.
- **Trusted Types 정책 미적용**: CSP `require-trusted-types-for 'script'` 없으면 sink가 plain string을 그대로 받음. 정책 헤더 부재 자체가 위험 가산 요인.
- **JS template literal HTML 렌더 경로**: `` `<div>${x}</div>` `` 형태 문자열이 `innerHTML`/`dangerouslySetInnerHTML`로 흐르는 chain.

## [필수] 능력형 토큰 클래스-제외 금지 + 의무 출력 (Safe-by-Proof §2-D)

HTML 출력 sink 능력형 토큰(`innerHTML`/`outerHTML`/`dangerouslySetInnerHTML`/`v-html`/`document.write`/`.html(` (jQuery)/`html_safe`/`raw(`/`<%== %>`/`{!! !!}`/`th:utext`)은 **매치 = HTML sink 실재**다. 일괄 제외 금지 — 개별 또는 동질 하위클래스(판별 축 명시: 예 "이스케이프 헬퍼가 sink 전에 적용"·"정적 리터럴") + spot-check. 같은 토큰이 안전·위험 양쪽에 나타나는 비동질 클래스 일괄 제외 금지(예: `raw(`를 `Draw`/`Withdraw` 부분매치와 진짜 `raw(userVar)`를 같은 클래스로 묶지 말 것).

**기계 게이트(JS/TS)**: 본 스캐너는 `exclusion_policy: capability` + `capability_via_sink_rule: true`다. broad-pattern ast 노이즈(출력 컨텍스트 등 수천 건)와 분리된 **고정밀 sink 룰**(`noah-<lang>-xss-innerhtml-sink`, JS/TS의 `innerHTML`/`dangerouslySetInnerHTML`/`document.write`/`.html()` 등)이 능력형 매치를 집계한다. 이 `-sink` 룰 매치(locindex rule_ids에 `-sink` 포함)는 **하나도 빠짐없이 dispositioned**되어야 한다. 결과 MD에 마커 1줄 포함(`phase1_review_assert.py`가 파싱):

```
<!-- OBLIGATION capability_matches=<-sink 룰 매치 수> dispositioned=<처리 수> method="<개별후보 N / 동질클래스 제외 M(판별축) / spot-check K>" -->
```

`capability_matches`는 locindex의 `-sink` 룰 매치 수와 같아야 하고(언더신고 불가), `dispositioned`가 그와 같아야 한다(잔여는 `[INCOMPLETE]`). 비-JS/TS HTML sink(`html_safe`/`raw`/`th:utext` 등)와 broad-pattern ast/generic 노이즈는 §6-A-2 COVERAGE로 처리한다. (sink 룰이 JS/TS만 있으므로 다른 언어 HTML sink는 본 지침 + COVERAGE로 보호 — 향후 언어별 sink 룰 확장.)

## 안전 패턴 (FP Guard)

코드에서 직접 확인된 경우에만 후보에서 제외 가능:

- **React JSX 텍스트 보간 `{value}`**: 자동 escape됨. `dangerouslySetInnerHTML`이 아닌 일반 보간은 sink가 아니다.
- **Angular `{{ value }}` (interpolation)**: 자동 escape. `[innerHTML]`/`bypassSecurityTrustHtml`만 sink.
- **Vue `{{ value }}` (mustache)**: 자동 escape. `v-html`만 sink.
- **`DOMPurify.sanitize(value)` 직후 sink로 전달**: 동일 라인/직전 라인에서 호출 확인 + 옵션이 기본값(또는 USE_PROFILES 외 위험 옵션 없음)인 경우.
- **Rails `<%= %>` (단일 등호)**: ERB 자동 escape. `<%== %>`/`raw`/`html_safe`만 sink.
- **Django `{{ value }}` (autoescape on)**: 자동 escape. `|safe` 필터만 sink.
- **Thymeleaf `th:text`**: 자동 escape. `th:utext`만 sink.
- **`textContent` / `innerText` 할당**: HTML 파싱 안 함. sink 아님.
- **서버 컨트롤러에서 입력값에 대한 명시적 sanitize/escape 호출 확인된 경우** (예: `sanitizeHtml(input, {allowedTags: []})`).
- **Svelte/Solid/Astro 자동 escape**: `{value}` 보간은 자동 escape. `{@html}`/`innerHTML={}`/`set:html`만 sink.
- **Laravel Blade 자동 escape**: `{{ $value }}` 자동 escape. `{!! !!}`만 sink.
- **OWASP Java Encoder**: `Encode.forHtml(x)`, `Encode.forJavaScript(x)` 컨텍스트별 인코더 호출 확인.
- **Trusted Types 정책 적용**: CSP `require-trusted-types-for 'script'` + `trusted-types <policy>` 헤더가 응답에 있으면 string sink 거부.
- **CSP nonce/strict-dynamic + 인라인 script 차단**: XSS 자체는 가능하나 실행 영향도 감소 — 후보 유지하되 영향도 라벨링.

**[필수] "API 응답 = 서버 데이터 = 안전" 판단 금지.** 데이터가 서버 API 응답에서 온다는 사실만으로 sink를 후보에서 제외하지 않는다. 서버 컨트롤러 코드에서 해당 필드의 sanitize 로직을 직접 확인해야 제외 가능.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `DOMPurify.sanitize(...)` (구버전 또는 비기본 옵션) | 가능 | mXSS 사례 (CVE-2020-26870 등). 라이브러리 버전 확인. `RETURN_TRUSTED_TYPE`/`SAFE_FOR_TEMPLATES` 옵션 누락도 위험. |
| `sanitize` allowedTags 화이트리스트 | 가능 | 허용 태그(`<a>`, `<img>` 등)에 `onclick`/`onerror` 이벤트 속성을 차단 안 하면 우회 |
| 길이 제한 (예: 50자) | 가능 | 짧은 페이로드 `<svg/onload=alert(1)>` (28자), `<img src=x onerror=alert(1)>` |
| 키워드 블랙리스트 (`<script>`) | 가능 | 대소문자 혼합 `<sCrIpT>`, 중첩 `<scr<script>ipt>`, 공백 변형 `<script\t>`, `<script/x>` |
| `<` `>` HTML escape만 적용 (속성 컨텍스트) | 가능 | 속성 안 컨텍스트(`<a href="${x}">`)에선 `"` 이스케이프 누락 시 `" onclick=alert(1) x="` 우회 |
| URL 스킴 블랙리스트 (`javascript:`) | 가능 | `JaVaScRiPt:`, `java\tscript:`, `data:text/html,...` 우회 |

| 조건 | 판정 |
|------|------|
| Source가 사용자 제어 가능 + sink 도달 + 검증 코드 없음 | 후보 (reflected/stored 구분하여 명시) |
| Source가 사용자 제어 가능 + sink 도달 + 부분 검증 (예: 길이/타입만) | 후보 + "무엇이 검증되고 무엇이 안 되는지" 기술 |
| Source가 사용자 제어 가능 + sink 도달 + 위 안전 패턴 항목 코드 확인 | 제외 + 근거 라인 명시 |
| Sink는 있으나 source 추적 불가 (변수가 어디서 오는지 모름) | 후보 유지 (직관 제외 금지) |
| Sink가 SPA 빌드에서 호출되지 않는 서버사이드 헬퍼 | 제외 (실제 라우트/뷰에서 호출되지 않음을 grep으로 확인) |
| `renderToStaticMarkup` 내부 sink, 반환값 흐름 추적 미완료 | 후보 유지 |
| 백엔드 전용 repo + 콘텐츠성 free-text가 escape/sanitize 없이 저장·응답으로 egress (렌더 sink는 범위 밖 소비자) | 후보 유지 (STORED, 저신뢰) — "## Egress Sink 아키타입"의 단일 통합 후보로 등록. "repo에 렌더 sink 없음"을 제외 근거로 쓰지 말 것 |

**Reflected vs Stored 라벨 (트리거 채널 분류):**
- **REFLECTED**: URL/파라미터/헤더가 동일 응답에 즉시 출력
- **STORED**: DB/파일/세션에 저장 후 다른 요청에서 출력
- **DOM**: 클라이언트 JS만으로 source→sink 완결 (dom-xss-scanner와 중복 시 dom-xss-scanner에 위임)
- **SELF**: 트리거가 본인 세션에만 영향 (예: localStorage 본인 값) — 위협 모델 약함이지만 후보 유지하고 라벨링

## 후보 판정 제한

**서버 내부 설정값**(환경변수, 하드코딩 상수, 인프라 설정)이 source인 경우에만 제외. 그 외 모든 입력(일반 사용자, 관리자, 파트너, 외부 API, 연동 시스템 등)이 source인 경우 후보.
