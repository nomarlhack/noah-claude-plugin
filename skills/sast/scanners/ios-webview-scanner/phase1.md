---
id_prefix: IOS_WEBVIEW
rules_dir: rules/
---

> ## 핵심 원칙: "WKWebView에 들어가는 URL·JS·콘텐츠는 신뢰 경계를 넘는다"
>
> iOS WKWebView가 비신뢰 URL을 로드하거나, 네이티브가 비신뢰 데이터를 JS로 주입하거나, `navigationDelegate`가 URL 검증 없이 모든 네비게이션을 허용하면 XSS·로컬 파일 탈취·임의 JS 실행으로 이어진다. `UIWebView`는 deprecated이지만 레거시 코드베이스에서 동일 위험이 존재한다.

## Sink 의미론

| 라벨 | sink | 위험 조건 |
|---|---|---|
| `WEBVIEW_JS_INJECT` | `evaluateJavaScript(_:completionHandler:)` | 인자에 비상수 데이터 문자열 보간. `%@` 포맷팅도 위험. |
| `WEBVIEW_LOAD_URL` | `load(URLRequest)`, `load(_:mimeType:...baseURL:)` | 사용자 제어 URL을 scheme 검증 없이 로드 |
| `NAVIGATION_UNVALIDATED` | `webView(_:decidePolicyFor:decisionHandler:)` 에서 항상 `.allow` | host/scheme 검증 없는 전체 허용 |
| `ARBITRARY_LOADS` | `NSAllowsArbitraryLoads: true` in Info.plist | 평문 HTTP 전체 허용 → ATS 우회 |
| `JS_BRIDGE_EXPOSURE` | `add(_:name:)` (WKUserContentController) | 네이티브 메서드 노출 → 비신뢰 페이지에서 접근 가능 |
| `UIWEBVIEW_LEGACY` | `UIWebView` 사용 | Apple deprecated, WKWebView로 마이그레이션 필요. JS injection·credential 탈취 위험 |

## Source-first 추가 패턴

- URL schemes: `deeplink://`, `myapp://`, custom scheme에서 `queryItem` 값 추출
- URLComponents, URLQueryItem, URL.queryParameters
- AppDelegate application(_:open:options:) / SceneDelegate scene(_:openURLContexts:)

## 자주 놓치는 패턴 (Frequently Missed)

- `evaluateJavaScript("callback('\(userInput)')")` — Swift string interpolation이 JS 이스케이프 없이 주입
- `decidePolicyFor` 에서 `decisionHandler(.allow)` 단독 호출 — URL 검증 로직 전혀 없음
- `WKUserContentController.add(self, name: "bridge")` + 비신뢰 URL 로드 조합
- `UIWebView.loadHTMLString(userHTML, baseURL: nil)` — XSS 직접 게이트

## 안전 패턴 (FP Guard)

- `evaluateJavaScript` 인자가 컴파일 타임 상수 리터럴만 사용
- `decidePolicyFor` 내에서 `allowedHosts.contains(url.host)` exact-match 화이트리스트 후 allow
- `WKWebpagePreferences` / `allowsContentJavaScript = false`
- `WKAppBoundDomains` 설정으로 도메인 제한

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 비상수 데이터가 evaluateJavaScript 인자에 보간 | 후보 (라벨: `WEBVIEW_JS_INJECT`) |
| 사용자 제어 URL을 scheme 검증 없이 WebView 로드 | 후보 (라벨: `WEBVIEW_LOAD_URL`) |
| decidePolicyFor 에서 무조건 .allow | 후보 (라벨: `NAVIGATION_UNVALIDATED`) |
| UIWebView 사용 | 후보 (라벨: `UIWEBVIEW_LEGACY`) |
| JS bridge 노출 + 비신뢰 URL 조합 | 후보 (라벨: `JS_BRIDGE_EXPOSURE`) |
| 상수만 사용하거나 화이트리스트 검증 있음 | 제외 |

## 후보 판정 제한

순수 인앱 로컬 HTML(`Bundle.main.url(forResource:)` + 고정 asset만) 로드는 제외. 네트워크 연결 없는 순수 렌더러도 제외.
