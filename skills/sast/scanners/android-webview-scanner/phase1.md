---
id_prefix: ANDROID_WEBVIEW
rules_dir: rules/
---

> ## 핵심 원칙: "WebView에 들어가는 콘텐츠·URL·JS는 신뢰 경계를 넘는다"
>
> WebView가 원격/비신뢰 콘텐츠를 로드하거나, 네이티브가 비신뢰 데이터를 JS로 주입하거나, file 오리진 SOP가 열려 있으면 XSS·로컬 파일 탈취·브리지 악용으로 이어진다. 로드 대상의 신뢰도와 주입값 이스케이프 여부가 정탐의 핵심.

## Sink 의미론

| 라벨 | sink | 위험 조건 |
|---|---|---|
| `WEBVIEW_JS_INJECT` | `evaluateJavascript(x)`, `loadUrl("javascript:"+x)`, `loadData(...)` | 인자에 **비상수 데이터 문자열 결합**. `JSONObject.quote`/`Uri.encode` 등 명시적 이스케이프 동반 시 안전 격하 |
| `JS_BRIDGE_EXPOSURE` | `addJavascriptInterface(obj, name)` + `@JavascriptInterface` | 원격/비신뢰 URL 로드와 결합 시 위험. 로컬 asset + 최소노출 메서드면 정보성 |
| `FILE_SOP_BYPASS` | `setAllowUniversalAccessFromFileURLs(true)`, `setAllowFileAccessFromFileURLs(true)`, `setAllowFileAccess(true)`, `setAllowContentAccess(true)` (프로퍼티 `= true` 포함) | **`true`일 때만** 위험. `false` 명시는 방어(매치 제외). file:// 로드와 결합 시 로컬 파일 탈취 |
| `MIXED_CONTENT` | `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)` | https 페이지에서 http 리소스 로드 허용 |
| `TLS_ERROR_IGNORED` | `WebViewClient.onReceivedSslError { handler.proceed() }` | 조건 없는 `proceed()` → MITM |
| `NAV_UNVALIDATED` | `shouldOverrideUrlLoading` | host 검사에 `contains/startsWith/endsWith`(우회가능) 사용. **exact-equality 화이트리스트면 안전** |
| `CREDENTIAL_LEAK` | `setSavePassword(true)` | deprecated, 자격증명 평문 저장 |

## 안전 격하 신호 (정탐 아님)

- 주입값이 `JSONObject.quote(...)` / `Uri.encode(...)` / `TextUtils.htmlEncode(...)`로 이스케이프됨
- `setAllow*FileURLs(false)` 명시 (값 인식 룰이 이미 `(true)`만 매치하므로 false는 후보로 안 올라옴)
- 고정 상수 asset URL(`file:///android_asset/...`)만 로드하고 `shouldOverrideUrlLoading`이 exact-match로 외부 네비게이션 차단
- 강력한 CSP(meta) + DOMPurify가 렌더 콘텐츠에 적용 (XSS 측 cross-ref)

## Source-first 추가 패턴

```kotlin
// 위험: 비상수 데이터를 JS로 주입
webView.evaluateJavascript("show('" + userInput + "')", null)   // 인젝션
// 안전: 명시적 이스케이프
webView.evaluateJavascript("show(${JSONObject.quote(userInput)})", null)

// 위험: file 오리진 SOP 개방
settings.allowUniversalAccessFromFileURLs = true
// 안전: 명시적 차단 (룰이 매치하지 않음)
settings.allowUniversalAccessFromFileURLs = false
```

EasyWeb 등 프레임워크 래퍼(`runJavascript`/`EasyRunnableJavascript`)는 내부적으로 `evaluateJavascript`를 호출하므로, 래퍼 인자의 이스케이프 여부도 동일 기준으로 판정한다.
