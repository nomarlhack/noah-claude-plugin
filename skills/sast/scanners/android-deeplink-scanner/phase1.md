---
id_prefix: ANDROID_DEEPLINK
rules_dir: rules/
---

> ## 핵심 원칙: "외부에서 호출 가능한 모든 URI는 attacker-controlled"
>
> deeplink는 다른 앱/브라우저/QR/문자메시지에서 호출 가능 → 본질적으로 untrusted source. 받은 URI/extras가 WebView, startActivity, file 접근, JS bridge로 흘러가는 모든 경로를 추적. autoVerify 없는 custom scheme은 다른 앱이 가로챌 수 있어 자체로 위험. 사용자 인증 없이 진입 가능한 deeplink는 영향도 격상.

## Sink 의미론

deeplink sink는 "외부 호출 URI/extras가 컨트롤하는 모든 행위 지점"이다. AndroidManifest의 `<intent-filter>` 선언이 source 진입점이고, Java/Kotlin의 `getIntent().getData()` / `getQueryParameter()` 등이 read 지점이다. 이후 다음 sink로 흘러가면 위험:

| 라벨 | sink |
|---|---|
| `WEBVIEW_XSS` | `WebView.loadUrl(deeplinkParam)`, `WebView.loadDataWithBaseURL(...)`, `evaluateJavascript(deeplinkParam)` |
| `OPEN_REDIRECT` | 앱 내부 navigation/redirect URL이 deeplink param에서 직접 옴 |
| `INTENT_REDIRECT` | `Intent.parseUri(deeplinkParam, ...)` → `startActivity(parsedIntent)` (anti-pattern) |
| `FILE_SCHEME_LFI` | `WebView.loadUrl("file://...")` 또는 `FileInputStream(deeplinkParam)` |
| `JS_BRIDGE_EXPOSURE` | `addJavascriptInterface(...)` + `setJavaScriptEnabled(true)` + deeplink로 attacker URL 로드 |
| `PATH_TRAVERSAL` | deeplink param이 `File`/`FileInputStream`/`SharedPreferences` 키로 사용 |
| `AUTH_BYPASS` | deeplink 진입 시 세션/로그인 검증 없이 민감 화면(잔액/송금/설정) 진입 |
| `PENDING_INTENT_HIJACK` | `PendingIntent.getActivity(..., FLAG_MUTABLE)` + 외부 component에 전달 |
| `NO_AUTOVERIFY` | manifest에 `<data android:scheme="myapp"/>` 만 있고 `android:autoVerify="true"` 없음 (custom scheme 한정) |
| `ASSETLINKS_MISCONFIG` | autoVerify=true이지만 `.well-known/assetlinks.json` 부재/오설정 |
| `TASK_HIJACK` | `android:taskAffinity` 미명시 + `launchMode="singleTask"` (Strandhogg 변형) |
| `EXPORTED_DEEPLINK_NO_PERM` | `<activity android:exported="true">` + `<intent-filter>` 보유 + `android:permission` 없음 |

## Source-first 추가 패턴

Source는 항상 `getIntent()` 계열 — 그 후 어떤 라벨로 분류되는지 판정:

```kotlin
// Source 진입점 (다음이 모두 sink로 흘러갈 수 있음)
val intent = getIntent()
val uri: Uri? = intent.data                          // getData()
val redirect = uri?.getQueryParameter("redirect")    // 가장 흔한 sink 진입
val targetUrl = uri?.getQueryParameter("url")
val extra = intent.getStringExtra("payload")
val parsedIntent = Intent.parseUri(extra, 0)         // INTENT_REDIRECT 게이트
```

**host/path별 routing dispatch 패턴** — host당 다른 sink로 분기하므로 **모든 분기 경로 점검 필수**:
```kotlin
// 예: <app-scheme>://<host>?url=... 같은 host별 진입점 (대상 앱의 Manifest scheme/host로 판정)
when (uri?.host) {
    "adwebview" -> webView.loadUrl(uri.getQueryParameter("url")!!)  // ← WEBVIEW_XSS
    "open"      -> startActivity(Intent.parseUri(uri.getQueryParameter("intent"), 0))  // ← INTENT_REDIRECT
    "share"     -> handleShare(uri.getQueryParameter("data"))
    "settings"  -> navigateTo(uri.path)  // ← OPEN_REDIRECT 가능
}
```

`onCreate`/`onNewIntent`/`onStart` 모두 deeplink 진입점 — `singleTop`/`singleTask`는 onNewIntent로 들어옴.

AndroidManifest 진입점:
```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
  <intent-filter android:autoVerify="true">  <!-- App Links -->
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https" android:host="example.com" android:pathPrefix="/app"/>
  </intent-filter>
  <intent-filter>  <!-- custom scheme, autoVerify 불가 -->
    <data android:scheme="myapp"/>
  </intent-filter>
</activity>
```

## 자주 놓치는 패턴 (Frequently Missed)

| 패턴 | 위험 | 라벨 |
|---|---|---|
| `<intent-filter>` 보유한 `<activity>`가 `android:exported` 미명시 (API 31+ 기본 false이지만 명시 누락도 점검) | exported 의도 vs 실수 구분 필요 | `EXPORTED_DEEPLINK_NO_PERM` |
| custom scheme (`myapp://`)에 `autoVerify` 적용 시도 (custom scheme은 verify 불가 — 무의미) | 다른 앱이 동일 scheme 등록 → hijack | `NO_AUTOVERIFY` |
| `Intent.parseUri(userInput, Intent.URI_INTENT_SCHEME)` | 임의 component 호출 게이트 (intent://) | `INTENT_REDIRECT` |
| WebView `setAllowFileAccessFromFileURLs(true)` 또는 `setAllowUniversalAccessFromFileURLs(true)` | file:// 스킴에서 모든 origin 접근 → SOP 우회 | `FILE_SCHEME_LFI` |
| `loadUrl("javascript:" + userInput)` | XSS 직접 게이트 | `WEBVIEW_XSS` |
| `webView.loadUrl(uri.getQueryParameter("url"))` — **url 파라미터의 스킴 검증 없음** (`javascript:`/`data:`/`file:` 차단 누락) | URL 검증 없이 그대로 WebView load → XSS/LFI/origin 위장 | `WEBVIEW_XSS` |
| host/path별 routing (`when(uri.host){...}`, `if(uri.path == "/x")...`) — host 한 곳이라도 검증 누락 시 전체 약함 | 점검 시 **모든 host/path 분기** cross-check 필요 | (전 라벨) |
| `shouldOverrideUrlLoading` 미오버라이드 또는 `return false` — WebView 안에서 모든 URL 자동 로드 (`file://`, `javascript:`, `intent://`) | nested WebView load가 새로운 attack vector | `WEBVIEW_XSS` / `FILE_SCHEME_LFI` |
| `addJavascriptInterface(this, "Android")` (target SDK < 17 + Android 4.1 미만) | reflection으로 임의 코드 실행 | `JS_BRIDGE_EXPOSURE` |
| `PendingIntent.getActivity(ctx, 0, intent, 0)` (FLAG 미명시, API 30 이하 기본 mutable) | 외부에서 base intent 변조 → hijack | `PENDING_INTENT_HIJACK` |
| `<intent-filter>` 안에 여러 `<data>` 태그 — 하나라도 약하면 전체 약함 | 점검 시 모든 조합 cross-check 필요 | (전 라벨) |
| deeplink로 들어온 직후 `if (uri.scheme == "https")` 체크만 — host/path 미검증 | open redirect/XSS 게이트 | `OPEN_REDIRECT` |
| `onNewIntent`에서 deeplink 처리 (`singleTask`/`singleTop`) | 누락 시 onCreate만 점검하면 놓침 | (전 라벨) |
| `assetlinks.json`이 https://example.com/.well-known/assetlinks.json 부재 | autoVerify 실패 → 시스템이 chooser 표시 | `ASSETLINKS_MISCONFIG` |

## 안전 패턴 (FP Guard)

| 패턴 | 사유 |
|---|---|
| Host/scheme/path **모두** 화이트리스트 검증 후 sink 호출 | 검증 통과 입력만 도달 |
| `Uri.parse` 후 `getHost()` `equals` 정확 매칭 (substring/contains 금지) | 부분 일치 우회 차단 |
| WebView `loadUrl` 직전 `URL.getProtocol()` + `getHost()` allowlist | 스킴 + 호스트 동시 검증 |
| WebView `loadUrl` 직전 url 파라미터 스킴 화이트리스트 (`http`/`https`만) — `if(scheme !in setOf("http","https")) return` | `javascript:`/`data:`/`file:`/`intent:` 차단 |
| WebView `loadUrl` 직전 url 파라미터 스킴 블랙리스트 (`javascript`/`data`/`file`/`intent` 차단) — **단 trim() + lowercase() + URL decode 후 검증해야 안전** | XSS/LFI 1차 차단 (단 인코딩 우회 점검 필요) |
| `addJavascriptInterface` 사용 시 target SDK ≥ 17 + `@JavascriptInterface` 어노테이션 | reflection 차단됨 |
| `PendingIntent.FLAG_IMMUTABLE` 명시 (API 23+) | extras 변조 차단 |
| Custom scheme 미사용 — App Links (`https://` + autoVerify=true + assetlinks.json) | 시스템이 verify 강제 |
| deeplink 진입 후 인증 미통과 시 로그인 화면으로 강제 redirect | AUTH_BYPASS 방어 |
| `Intent.parseUri` 사용 시 `Intent.URI_ANDROID_APP_SCHEME` 같은 제한 플래그 | 임의 component 호출 차단 |
| `shouldOverrideUrlLoading` 오버라이드 + 새 URL을 화이트리스트 검증 후 `return true`로 차단 | WebView 내부 추가 navigation 차단 |

## 우회 가능 패턴

방어가 있어 보이지만 우회 가능한 회색 코드 — 후보 유지하되 사유 기록:

| 방어 | 우회 |
|---|---|
| `host.endsWith("example.com")` | `evil-example.com`, `attackerexample.com` 매칭 통과 |
| `host.contains("example.com")` | `evil.com/example.com` (path injection 후 substring 우회) |
| `scheme == "https"` 만 검증 | host 미검증 → open redirect/XSS |
| `path.startsWith("/safe")` | `/safe/../../evil` (정규화 누락) |
| 정규식 `^https://example\.com` | `https://example.com.evil.com` (`.`이 메타문자) |
| url 파라미터 스킴 블랙리스트 (`startsWith("javascript:")`) — 대소문자 미정규화 | `JaVaScRiPt:alert(1)`, `\tjavascript:alert(1)` (선행 공백/탭/CR/LF), URL 인코딩 `javascript%3Aalert(1)` |
| url 파라미터 스킴 블랙리스트 — URL decode 누락 | `%6Aavascript:alert(1)` (`j` 인코딩), `%6A%61%76%61%73%63%72%69%70%74:alert(1)` (전체 인코딩), Unicode escape `\u006Aavascript:` |
| url 파라미터 스킴 화이트리스트 (`http`/`https`만) | `https://attacker.com/redirect?to=javascript:alert(1)` — 화이트리스트 통과 후 attacker 페이지에서 javascript: 재진입 (chained redirect) |
| `shouldOverrideUrlLoading`에서 외부 스킴만 차단 (`http`/`https`만 허용) | `intent://...#Intent;...end` (intent scheme), `about:blank#javascript:...` 같은 fragment 변형 |
| autoVerify=true이지만 `assetlinks.json` 미배포 | verify 실패 → 시스템 chooser 표시 → 사용자 선택 시 다른 앱 실행 |
| WebView allowlist + `loadDataWithBaseURL(baseUrl, ...)` | baseUrl이 attacker-controlled면 origin 위장 |
| `@JavascriptInterface` 적용 + private 메서드 노출 | reflection으로 다른 클래스 메서드 호출 가능 |
| `FLAG_IMMUTABLE` 적용했으나 base intent 자체에 sensitive extras | extras 변조 못해도 redirect destination 유지 |
| `singleTask` + `taskAffinity=""` 명시 | 다른 task로 hijack 가능 — Strandhogg 2.0 변형 |
| Custom scheme 차단 후 https만 사용 | App Links의 `assetlinks.json`이 다른 도메인 fingerprint 포함 시 우회 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| `<intent-filter>` 활성 + Source(getIntent.getData)에서 위 표 sink 도달 + 화이트리스트 없음 | 후보 |
| `webView.loadUrl(uri.getQueryParameter("url"))` 류 — url 파라미터의 스킴 검증 (`javascript:`/`data:`/`file:` 차단) 코드 부재 | 후보 (`WEBVIEW_XSS`) |
| host별 routing 분기 중 한 host의 sink가 url 파라미터를 검증 없이 사용 | 후보 — 해당 host만 영향 |
| Source → sink 도달하지만 호출 전 `host == "example.com"` 정확 매칭 | 안전 |
| `loadUrl(uri)` 호출이지만 uri가 BuildConfig 상수 | 안전 (소스 추적 결과 untrusted 아님) |
| custom scheme + autoVerify 없음 + 민감 화면 진입 가능 | 후보 (`NO_AUTOVERIFY`) |
| autoVerify=true + `assetlinks.json` 미발견 | 후보 (`ASSETLINKS_MISCONFIG`) |
| `<activity exported="true">` + `<intent-filter>` 보유 + `android:permission` 부재 | 후보 (`EXPORTED_DEEPLINK_NO_PERM`) |
| `addJavascriptInterface` + deeplink 진입 + targetSdk ≥ 17 + `@JavascriptInterface` 어노테이션 적용 | 후보 (영향도 약함) — interface 메서드가 민감 행위면 영향도 격상 |
| `Intent.parseUri(getIntent().getDataString(), Intent.URI_INTENT_SCHEME)` 호출 후 startActivity | 후보 (`INTENT_REDIRECT`) |
| deeplink 진입 화면이 `requireLogin()` 같은 가드 전혀 없음 + 민감 행위 노출 | 후보 (`AUTH_BYPASS`) |
| Source 도달 sink 없음 (단순 `getIntent().getData()` 후 미사용) | 안전 |

## 후보 판정 제한

| 케이스 | 사유 |
|---|---|
| `<application android:debuggable="true">` 환경 한정 동작 | 빌드 설정 — prod APK는 별도 |
| 테스트 코드 (`androidTest/`, `test/`) 내 deeplink 처리 | 실 코드 아님 |
| Library 모듈 (`/libs/`, `/sdk/`) 내 deeplink — 호스트 앱이 manifest merge 안 하면 노출 안 됨 | 호스트 앱 manifest 확인 필요 |
| 빌드 variant 별 다른 manifest (debug only deeplink) | release manifest만 점검 |
| Android Studio `instrumentation` 진입점 | 테스트 전용 |
| TWA (Trusted Web Activity) 전용 deeplink — Chrome Custom Tabs로만 호출 가능 | 외부 호출 불가 |
- ProGuard/R8 minify 후 코드 — 디컴파일 결과 분석 (decompile 신뢰도 보고)
