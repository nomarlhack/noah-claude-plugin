### WebView 동적 검증 cheat sheet

> 동적 검증은 adb + device/emulator + 대상 APK가 필요하다. 미충족 시 사용자에게 안내 후 `[환경 제한]`으로 표시한다. (공통 환경 점검은 android-deeplink-scanner/phase2.md 참조)

#### JS_BRIDGE_EXPOSURE / WEBVIEW_JS_INJECT
- exported 진입점이 있으면 `adb shell am start`로 WebView를 악성 콘텐츠와 함께 기동.
- 로드되는 페이지에서 노출된 브리지 메서드 호출 가능 여부 확인: `mdviewer.someMethod()`.
- 주입값 이스케이프 우회: 페이로드에 `");alert(1);//`, `</script>` 등을 넣어 JS 문자열 탈출이 발생하는지 관찰. `JSONObject.quote` 적용 시 탈출 불가 → 안전.

#### FILE_SOP_BYPASS
- file:// 페이지에서 `XMLHttpRequest`/`fetch`로 `file:///data/data/<pkg>/...` 읽기 시도.
- `allowUniversalAccessFromFileURLs=true`면 로컬 파일 응답 수신 → 탈취 가능. `false`면 차단(보안).

#### TLS_ERROR_IGNORED
- MITM 프록시(예: mitmproxy) 경유로 잘못된 인증서 제시 → `onReceivedSslError`가 `proceed()`로 무시하면 평문 가로채기 성립.

#### NAV_UNVALIDATED
- `shouldOverrideUrlLoading`의 host 검사 우회: `https://trusted.evil.com`, `https://evil.com/trusted` 등으로 화이트리스트 우회 시도. exact-match면 차단(보안).

판정: 트리거 확인 시 "확인됨", 환경 미충족/우회 불가 입증 시 각각 "후보"/"안전".
