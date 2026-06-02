---
id_prefix: ANDROID_ACCOUNTMANAGER
rules_dir: rules/
---

> ## 핵심 원칙: "AccountManager에서 꺼낸 authToken/password는 caller 검증 없이는 누구든 탈취 가능"
>
> Android AccountManager는 SSO 토큰·비밀번호를 시스템 수준으로 관리하지만,
> AbstractAccountAuthenticator.getAuthToken() 구현에서 호출자 신원을 검증하지 않거나,
> peekAuthToken()·getPassword()로 캐시 토큰을 직접 반환하면 GET_ACCOUNTS 권한만 있는 앱이
> 다른 앱의 SSO 토큰을 탈취할 수 있다.

## Sink 의미론

| 라벨 | sink | 위험 조건 |
|---|---|---|
| `AUTH_TOKEN_EXPOSURE` | `getAuthToken()` / `peekAuthToken()` / `blockingGetAuthToken()` | caller UID/패키지 검증 없이 토큰 반환 → 임의 앱 탈취 |
| `PASSWORD_EXPOSURE` | `getPassword()` / `addAccountExplicitly(userdata)` | 비밀번호·민감 데이터를 검증 없이 반환/저장 |
| `TOKEN_IN_BUNDLE` | `bundle.putString(KEY_AUTHTOKEN, ...)` | getAuthToken() 응답 Bundle에 토큰을 caller 검증 없이 삽입 |
| `TOKEN_IN_LOG` | `Log.d/i/e(token)` | 토큰·비밀번호를 Logcat에 출력 |
| `TOKEN_IN_INTENT` | `Intent.putExtra(KEY_AUTHTOKEN, ...)` | 토큰을 implicit Intent extra에 포함 → 도청 가능 |
| `INSECURE_ACCOUNT_STORE` | `getUserData()` / `setUserData()` | 민감 필드를 userdata에 평문 저장 → GET_ACCOUNTS 앱이 읽기 가능 |

## 안전 격하 신호 (정탐 아님)

- `getAuthToken()` 내부에서 `response.getCallerUid()` 또는 `Binder.getCallingUid()`로 caller UID 검증 후 허용 목록 확인
- `getAuthToken()` 내부에서 `AccountManager.KEY_ANDROID_PACKAGE_NAME` 번들 키로 caller 패키지명 확인
- 토큰을 반환 전 `checkCallingOrSelfPermission`으로 커스텀 서명 권한 검증
- peekAuthToken 결과를 내부 로직에만 사용하고 외부 전달 없음
- `addAccountExplicitly(account, password, null)` — userdata null (민감 데이터 미저장)

## Source-first 추가 패턴

```kotlin
// 취약: caller 검증 없이 토큰 반환
override fun getAuthToken(
    response: AccountAuthenticatorResponse,
    account: Account,
    authTokenType: String,
    options: Bundle
): Bundle {
    val token = tokenCache[account.name]   // 누구든 요청 가능
    return Bundle().apply {
        putString(AccountManager.KEY_AUTHTOKEN, token)  // AUTH_TOKEN_EXPOSURE
        putString(AccountManager.KEY_ACCOUNT_NAME, account.name)
        putString(AccountManager.KEY_ACCOUNT_TYPE, account.type)
    }
}

// 취약: peekAuthToken 결과를 Intent extra로 전달
val token = accountManager.peekAuthToken(account, AUTH_TYPE)
startActivity(Intent("com.other.app.ACTION").putExtra("token", token)) // TOKEN_IN_INTENT

// 취약: 토큰 Logcat 출력
Log.d("Auth", "SSO token: $token")  // TOKEN_IN_LOG

// 안전: caller UID 검증
override fun getAuthToken(...): Bundle {
    val callerUid = Binder.getCallingUid()
    val callerPkg = options.getString(AccountManager.KEY_ANDROID_PACKAGE_NAME) ?: ""
    require(ALLOWED_UIDS.contains(callerUid)) { "Unauthorized caller" }
    ...
}
```

## Phase 1 판정 기준

### Source 도달성
- `getAuthToken()` / `peekAuthToken()` / `getPassword()` 호출 결과가 외부 전달(Bundle/Intent/Log)에 도달하는지 확인
- AbstractAccountAuthenticator 구현체에서 `Binder.getCallingUid()` / `response.getCallerUid()` 호출 여부 확인

### 소유권·인가 게이트
- caller UID 화이트리스트 비교 존재 여부
- 서명 기반 커스텀 권한(`android:protectionLevel="signature"`) 적용 여부
- `checkCallingOrSelfPermission` / `enforceCallingOrSelfPermission` 호출 여부

### 판정
| 조건 | 판정 |
|------|------|
| getAuthToken()에 caller 검증 없고 토큰 Bundle 반환 | **TP** |
| peekAuthToken() 결과가 Intent extra / Log에 포함 | **TP** |
| getPassword() 반환값 외부 전달 | **TP** |
| getUserData()로 민감 필드 외부 전달 | **TP** |
| caller UID/패키지 검증 후 허용 목록 확인 | **FP** |
| 서명 권한으로 보호된 내부 전용 호출 | **FP** |
