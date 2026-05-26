---
id_prefix: IOS_STORAGE
rules_dir: rules/
---

> ## 핵심 원칙: "민감 데이터는 Keychain에, 나머지는 암호화 속성과 함께"
>
> iOS 앱이 비밀번호·토큰·개인정보를 UserDefaults·평문 파일·CoreData(암호화 없음)에 저장하면 기기 탈취 또는 iTunes/ADB 백업으로 탈취된다. Keychain도 접근 속성(`kSecAttrAccessible`)이 너무 관대하면 잠금 해제 없이 접근 가능하다.

## Sink 의미론

| 라벨 | sink | 위험 조건 |
|---|---|---|
| `INSECURE_USERDEFAULTS` | `UserDefaults.set(_:forKey:)` | 비밀번호·토큰·개인정보가 UserDefaults에 저장 — 백업·jailbreak 노출 |
| `PLAINTEXT_FILE` | `FileManager`, `Data.write(to:)`, `NSData.write(to:)` | 민감 데이터를 암호화 속성 없이 파일로 기록 |
| `KEYCHAIN_OVERACCESSIBLE` | `SecItemAdd`, `kSecAttrAccessible` | `kSecAttrAccessibleAlways` / `kSecAttrAccessibleAlwaysThisDeviceOnly` — 기기 잠금 해제 불필요 |
| `WEAK_COREDATA` | `NSPersistentStoreCoordinator` | `NSPersistentStoreFileProtectionKey` 미설정 — DB 파일 평문 |
| `CLIPBOARD_LEAK` | `UIPasteboard.general.string = ...` | 민감 데이터를 클립보드에 기록 → 다른 앱 접근 가능 |
| `PLIST_PLAINTEXT` | `PropertyListSerialization`, `.plist` 파일 기록 | 민감 값 평문 plist 저장 |

## Source-first 추가 패턴

- `password`, `token`, `secret`, `apiKey`, `authToken`, `accessToken` 변수명을 추적
- 네트워크 응답에서 꺼낸 credentials / authentication 정보
- 사용자 입력 비밀번호 필드

## 자주 놓치는 패턴 (Frequently Missed)

- `UserDefaults.standard.set(password, forKey: "user_password")` — 가장 흔한 실수
- Keychain에 `kSecAttrAccessibleAlways` 저장 — 화면 잠금 무관하게 접근
- `NSLog("Token: \(authToken)")` — 로그에 토큰 노출 (log-injection-scanner cross-ref)
- Core Data migration 후 `NSFileProtection` 재설정 누락
- `do { try data.write(to: url) }` — `.completeFileProtection` 옵션 없음

## 안전 패턴 (FP Guard)

- Keychain에 `kSecAttrAccessibleWhenUnlocked` / `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
- `Data.write(to:options:)` 에 `.completeFileProtection` 또는 `.completeFileProtectionUnlessOpen` 옵션
- `NSPersistentStoreFileProtectionKey: FileProtectionType.complete`
- 저장 전 `CryptoKit`/`CommonCrypto`로 암호화

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 민감 데이터 변수가 UserDefaults에 저장 | 후보 (라벨: `INSECURE_USERDEFAULTS`) |
| 데이터 파일 쓰기에 FileProtection 옵션 없음 | 후보 (라벨: `PLAINTEXT_FILE`) |
| Keychain에 `kSecAttrAccessibleAlways` 사용 | 후보 (라벨: `KEYCHAIN_OVERACCESSIBLE`) |
| 클립보드에 비밀번호/토큰 기록 | 후보 (라벨: `CLIPBOARD_LEAK`) |
| FileProtection/Keychain 안전 설정 있음 | 제외 |

## 후보 판정 제한

비민감 설정값(UI 프리퍼런스, 언어 설정 등)의 UserDefaults 저장은 제외. 변수명/컨텍스트로 민감 데이터 여부 판단.
