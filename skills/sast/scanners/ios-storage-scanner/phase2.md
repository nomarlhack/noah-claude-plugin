### 기본 페이로드

#### INSECURE_USERDEFAULTS — UserDefaults 데이터 덤프

```bash
# 탈옥 기기 또는 시뮬레이터에서 UserDefaults plist 접근
# 시뮬레이터
find ~/Library/Developer/CoreSimulator -name "*.plist" | xargs grep -l "password\|token\|secret"

# iMazing / iTunes 백업에서 추출
# 또는 objection으로 런타임 덤프
objection -g TargetApp explore
ios nsuserdefaults get
```

#### KEYCHAIN_OVERACCESSIBLE — Keychain 접근성 확인

```bash
# objection으로 Keychain 항목 열람
ios keychain dump

# frida로 kSecAttrAccessible 값 확인
frida -U -n TargetApp -e "
  var SecItemCopyMatching = new NativeFunction(
    Module.findExportByName('Security', 'SecItemCopyMatching'),
    'int', ['pointer', 'pointer']
  );
"
```

#### PLAINTEXT_FILE — 파일 시스템 검사

```bash
# 앱 Documents / Library 디렉토리 파일 열람 (탈옥 또는 시뮬레이터)
objection -g TargetApp explore
file ls
file cat /var/mobile/Containers/Data/Application/<UUID>/Documents/
```

### 참고사항

- `UserDefaults`에 민감 데이터 저장은 코드 증거만으로 `confirmed` 처리 가능
- Keychain `kSecAttrAccessibleAlways`도 코드 증거로 `confirmed`
- Phase 2 동적 검증은 탈옥 기기 또는 시뮬레이터 환경 필요

### Phase 2 결과 파일 형식

```markdown
<!-- NOAH-SAST PHASE2 MANIFEST v2 -->
```json
{
  "scanner": "ios-storage-scanner",
  "schema_version": 2,
  "results": [
    {
      "id": "IOS_STORAGE-1",
      "evidence": {
        "commands": ["objection -g TargetApp explore -- 'ios nsuserdefaults get'"],
        "responses": {"http_status": 0, "body_excerpt": "{\"auth_token\": \"eyJ...\"}"},
        "observations": ["auth_token stored in UserDefaults in plaintext"]
      }
    }
  ]
}
```
<!-- /NOAH-SAST PHASE2 MANIFEST -->
```
