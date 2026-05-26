### 기본 페이로드

#### WEAK_CIPHER — ECB 패턴 분석

```python
# AES-ECB로 암호화된 데이터는 동일 블록이 동일 암호문 → 패턴 노출
# 앱에서 암호화된 데이터를 추출 후 분석
python3 -c "
import base64
ciphertext = base64.b64decode('<CAPTURED_CIPHERTEXT>')
# 16바이트 블록 비교
blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
print('Duplicate blocks:', len(blocks) - len(set(blocks)))
"
```

#### HARDCODED_KEY — 키 추출

```bash
# strings로 하드코딩 키 탐색
strings TargetApp.ipa | grep -E "^[A-Za-z0-9+/=]{32,}$"

# Ghidra / IDA로 상수 배열 역어셈블
# 또는 frida로 런타임 키 추출
frida -U -n TargetApp -e "
  Interceptor.attach(Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt'), {
    onEnter: function(args) {
      console.log('Key:', hexdump(args[5], {length: args[6].toInt32()}));
    }
  });
"
```

#### WEAK_HASH — MD5 충돌

```bash
# 앱에서 비밀번호 해시값 추출 후 레인보우 테이블 공격
# md5(<common_password>) 일치 여부 확인
python3 -c "import hashlib; print(hashlib.md5(b'password123').hexdigest())"
```

### 참고사항

- 코드에 `kCCOptionECBMode` 또는 `CC_MD5` 가 있으면 코드 증거만으로 `confirmed` 처리 가능
- 하드코딩 키는 `Insecure.MD5.hash` 형태는 CryptoKit이 위험성을 명시하므로 `confirmed`

### Phase 2 결과 파일 형식

```markdown
<!-- NOAH-SAST PHASE2 MANIFEST v2 -->
```json
{
  "scanner": "ios-crypto-scanner",
  "schema_version": 2,
  "results": [
    {
      "id": "IOS_CRYPTO-1",
      "evidence": {
        "commands": ["strings TargetApp | grep -E '^[A-Za-z0-9+/=]{32,}$'"],
        "responses": {"http_status": 0, "body_excerpt": "aes_key_hardcoded_value_here"},
        "observations": ["AES key found as string literal in binary"]
      }
    }
  ]
}
```
<!-- /NOAH-SAST PHASE2 MANIFEST -->
```
