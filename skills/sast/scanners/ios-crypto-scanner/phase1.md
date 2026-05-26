---
id_prefix: IOS_CRYPTO
rules_dir: rules/
---

> ## 핵심 원칙: "iOS는 CryptoKit을 쓰고, CommonCrypto는 올바른 파라미터로만"
>
> ECB 모드·MD5·SHA1·짧은 IV·하드코딩된 키는 암호화를 명목상으로 만든다. AES-ECB는 패턴이 노출되고, MD5/SHA1은 충돌 가능하며, 고정 IV는 암호문을 예측 가능하게 만든다.

## Sink 의미론

| 라벨 | sink | 위험 조건 |
|---|---|---|
| `WEAK_CIPHER` | `CCCrypt(kCCAlgorithmDES/3DES/RC4)`, `kCCOptionECBMode` | DES·3DES·RC4 사용 또는 AES-ECB 모드 |
| `WEAK_HASH` | `CC_MD5`, `CC_SHA1`, `Insecure.MD5/SHA1` (CryptoKit) | 비밀번호 해싱·서명 검증에 MD5/SHA1 |
| `HARDCODED_KEY` | AES key/IV가 코드 내 상수 리터럴 | key/IV 하드코딩 → 리버싱으로 즉시 탈취 |
| `STATIC_IV` | CCCrypt IV 파라미터에 고정 바이트 배열 | 동일 IV 재사용 → 암호문 패턴 노출 |
| `INSECURE_RANDOM` | `arc4random()` for cryptographic use, `drand48()` | 암호화 목적 취약 난수 |
| `WEAK_KEYDERIVATION` | PBKDF2 반복 횟수 < 100,000 | 브루트포스 취약 |

## Source-first 추가 패턴

- 암호화 키·IV 변수 (`let key = Data(...)`, `var aesKey: [UInt8] = [...]`)
- PBKDF2 `CCKeyDerivationPBKDF` 파라미터 (rounds)
- `kCCOptionECBMode` 비트 플래그 사용

## 자주 놓치는 패턴 (Frequently Missed)

- `let iv = [UInt8](repeating: 0, count: 16)` — 0으로 채운 정적 IV
- `CC_MD5(data, length, result)` — 비밀번호 저장에 MD5
- `kCCOptionECBMode` 플래그 — AES-ECB
- `CCKeyDerivationPBKDF(..., rounds: 1000, ...)` — PBKDF2 반복 횟수 부족

## 안전 패턴 (FP Guard)

- `CryptoKit.AES.GCM` / `ChaChaPoly` — 최신 인증 암호화
- `Insecure.MD5` / `Insecure.SHA1` — CryptoKit이 명시적으로 `Insecure` 네임스페이스에 분리함
- `CCKeyDerivationPBKDF` rounds ≥ 100,000
- `SecRandomCopyBytes` — 암호화 안전 난수

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| DES/3DES/RC4 알고리즘 사용 | 후보 (라벨: `WEAK_CIPHER`) |
| AES-ECB 모드 (`kCCOptionECBMode`) | 후보 (라벨: `WEAK_CIPHER`) |
| 비밀번호 해싱에 MD5/SHA1 | 후보 (라벨: `WEAK_HASH`) |
| 암호화 키/IV가 코드 상수 | 후보 (라벨: `HARDCODED_KEY`) |
| IV가 0 배열 또는 고정값 | 후보 (라벨: `STATIC_IV`) |
| PBKDF2 rounds < 100,000 | 후보 (라벨: `WEAK_KEYDERIVATION`) |
| CryptoKit 최신 API + 안전 파라미터 | 제외 |

## 후보 판정 제한

체크섬 목적(무결성 검증이 아닌 비교)의 MD5 사용, 또는 명시적으로 보안 비관련 해싱은 제외 검토.
