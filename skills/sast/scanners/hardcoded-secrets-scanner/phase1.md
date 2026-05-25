---
id_prefix: SECRET
archetype: presence
---

> ## 핵심 원칙: "코드에 박힌 비밀값은 그 자체로 취약점이다"
>
> 하드코딩된 비밀값(API key, password, private key, token)은 버전 관리 시스템에 영구 기록되어 모든 접근자에게 노출된다. 실제 악용 여부와 무관하게 후보로 등록한다. 단, 테스트/예시 코드의 placeholder는 제외한다.

## Sink 의미론

하드코딩된 비밀값의 유형:

| 유형 | 패턴 예시 |
|------|----------|
| API Key | `API_KEY = "sk-..."`, `apiKey: "AIza..."` |
| DB 비밀번호 | `password = "prod_pass123"`, `DB_PASS = "..."` |
| JWT secret | `JWT_SECRET = "my_secret_key"` |
| Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| OAuth secret | `CLIENT_SECRET = "..."` |
| Cloud credential | `AWS_SECRET_ACCESS_KEY = "..."` |
| Generic token | `token = "ghp_..."`, `bearer = "..."` |

## 자주 놓치는 패턴 (Frequently Missed)

- **환경 변수처럼 보이지만 하드코딩**: `SECRET_KEY = os.getenv("SECRET_KEY", "fallback_hardcoded")`
- **테스트 외 실 코드의 하드코딩**: `settings.py`, `application.properties`, `config.yml`에 직접 삽입
- **Base64 인코딩된 시크릿**: `secret = "c2VjcmV0X2tleV8xMjM="` (디코딩하면 `secret_key_123`)
- **주석에 남겨진 시크릿**: `// password: admin123`

## 안전 패턴 (FP Guard)

- `os.environ.get("SECRET_KEY")`, `process.env.SECRET_KEY` 환경 변수 참조 → 제외
- `${SECRET_KEY}` 설정 파일 변수 참조 → 제외
- 테스트 파일(`test_*.py`, `*.test.ts`, `spec/**`) 내 명시적 테스트 픽스처 → 제외 (단, 프로덕션 코드와 동일한 비밀값이면 후보)
- `"your_api_key_here"`, `"<YOUR_SECRET>"`, `"REPLACE_ME"` 명시적 placeholder → 제외

## 후보 판정 의사결정

| 조건 | 판정 |
|------|------|
| 고엔트로피 문자열이 비밀값 변수명에 직접 할당 | 후보 (라벨: `HARDCODED_SECRET`) |
| 환경 변수 없는 fallback에 실제 시크릿처럼 보이는 값 | 후보 (라벨: `HARDCODED_FALLBACK`) |
| PEM 블록 직접 삽입 | 후보 (라벨: `EMBEDDED_KEY`) |
| 환경 변수 참조 또는 명시적 placeholder | 제외 |
| 테스트 코드의 픽스처 (프로덕션 코드와 분리됨) | 제외 |

## 후보 판정 제한

- `.env.example`, `README.md` 내 예시 값은 제외
- 오픈소스 라이브러리의 기본 예제값(`changeit`, `changeme`, `secret`) → DEVIANT 신호 없으면 제외 검토
