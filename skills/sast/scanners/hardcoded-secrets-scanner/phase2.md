### 기본 페이로드

#### 유효성 검증 — API Key/Token

```
# 탐지된 키로 실제 API 호출 시도 (읽기 전용 엔드포인트)
curl -H "Authorization: Bearer <FOUND_TOKEN>" https://api.target.com/v1/me

# AWS credential
aws sts get-caller-identity --access-key <FOUND_KEY> --secret-key <FOUND_SECRET>

# GitHub token
curl -H "Authorization: token <FOUND_TOKEN>" https://api.github.com/user
```

#### DB 비밀번호 검증

```
# PostgreSQL
psql postgresql://<user>:<FOUND_PASS>@<host>/<db> -c "SELECT 1"

# MySQL
mysql -h <host> -u <user> -p<FOUND_PASS> -e "SELECT 1"
```

### 우회 페이로드

```
# Base64 디코딩 후 확인
echo "<base64_value>" | base64 -d

# JWT secret 검증 (brute-force 아닌 직접 서명)
python3 -c "import jwt; print(jwt.encode({'sub':'admin'}, '<FOUND_SECRET>', algorithm='HS256'))"
```

### 참고사항

- 탐지된 비밀값의 **실제 유효성 확인은 읽기 전용 엔드포인트**로만 수행 (과도한 요청 금지)
- 유효성이 확인되면 즉시 보고 후 무효화 요청 권고
- 단순 존재만으로도 `confirmed` 처리 가능 (소스코드에 박혀 있다는 사실 자체가 증거)

### Phase 2 결과 파일 형식

```markdown
<!-- NOAH-SAST PHASE2 MANIFEST v2 -->
```json
{
  "scanner": "hardcoded-secrets-scanner",
  "schema_version": 2,
  "results": [
    {
      "id": "SECRET-1",
      "evidence": {
        "commands": ["curl -H 'Authorization: Bearer sk_live_...' https://api.stripe.com/v1/account"],
        "responses": {"http_status": 200, "body_excerpt": "{\"id\": \"acct_...\", \"object\": \"account\"}"},
        "observations": ["API key valid — live Stripe account confirmed"]
      }
    }
  ]
}
```
<!-- /NOAH-SAST PHASE2 MANIFEST -->
```

> **코드 존재 자체가 증거인 경우**: API 유효성 확인 없이도 `commands: []`, `observations: ["소스코드 X:Y에 하드코딩 확인 — 버전 관리 시스템에 영구 기록"]`으로 기록 후 phase2-review에 전달.
