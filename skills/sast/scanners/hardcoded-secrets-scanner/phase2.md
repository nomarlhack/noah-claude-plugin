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
