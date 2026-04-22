**도구 선택:** curl만 사용. Playwright 미사용.

**기본 원칙:**
- 모든 테스트는 **서버 응답 동작**으로 판정
- 쓰기 작업 안전 수칙: 테스트 전용 리소스 생성 후 대상
- 각 라벨 phase1 후보별 개별 테스트
- **비교 기준 수립 필수**: 정상 요청 응답 먼저 캡처

---

## 라벨별 테스트

### `VALIDATION_MISMATCH` — 클라이언트 검증 우회

**정상 요청 (baseline):**
```bash
curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "https://target/api/<endpoint>" \
  -H "Content-Type: application/json" -H "Cookie: <session>" \
  -d '{"email":"valid@example.com","age":25,"name":"TestUser"}'
```

**검증 규칙 위반 페이로드:**
```bash
# 형식 위반 (이메일)
-d '{"email":"not-an-email","age":25,"name":"TestUser"}'

# 범위 위반 (음수 나이)
-d '{"email":"valid@example.com","age":-1,"name":"TestUser"}'

# 길이 위반 (빈 문자열)
-d '{"email":"valid@example.com","age":25,"name":""}'

# 길이 위반 (극단적)
-d '{"email":"valid@example.com","age":25,"name":"'$(python3 -c 'print("A"*100000)')'"}'

# enum 위반
-d '{"status":"INVALID_STATE","name":"x"}'

# 타입 위반 (string → array)
-d '{"name":["array"],"email":"x@x.com"}'
```

| 응답 | 판정 |
|---|---|
| 200/201 + 데이터 저장 (위반 데이터 수용) | 확인됨 |
| 400/422 + 검증 에러 | 안전 |
| 500 + DB 제약조건 에러 | 확인됨 (서버 검증 누락, DB 의존) |

### `TYPE_CONFUSION` — 타입 혼동

**기대 타입과 다른 타입 페이로드:**
```bash
# 문자열 → 배열 (NoSQLi 결합 가능 — nosqli-scanner)
-d '{"username":["admin"],"password":"test"}'

# 문자열 → 숫자
-d '{"username":0,"password":"test"}'

# 문자열 → boolean
-d '{"username":true,"password":"test"}'

# 문자열 → null
-d '{"username":null,"password":"test"}'

# 숫자 → 문자열
-d '{"quantity":"1abc","product_id":123}'

# 정수 → 부동소수
-d '{"id":1.5,"name":"x"}'

# 정수 오버플로
-d '{"count":9999999999999999999,"name":"x"}'
```

**JS 강제 변환 악용:**
```bash
# 빈 문자열 (falsy)
-d '{"token":"","admin":""}'

# 숫자 0 (falsy)
-d '{"count":0,"verified":0}'

# NaN
-d '{"price":"NaN","name":"x"}'

# Infinity
-d '{"max":"Infinity","name":"x"}'
```

| 응답 | 판정 |
|---|---|
| 200 + 인증 우회/권한 변경/데이터 변조 | 확인됨 |
| 200 + 형변환된 데이터 처리 | 확인됨 (의도치 않은 변환) |
| 400/422 + 타입 에러 | 안전 |
| 500 + 타입 에러 stack trace | 확인됨 (서비스 장애 게이트) |

### `NULL_SAFETY` — Null/Undefined 처리

```bash
# null 값
-d '{"username":null,"role":null}'

# 필드 누락
-d '{}'

# 필수 필드 일부만
-d '{"username":"admin"}'

# 중첩 객체 null
-d '{"user":null,"settings":null}'

# 빈 배열
-d '{"ids":[]}'

# undefined (JSON 외, JS 환경)
-d '{"x":undefined}'  # JSON 무효 — 일부 파서가 관대하면 통과
```

| 응답 | 판정 |
|---|---|
| 200 + null이 기본 권한/역할로 대체 | 확인됨 |
| 200 + 필수 필드 null로 저장 | 확인됨 |
| 500 + NullPointerException/TypeError stack | 확인됨 (서비스 장애) |
| 400/422 + "field is required"/"must not be null" | 안전 |

### `SCHEMA_DEFECT` — 스키마 검증 결함

**미정의 필드 주입:**
```bash
-d '{"name":"test","email":"x@x.com","role":"admin","isAdmin":true,"__internal_flag":true,"_id":"override","createdAt":"1900-01-01"}'

# 중첩 객체 미정의 필드
-d '{"profile":{"name":"test","verified":true,"admin_override":true}}'

# Array에 추가 필드 (object as array element)
-d '{"items":[{"id":1,"hidden_admin":true}]}'
```

**필수 필드 누락:**
```bash
-d '{"optional_field":"value"}'
```

**Content-Type 불일치:**
```bash
# JSON endpoint에 form-urlencoded
curl -X POST "https://target/api/<endpoint>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'name=test&role=admin&isAdmin=true'

# JSON endpoint에 text/plain (CSRF preflight 우회)
curl -X POST "https://target/api/<endpoint>" \
  -H "Content-Type: text/plain" \
  -d '{"name":"test","role":"admin"}'

# multipart/form-data
curl -X POST "https://target/api/<endpoint>" \
  -F "name=test" -F "role=admin" -F "isAdmin=true"
```

| 응답 | 판정 |
|---|---|
| 200/201 + 미정의 필드 저장/반영 | 확인됨 |
| 200/201 + 미정의 필드 무시 | 안전 |
| 200/201 + 기본값으로 저장 (보안 위험 시) | 확인됨 |
| 400/422 + "additional properties not allowed"/"unknown field" | 안전 |
| Content-Type 다른 요청 동일 처리 | 확인됨 (Content-Type 검증 누락) |
| 415 Unsupported Media Type | 안전 |

---

### 우회 페이로드

| 방어 | 우회 |
|---|---|
| 클라이언트만 검증 | 서버 직접 호출 — Postman/curl로 raw 요청 |
| 정규식 검증 (JS RegExp) | Unicode 문자 (`Café` vs `Café`), zero-width 삽입 |
| 길이 제한 (UTF-8 byte 기준) | UTF-8 multibyte로 글자 수보다 byte 적게 |
| Schema validation `additionalProperties: false` | 검증 후 다시 merge하는 코드 — 검증과 사용 시점 race |
| 정수 캐스트 후 검증 | `parseInt('123abc')` → 123 통과, 다른 곳 문자열 그대로 |

---

### 참고사항

- Mass assignment 경계: `role`/`isAdmin`/`admin` 변경 시 본 스캐너는 `SCHEMA_DEFECT`, cross-scanner는 business-logic `PRIV_ESCALATION`, idor `MASS_ASSIGNMENT` — 중복 가능성 보고서 명시
- NoSQLi 경계: MongoDB 연산자(`$gt`/`$ne`/`$regex`) 포함 응답은 `TYPE_CONFUSION` 아닌 nosqli-scanner 영역
- 비파괴적 원칙: 상태 변경 API는 테스트 전용 리소스 생성 후 대상
- 정상 비교 필수: 비정상 응답을 정상 응답과 diff 비교
- Unicode 정규화 누락 (NFC/NFD)은 이메일/username 중복 허용 게이트
- Zero-width/invisible 문자는 검증 우회 변형
- Case sensitivity 차이는 이메일 중복 검증 우회
- Turkish locale `i`.toUpperCase() → `İ` 같은 locale-aware 비교 실수
- JSON duplicate keys 파서별 동작 차이로 우회
- NaN/Infinity는 `JSON.parse` 미포함이지만 `parseFloat`/`Number`는 허용 — 범위 검증 통과
- Positional/named parameter 혼합 API는 다른 처리 경로
- 각 Test (`VALIDATION_MISMATCH`/`TYPE_CONFUSION`/`NULL_SAFETY`/`SCHEMA_DEFECT`) 별도 판정
- JSON Schema validator (Ajv 등)는 `coerceTypes: false` 권장 — true면 자동 형변환
- Spring `@Valid` + DTO는 컴파일 타임 강제 — 미적용 endpoint 점검
- Express middleware (joi/yup) 적용 위치 (route 정의보다 먼저인지) 확인
