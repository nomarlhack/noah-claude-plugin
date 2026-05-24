---
id_prefix: IDOR
rules_dir: rules/
---

> ## 핵심 원칙: "다른 사용자 리소스에 실제로 접근할 수 있어야 취약점이다"
>
> `findById(id)` 자체는 취약점이 아니다. 사용자 A의 인증 정보로 사용자 B의 리소스 식별자를 보냈을 때 서버가 B의 리소스를 반환해야 한다.

## Sink 의미론

IDOR sink는 "엔드포인트가 객체 식별자를 받고 그 식별자로 리소스를 조회/수정하는데, 인증된 사용자와 그 객체의 소유 관계를 검증하지 않는 지점"이다. 권한 체크가 라우트 레벨(`role == admin`)만 있고 객체 레벨(`resource.owner == user`)이 없는 케이스가 가장 흔함.

| 카테고리 | 패턴 |
|---|---|
| 경로 파라미터 | `/users/:id`, `/orders/{orderId}`, `/api/v1/posts/{slug}` |
| 쿼리 파라미터 | `?user_id=`, `?account=`, `?org=` |
| 바디 파라미터 | `{userId: ..., action: ...}` (멀티 액션 핸들러) |
| Hidden form field | `<input type=hidden name=id value=...>` |
| 내부 API 노출 | `/internal/...`이 외부 라우트로 누설 |
| WebSocket 채널 ID | `subscribe('/user/:id/...')`, `JOIN room <id>` |
| gRPC method 인자 | `.proto` service method의 ID 필드 |
| SSE stream URL | `/events/:resourceId/stream` |

## Source-first 추가 패턴

- 사용자 ID/주문 ID/문서 ID/게시글 ID를 path/query/body로 받는 모든 라우트
- file ID 다운로드 라우트 (`/files/:id/download`)
- 첨부파일 직접 URL (`/uploads/{uuid}` — UUID 추측 어려움이 보안이 아니라 인가가 필요)
- presigned URL 생성 endpoint
- batch endpoint (`{ids: [...]}`)
- GraphQL `node(id: ...)` resolver
- 검색 endpoint (`?q=...&owner=...`)
- 보고서 export endpoint
- 멀티테넌시 endpoint (org_id를 사용자 입력으로)
- gRPC service method (proto 정의 + 핸들러)
- JWT claim 안에 객체 ID 포함된 경우 (토큰 변조 가능 시 IDOR)
- 이메일/전화번호 기반 조회 (`?email=`) — PII가 식별자 역할

## 자주 놓치는 패턴 (Frequently Missed)

- **식별자는 이름이 아니라 역할로 판별**: 외부 입력이 "어떤 리소스/레코드/파일을 가리키는 값"이면 IDOR 식별자다 — 파라미터 이름이 `Id`로 끝나는지는 무관하다. 이름 목록(`*Id` 등)으로 한정하면 반드시 놓친다. **판별 기준은 "이 값이 달라지면 다른 사람의 리소스에 접근하게 되는가"**이다. 외부 입력은 프레임워크의 입력 표지 어노테이션 **전수**(Spring Web 예: `@PathVariable`/`@RequestParam`/`@RequestBody`/`@RequestHeader`/`@CookieValue`/`@ModelAttribute`/`@RequestPart`)로 식별한 뒤, 각 값이 리소스를 지목하는 역할인지(DB 조회 키, 파일/스토리지 경로, 토큰/핸들, 캐시 키, 외부 시스템 참조 등 형태 불문) 의미로 판정하라. **헤더·쿠키 source는 게이트웨이가 인증 후 덮어쓰는 신뢰 헤더와 구조적으로 구분 불가하므로**, 후보로 올린 뒤 게이트웨이 정책(해당 헤더명을 덮어쓰는지)을 확인하여 안전 분기를 처리한다(덮어쓰기 확인 못 하면 후보 유지가 안전).
- **[필수] 인증 자체가 없는 진입점도 IDOR 후보**: IDOR을 "인증된 사용자가 다른 사용자 리소스에 접근"으로만 좁히면 미탐. 컨트롤러가 외부 식별자(accountId/userId/이메일/전화번호 등 역할상 사용자 지목값)를 **세션이 아니라 클라이언트 입력에서** 받아 service에 그대로 전달하면, 인증 자체가 부재하든 인가만 누락이든 결과는 동일하다 — 임의 사용자 리소스 접근. 다음 신호를 만나면 후보로 올린다:
  - 메서드 시그니처에 사용자 지목 입력(`@RequestHeader`/`@RequestParam`/`@RequestBody`로 받은 식별자류 필드)이 있고, 컨트롤러/메서드/AOP 어느 계층에도 인가 게이트(소유권 비교·`@PreAuthorize`·세션 사용자 ID 사용)가 없음.
  - 컨트롤러 매핑 경로의 의미가 "인증 불요"임을 강하게 시사(`public`·`open`·`anonymous`·`guest/public` 등 — **키워드 단정이 아니라** 같은 코드베이스의 인증 적용 경로와 비교했을 때 보호 부재가 일관성 어긋남이면 후보).
  - 입력값이 세션 사용자 ID로 **덮어쓰이지 않고** 그대로 service 호출 인자로 흐름.
  → **세션에서 사용자 ID를 가져와 외부 입력값을 무시(또는 비교)하는 코드가 처리 경로에 없으면**, 사용자가 보낸 식별자를 신뢰하는 것이다. 라벨 `AUTH_BYPASS`(또는 IDOR_GATE_UNVERIFIED) 후보.
- **"넘기는 것"과 "검증하는 것"은 다르다**: 컨트롤러가 요청자 식별자(accountId/userId)를 service 인자로 전달하더라도, service가 그 식별자로 **소유권을 실제 비교**하지 않으면 IDOR다. accountId를 인자에 끼워 넣은 것만으로 안전하다고 단정하지 말고, 리소스 지목 값이 요청자 소유인지 비교하는 코드를 처리 경로에서 확인하라.
- **[필수] "게이트 호출 존재" ≠ "게이트 범위 적정"**: 소유권 검증 함수가 호출되는 것을 확인했다고 안전으로 단정하지 말 것. 그 게이트가 **모든 접근 경로·모든 리소스 타입을 빠짐없이 커버하는지** 게이트 함수 본문을 직접 Read하여 확인하라. 자주 보이는 부분 게이트(우회 경로):
  - **타입/분기 예외**: `if (isNotOwner(...) && !isSpecialType()) throw;` — 특정 리소스 타입/카테고리/플래그(예: 공유·이벤트·특수거래 종류 등 코드베이스마다 다름)이면 throw를 건너뛰어 검증을 우회한다. throw 조건에 `&& !특정조건` / `|| 특정조건` 형태로 면제 분기가 붙어 있으면, 그 면제 경로에 대체 검증(멤버십·소속 등)이 실제로 있는지 끝까지 추적하라.
  - **부분 주체만 검증**: 소유자(작성자/구매자/수신자 등) 일부만 확인하고 "공유 대상·그룹 참여자·위임자" 같은 다른 정당 주체 또는 그 외 접근자는 미확인.
  - **조건부 실행**: 게이트가 `if (someFlag)` 안에서만 실행되어 flag 거짓 경로는 무검증.
  - **일부 액션만**: 조회는 게이트, 수정/삭제/다운로드는 누락.
  → 게이트가 있으나 일부 경로를 빠뜨리면 **안전이 아니라 `DEFENSE_BYPASS` 후보**(우회 경로를 본문에 명시). 게이트의 throw 조건·분기·커버 범위를 코드로 추적하는 것이 IDOR 판정의 핵심이다.
- **쿼리에 owner_id 누락**: `WHERE id = ?` (소유자 스코프 없음). `WHERE owner_id = currentUser AND id = ?` 필요.
- **라우트 인증은 통과, 객체 권한 미체크**: `@LoginRequired` + `Order.find(id)` (현재 사용자 무관 조회).
- **간접 참조 매핑 부재**: 사용자 A가 자기 주문 목록에서 ID를 알아낸 후 다른 사람 ID 추측.
- **순차 ID (autoincrement)**: 추측 용이. UUID도 인가가 없으면 동일 — UUID는 보안 아님.
- **GraphQL `node(id:)` global resolver**: 모든 타입을 ID로 조회 → 권한 체크 누락 시 모든 리소스 노출.
- **batch endpoint (`{ids: [1,2,3]}`)**: 일부 ID만 권한 검사 후 전체 반환.
- **PATCH로 owner 변경**: `{id: 1, owner_id: attacker}` → 본인 소유로 만든 후 조작.
- **mass assignment**: `User.update(id, req.body)` — 사용자가 `is_admin: true` 추가.
- **Read는 검증, Update/Delete는 미검증**: 한 라우트만 검사하는 패턴.
- **검색 결과에 권한 외 객체 포함**: 검색은 권한 무시, 사용자가 ID 알아낸 후 직접 조회.
- **export/download가 검증 누락**: PDF/Excel 생성 라우트.
- **첨부파일 URL이 path만 검사**: `?attachment_id=`로 다른 사용자 첨부 다운로드.
- **profile picture URL**: `/users/:id/avatar` — 인가 무시 (공개라 가정).
- **내부 RPC 노출**: 내부용 endpoint가 외부 gateway로 라우팅 누설.
- **Cache 키에 user_id 미포함**: 캐시 응답이 다른 사용자에게 leak.
- **Pagination cursor에 hint 포함**: cursor decode 시 다른 사용자 컨텍스트.
- **WebSocket 채널 구독**: `subscribe('/user/:id/notifications')` — id 검증 없음.
- **Reset password token이 user_id 포함, 서명 없음**.
- **2FA setup endpoint**: `POST /users/:id/2fa/disable` — 본인 인증 없이.
- **Social login link/unlink**: 다른 사용자 계정에 자기 social 연결.
- **`org_id` switch**: 멀티테넌시에서 사용자가 다른 org_id로 요청하면 통과.
- **role/permission 변경 endpoint**: `PUT /users/:id/role`에서 **다른 사용자**의 role을 변경하는 케이스만 본 스캐너 담당(cross-user). 자기 자신 role을 변경하는 mass assignment는 business-logic `PRIV_ESCALATION` 담당.
- **HTTP method 차이**: GET은 권한 체크, HEAD/OPTIONS/PATCH 누락. method-tampering과 결합.
- **CDN signed URL 만료 미검증**: presigned URL 발급 후 만료 후에도 백엔드가 검증 안 하면 재사용 가능.
- **Static asset 추측 가능 경로**: `/uploads/2024/01/15/IMG_001.jpg` 같은 패턴 노출.
- **권한 체크 후 ID 재조회 (TOCTOU)**: 검증 시점 ID와 실제 사용 시점 ID 사이 race.

## 안전 패턴 (FP Guard)

- **쿼리 레벨 owner scope**: `Order.where(user_id: current_user.id).find(id)`.
- **글로벌 미들웨어 owner check**: 모든 `/orders/:id` 진입 시 `before_action :ensure_owner`.
- **Policy 라이브러리** (Pundit, CanCanCan, casl, oso) + 전 라우트 enforce.
- **간접 참조 토큰**: 사용자별 매핑 테이블에서 hash → 실제 ID.
- **Object-level permission framework** (Django Guardian, Spring Security `@PreAuthorize`).
- **공개 리소스**: 설계상 공개 (공개 게시글) — 비즈니스 요구사항 확인.
- **본인 리소스만 반환하는 API**: 식별자 받지만 내부적으로 `current_user`만 조회.
- **GraphQL field-level resolver에 권한 체크**.
- **Capability 토큰**: 객체 ID 대신 unguessable token + 서명 검증 (예: HMAC).
- **Row-Level Security (Postgres RLS)**: DB 세션 변수에 user_id 설정 후 `CREATE POLICY` 강제 — 코드 누락에도 안전망.
- **GraphQL DataLoader + per-user 인가 키**: 배치 조회 시에도 사용자별로 분리된 캐시 키.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| 권한 체크가 일부 HTTP method만 적용 | 가능 | GET 검증 → PUT/DELETE/PATCH/HEAD/OPTIONS 우회. method-tampering 결합 |
| 권한 체크 후 별도 ID 재조회 | 가능 | TOCTOU race — 검증 직후 ID 변경된 상태로 두 번째 조회 |
| ID 타입 캐스트 후 검증 (정수 변환) | 가능 | `parseInt('123abc')` → 123 통과, 다른 곳에선 문자열 그대로 사용. SQL은 leading zero `0123`도 동일 |
| Path 정규화 누락 | 가능 | `/users/123` 차단 시 `/users/123/`, `/users/.//123`, `/users/%31%32%33` 우회 |
| 정책 라이브러리 default-allow 설정 | 가능 | 정의되지 않은 액션이 자동 허용. CanCan/Pundit `unless raise` 누락 |
| Substring/prefix 권한 검사 | 가능 | `user_id.startsWith(currentUser)` → `12` 사용자가 `123`, `124` 접근 |

| 조건 | 판정 |
|---|---|
| 식별자 받음 + 소유자 scope 없음 + 객체 권한 체크 없음 | 후보 |
| 라우트 인증만 있고 객체 인가 없음 | 후보 |
| GraphQL global node resolver + 타입별 권한 미체크 | 후보 (라벨: `GRAPHQL_NODE`) |
| Batch endpoint + 일부 ID만 검사 | 후보 (라벨: `BATCH_PARTIAL`) |
| Mass assignment + `owner_id`/`tenant_id` 등 **소유관계 필드** 변경 가능 | 후보 (라벨: `MASS_ASSIGNMENT`) |
| Mass assignment + `role`/`permissions`/`isAdmin` 등 **자기 권한 상승** | **business-logic `PRIV_ESCALATION` 담당** — 본 스캐너 후보 아님 |
| 상태 변경 엔드포인트(approve/cancel/transfer 등)에서 객체 소유권 검증 누락 | 후보 (수직 IDOR로 단독 분류, business-logic STATE_BYPASS와 중복 등재 금지) |
| 글로벌 미들웨어/쿼리 scope 확인 | 제외 |
| 본인 자원만 조회 (식별자 받지만 무시) | 제외 |
| 공개 리소스 (비즈니스 요구사항 확인됨) | 제외 |
| Read는 보호, Update/Delete는 미검증 | 후보 |

## 분류 체계 — 외부입력→리소스접근→소유권게이트부재 (3단계)

IDOR은 "있어야 할 인가 검증의 **부재**"라 단일 패턴으로 자동 판정하면 FP가 폭발하거나(넓게) 미탐이 생긴다(좁게). 따라서 **확신도에 따라 3단계로 분류**한다. 핵심 구조는 모든 단계 공통:

> **외부입력**(컨트롤러의 `@PathVariable`/`@RequestParam`/`@RequestBody` — **파라미터 이름·타입 무관**, 어노테이션이 표지) → **리소스접근**(repository/service 조회·조작 호출에 그 값 전달) → **소유권게이트 부재**(요청자 accountId/userId vs 리소스 소유자 비교, `@PreAuthorize`/`@PostAuthorize`, 객체 인가 AOP가 처리 경로에 없음)

**[필수] 이름 카탈로그 금지**: source를 특정 이름 패턴(`*Id` 등)으로 한정하지 말 것. 이름이 무엇이든 "값을 바꾸면 다른 사람의 리소스를 지목하게 되는" 외부 입력은 전부 IDOR source 후보다. 외부 입력은 **어노테이션으로 전수 식별**하고, sink는 호출 형태로, 게이트는 의미(소유권 비교의 효과)로 판정한다 — 세 가지 모두 이름 매칭에 의존하지 않는다.

| 단계 | 조건 | 처리 |
|------|------|------|
| **① 자동 후보 (비대칭)** | 같은 컨트롤러/형제 엔드포인트 다수는 소유권 게이트(어노테이션/검증 호출)가 있는데 **이 메서드만 누락** | master-list 후보 등록 (라벨 `IDOR_ASYMMETRIC`, 정밀도 높음) |
| **② 검토 후보 (게이트 부재)** | 외부입력→리소스접근 흐름은 확인했으나 소유권 게이트를 **처리 경로에서 찾지 못함** (taint 룰 `noah-*-idor-missing-owner-gate-taint` 매치 포함). 단 게이트가 service 깊이/커스텀에 있을 가능성 잔존 | master-list 후보 등록 (라벨 `IDOR_GATE_UNVERIFIED` + `[검토필요]`). **service/AOP 계층을 직접 Read하여 소유권 검증 유무를 확인**한 뒤, 검증이 실재하면 제외(이름이 아니라 효과로 판정), 부재 확정·불명이면 후보 유지 |
| **③ 검토 인벤토리 (전수)** | ①②에 안 잡힌 잔여 중, 외부 식별자를 받아 리소스에 접근하는 모든 엔드포인트 | **후보 아님 — 별도 "IDOR 검토 인벤토리" 섹션**에 표로 전수 기록 (FN 방지). DAST 권한 diff 입력. |

### 검토 인벤토리 출력 형식

**[필수] 인벤토리는 기계 생성한다.** 에이전트 수기로는 대량 진입점(실측 700건+)을 컨텍스트 한계로 누락한다. **taint 모드 + 컨트롤러 스캔 모드를 함께** 실행한다 — taint는 dataflow 확정 고신뢰분, 컨트롤러 스캔은 람다 클로저·DTO 우회·체이닝으로 taint flow가 닿지 못하는 진입점을 source-only로 메우는 안전망(FN 방지):

```bash
python3 <NOAH_SAST_DIR>/tools/idor_inventory.py \
  --locindex <PATTERN_INDEX_DIR>/idor-scanner.locindex.json \
  --project-root <PROJECT_ROOT>
```

이 도구는 외부 입력 어노테이션(`@PathVariable`/`@RequestParam`/`@RequestBody`/`@RequestHeader`/`@CookieValue`/`@ModelAttribute`/`@RequestPart`) 7종으로 모든 컨트롤러 진입점을 전수 추출하여 `엔드포인트 | 외부입력 | 위치 | 출처(taint/controller-scan) | 소유권게이트(❓ 미확인)` 표를 출력한다.

에이전트는 이 표를 결과 파일에 포함하되, **소유권게이트 열을 다음 형식으로 채운다**(거짓 복사 방지):

- `✓ <service>.<method>():<file:line>` — 완전 검증. **호출된 게이트 함수의 파일·라인을 반드시 인용**. 함수명만 적는 것 금지.
- `❌ 부재` — service Read 후 게이트 없음 확정.
- `⚠ 부분: <우회 경로>` — 부분 게이트(타입/분기 예외, 부분 주체, 조건부 실행, 일부 액션만 등). 우회 경로 1줄 명시.

**[필수] 금지 사항**:
- 같은 컨트롤러/모듈의 다른 항목 게이트 정보를 추정으로 복사 붙여넣기 금지. 각 항목은 해당 service를 **직접 Read**해 채운다.
- 게이트 호출 **존재**만으로 `✓` 판정 금지 — 게이트 함수 본문을 Read해 **범위 적정성**까지 확인(위 §"게이트 호출 존재 ≠ 게이트 범위 적정").
- "service 미확인"은 ❓로 유지(임의 ✓ 금지). 미확인이 많으면 후보 유지가 안전.

도구가 없거나 locindex가 없는 환경이면 아래 형식으로 수기 작성하되 전수성을 보장한다.

결과 파일 끝(manifest 앞)에 `### IDOR 검토 인벤토리` 섹션으로, 외부 식별자를 받아 리소스 접근하는 엔드포인트를 전수 표로 기록한다. 후보(①②)로 등록한 것도 포함하되 단계를 표시한다:

```
### IDOR 검토 인벤토리
| 엔드포인트 | 외부입력(파라미터) | 리소스접근 호출 | 소유권게이트 | 단계 |
|---|---|---|---|---|
| GET /download-url/payments/{paymentId} | paymentId(@PathVariable Long) | getDownloadUrlByPaymentId(accountId, paymentId) | ❓ service 미확인 | ② |
| GET /audio/download/secure-link | accessKey(@RequestParam String) | getVideoAudioDownloadSecureLink(accessKey, ...) | ❌ 없음 | ② |
| ... | ... | ... | ✓ owner.equals | — (안전, 참고용) |
```

`소유권게이트` 열: `✓`(검증 확인, 안전) / `❌`(부재 확정) / `❓`(service/AOP 미확인 — 검토 필요). 이 인벤토리는 "안 본 엔드포인트는 없다"를 보장하는 백스톱이다.

## 후보 판정 제한

사용자가 제공한 식별자로 **다른 사용자** 리소스에 접근 가능한 경로가 존재하는 경우 후보. 글로벌 미들웨어 소유권 검증 또는 쿼리 사용자 scope 적용이 **코드로 확인되면** 제외(이름 추측이 아니라 Read로 검증). taint 룰의 sanitizer 카탈로그에 없는 커스텀 소유권 검증도 효과가 동등하면 안전으로 인정한다.

## 프레임워크 확장 메타 원칙 (다른 언어/프레임워크에도 동일 적용)

본 문서의 어노테이션·도구는 Spring Web(Java/Kotlin) 예시를 든다. 다른 프레임워크에 idor 룰을 추가할 때 같은 원칙을 그대로 적용한다:

1. **외부 입력 표지 카탈로그를 완성한다.** path/query/body 외에 header/cookie/form-binding/multipart 등 그 프레임워크의 **모든 외부 입력 표지**를 source로 둔다. 일부만 카탈로그화하면 다른 코딩 스타일을 쓰는 컨트롤러에서 미탐(이번 viewedPlace 사례: `@RequestHeader`/`@ModelAttribute` 미포함이 원인 중 하나).
   - Express.js: `req.params`, `req.query`, `req.body`, `req.headers`, `req.cookies`, `req.files`
   - Django/DRF: view function `request.GET`/`POST`/`data`/`headers`/`COOKIES`/`FILES`, ViewSet의 `pk` 인자
   - FastAPI: `Path`, `Query`, `Body`, `Header`, `Cookie`, `Form`, `File`, Pydantic 모델 바인딩
   - Rails: `params[...]`, `request.headers`, `cookies`, `request.cookies`
   - Go (net/http, Gin, Echo): URL path 변수, `r.URL.Query()`, `r.Header.Get`, body bind, `c.Param`/`c.Query`/`c.GetHeader`
2. **이름 카탈로그(`*Id`/`accountId` 등) 금지.** 어노테이션/입력 표지가 곧 신뢰 경계다. 식별자 역할 판정은 "값이 달라지면 다른 사람 리소스 접근?"으로.
3. **인벤토리 도구는 두 모드 병행.** semgrep taint는 람다 클로저·DTO 필드·체이닝에서 추적 한계가 있다(엔진 무관 보편 한계). 그래서 dataflow 확정분(taint) + 컨트롤러 source-only 스캔(전수 안전망)을 합쳐야 FN 0에 가까워진다. 새 언어 컨트롤러 스캔 휴리스틱은 그 언어의 매핑·시그니처 문법에 맞게 추가한다(`idor_inventory.py` 확장).
4. **인증 부재 진입점도 IDOR 의미론에 포함.** 인증 자체가 없는 상태에서 외부 식별자 수용은 결과적으로 cross-user 접근과 동일. 룰 source 패턴이 잡으면 `IDOR_GATE_UNVERIFIED`(또는 `AUTH_BYPASS`) 후보.
