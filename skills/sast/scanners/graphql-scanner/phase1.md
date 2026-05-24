---
id_prefix: GRAPHQL
rules_dir: rules/
---

> ## 핵심 원칙: "정보 노출/인가 우회/DoS가 실제로 발생해야 취약점이다"
>
> Introspection 활성화만으로 즉시 익스플로잇이 되지는 않는다. 그러나 에이전트는 "의도적 공개인지"를 판단할 수 없으므로, introspection 활성은 **무조건 후보**(전제조건 명시)로 등록한다. 인가 우회, DoS, IDOR 등 실제 악용은 별도 라벨로 판정.

## Sink 의미론

GraphQL sink는 "GraphQL 서버 설정 또는 resolver 코드의 인가/검증/제한이 누락되거나 우회 가능한 지점"이다.

| 언어 | 라이브러리 |
|---|---|
| Node | `apollo-server`/`@apollo/server`, `express-graphql` (deprecated), `graphql-yoga`, `mercurius` (Fastify), `graphql-js` |
| Python | `graphene`/`graphene-django`, `strawberry-graphql`, `ariadne` |
| Java | `graphql-java`, Spring for GraphQL, Netflix DGS |
| Ruby | `graphql-ruby` |
| PHP | `webonyx/graphql-php`, `lighthouse` (Laravel) |
| .NET | `HotChocolate`, `GraphQL.NET` |

**점검 차원:**
1. Introspection (prod 노출 여부)
2. Field/resolver 인가
3. Query depth/complexity 제한
4. Batch query / alias 제한
5. 에러 메시지 노출
6. Subscription 인증

## Source-first 추가 패턴

- GraphQL 엔드포인트 라우트 (`/graphql`, `/api/graphql`, `/v1/graphql`)
- Apollo Server 설정 (`introspection`, `csrfPrevention`, `allowBatchedHttpRequests`)
- Yoga 설정 (`maskedErrors`, `landingPage`)
- Schema 정의 (`.graphql` 파일, SDL, code-first)
- Resolver 코드
- Directive 정의 (`@auth`, `@hasRole`)
- DataLoader 사용 코드
- Subscription resolver

## 자주 놓치는 패턴 (Frequently Missed)

- **Introspection 활성 + 민감 필드 노출**: `__schema` 쿼리로 모든 타입/필드/인자 노출. 내부 mutation 명, deprecated 필드 등.
- **Field suggestion 활성**: 잘못된 필드명 입력 시 "Did you mean ...?" 응답으로 schema 추론.
- **Resolver별 인가 누락**: query는 인가, mutation은 인증만 + admin mutation 누락.
- **중첩 resolver 인가 누락**: `user(id)` 인가 통과 후 `.posts` 필드 resolver는 권한 체크 안 함 → IDOR.
- **`node(id:)` global resolver**: Relay spec의 generic node fetcher가 모든 타입 권한 우회.
- **Query depth 무제한**: `{ user { friends { friends { friends { ... } } } } }` 무한 중첩 → DoS.
- **Query complexity 무제한**: 단일 쿼리에 100개 필드 + alias.
- **Batch query 무제한**: `[{...}, {...}, ...]` 1000개 쿼리.
- **Alias batching**: `{ a1: getUser(id:1) { ... } a2: getUser(id:2) { ... } ... a1000: ... }` — single HTTP request로 1000회 호출. rate limit 우회.
- **DataLoader 미사용 → N+1 DoS**.
- **Mutation rate limit 없음**: 비밀번호 brute force.
- **Subscription 인증 없음**: 타인 채널 구독.
- **Error 메시지 stack trace 노출**: 프로덕션에서 SQL/내부 경로 누설.
- **Variable injection**: 쿼리 변수가 SQL/NoSQL로 흘러감 (sqli/nosqli scanner와 결합).
- **Field-level rate limit 부재**: 특정 비싼 필드 (검색/통계) 무제한 호출.
- **GET 메서드로 mutation 허용**: CSRF (csrf-scanner와 결합).
- **Apollo Server csrfPrevention 비활성**: simple request로 CSRF.
- **`__type(name:)` 쿼리**: introspection 부분 차단해도 `__type`로 우회.
- **Persisted query 없음 + arbitrary query 허용**.
- **Shadow API**: 미문서화 mutation/query.
- **File upload (multipart spec)**: 검증 미흡.
- **Federation gateway에서 sub-graph 직접 접근 가능**: gateway 인증 우회.
- **Schema stitching의 cross-service 인가 누설**.
- **`@deprecated` 필드도 여전히 호출 가능**.
- **Scalar coercion 취약**: `Int` 타입에 매우 큰 값 (`2^53+1`) 전달 시 precision loss — 권한 검사 우회.
- **JSON scalar (`scalar JSON`)**: 구조화되지 않은 값으로 NoSQL 연산자 주입 (`$ne`, `$where`).
- **GraphQL over WebSocket 인증 우회**: `graphql-ws` connection init에서 token 검증 누락.
- **Apollo Federation subgraph 직접 호출**: gateway 우회하고 subgraph의 내부 `_entities` query 직접 호출.
- **File upload `graphql-upload`**: multipart spec 준수하나 파일명 검증 누락 (file-upload와 결합).

## 안전 패턴 (FP Guard)

- **Apollo Server `introspection: false`** + `landingPage: false` (production).
- **`NoSchemaIntrospectionCustomRule`** validation rule.
- **`graphql-depth-limit`** (예: depth ≤ 10).
- **`graphql-query-complexity`** (cost-based limit).
- **`graphql-validation-complexity`**.
- **Resolver decorator/directive로 일괄 인가** (`@auth`/`@hasRole`).
- **모든 resolver에 `context.user` 검증**.
- **DataLoader** 사용으로 N+1 차단.
- **Persisted queries / APQ (Automatic Persisted Queries)** + 화이트리스트.
- **`csrfPrevention: true`** (Apollo Server 4+).
- **Rate limit (per query/per user)**.
- **Production error masking** (`maskedErrors: true` Yoga, `formatError`로 stack 제거).
- **`allowBatchedHttpRequests: false`** 또는 batch 크기 제한.
- **Subscription 인증** (connection params).

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| Depth limit N 적용 | 부분 가능 | 동일 depth 내 필드 수 증가 (Horizontal fan-out) — complexity 제한도 필요 |
| Introspection 비활성 (Apollo `introspection: false`) | 부분 가능 | Field suggestion error (`Did you mean`)로 field 추측, `__typename` 단독은 허용 케이스 |
| Rate limit per user | 가능 | 인증 없는 anonymous query로 우회, 또는 alias batching으로 단일 요청에 N회 호출 |
| Complexity limit (cost-based) | 환경 의존 | DataLoader 사용 시 비용 0 계산 → 실제 N+1 발생. Directive 커스텀 비용 계산 공백 활용 |
| Persisted queries whitelist | 가능 | Allowlist에 포함된 query의 variable로 공격 — query shape는 고정이나 인자 검증 누락 시 |
| `csrfPrevention: true` (Apollo) | 부분 가능 | GET query 허용 시 CSRF 여지 — mutation만 POST 강제하는지 확인 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| Production에서 introspection 활성 (의도적 공개 여부 무관 — 에이전트가 판단 불가) | 후보 (라벨: `INTROSPECTION`, 전제조건: "의도적 공개 API라면 안전") |
| Resolver별 인가 일관성 없음 | 후보 (라벨: `RESOLVER_AUTHZ`) |
| 중첩 resolver 인가 누락 | 후보 (라벨: `NESTED_AUTHZ`) |
| `node(id:)` global resolver + 타입별 권한 미체크 | 후보 (라벨: `GLOBAL_NODE`) |
| Depth/complexity 제한 없음 | 후보 (라벨: `DOS`) |
| Alias/batch 제한 없음 | 후보 (라벨: `BATCH_DOS`) |
| Production stack trace 노출 | 후보 (라벨: `INFO_LEAK`) |
| GET method로 mutation 허용 | 후보 (라벨: `CSRF`) |
| 모든 점검 항목 통과 | 제외 |
| Federation gateway 우회 가능 | 후보 (라벨: `GATEWAY_BYPASS`) |

## 게이트웨이/프록시 책임 경계 (중요)

이 코드베이스가 GraphQL 스키마·리졸버를 **직접 정의하지 않고** 백엔드 GraphQL 서버로 쿼리를 **프록시/포워딩**하는 게이트웨이/BFF인 경우(예: `parseGraphQL(query)` 후 `executeQuery`/HTTP forward, Apollo/yoga 같은 서버 라이브러리는 의존성에 없음), **다음을 혼동하지 말 것:**

| 항목 | 책임 위치 | 판정 |
|---|---|---|
| 스키마 정의, 리졸버 인가, 필드 레벨 권한 | 백엔드 서버 (스캔 범위 밖) | 게이트웨이 코드만으론 후보 불가 — 단 `BACKEND_PROXY` 라벨로 Phase 2 권고 가능 |
| **게이트웨이에서 강제 가능한 쿼리 레벨 보호** | **게이트웨이 (이 코드)** | **백엔드 라이브러리 부재와 무관하게 후보** |

**게이트웨이에서 강제 가능한 보호(= 게이트웨이가 forward 전에 차단할 수 있는 것):**
- depth/complexity 제한 (`DOS`)
- alias/batch 제한 (`BATCH_DOS`)
- **introspection 차단 (`INTROSPECTION`)** — `parseGraphQL` 결과에 `__schema`/`__type` 쿼리가 있으면 forward 거부 가능. `validate()` + `NoSchemaIntrospectionCustomRule` 미적용이면 후보.
- operation type 검증 (`mutation` 텍스트 매치가 아닌 AST `definitions[*].operation` 검사)
- query allowlist / persisted query

**[필수] 일관성 규칙**: 게이트웨이가 `parseGraphQL`로 파싱만 하고 `validate()`/제한 rule 없이 백엔드로 forward하면, depth 제한 부재를 후보로 올렸다면 introspection 차단 부재도 **동일 논리로 반드시 후보**로 올린다. "introspection은 백엔드 책임"으로 제외하면서 "depth 제한은 게이트웨이 책임"으로 등록하는 비일관 판정 금지. 둘 다 게이트웨이가 forward 전 강제 가능한 보호다.

## 후보 판정 제한

GraphQL 엔드포인트를 직접 구현하거나 **백엔드로 프록시/포워딩하는 게이트웨이 코드**가 있는 경우 분석. 순수 클라이언트 코드(`gql` 템플릿 + apollo-client로 자기 쿼리만 작성)는 서버 측 보안과 무관하므로 제외. 전이 의존성은 제외.

> 게이트웨이는 "GraphQL 서버를 직접 구현"하지 않더라도 쿼리 레벨 보호를 강제할 수 있는 위치이므로 분석 대상이다. "서버 라이브러리(apollo-server 등)가 없으니 분석 대상 아님"으로 게이트웨이를 통째로 제외하지 말 것.
