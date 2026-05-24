---
id_prefix: NOSQLI
rules_dir: rules/
---

> ## 핵심 원칙: "쿼리 로직이 변경되지 않으면 취약점이 아니다"
>
> `db.collection.find(userInput)`이 있다고 바로 NoSQLi로 보고하지 않는다. 사용자가 제어한 입력으로 쿼리 연산자(`$gt`, `$ne`, `$regex`, `$where` 등)를 삽입하여 쿼리 로직을 실제로 변경할 수 있어야 취약점이다.

## Sink 의미론

NoSQLi sink는 "JS/JSON 객체 형태의 쿼리 명세에 사용자 입력이 객체로 들어올 수 있는 지점"이다. 문자열 sink가 아니라 **객체 sink**라는 점이 SQLi와 다르다. 핵심 위험: HTTP body parser(`express.json()`, `qs.parse({extended:true})`)가 `{password: {$ne: ""}}` 같은 객체를 만들고, 코드가 그것을 그대로 쿼리에 전달.

| 라이브러리 | 위험 sink |
|---|---|
| MongoDB native | `collection.find(q)`, `findOne(q)`, `updateOne(q,u)`, `deleteOne(q)`, `aggregate(pipeline)` |
| Mongoose | `Model.find(q)`, `findOne(q)`, `findById(id)` (id가 객체면 위험), `Model.find({$where: x})` |
| Mongoose 안전 한정 | `Model.where('field').equals(v)` 체이닝 |
| Redis | `client.eval(script, ..., userInput)` (Lua), 키 이름에 입력 사용 |
| CouchDB | `db.find({selector: q})`, `_design` view에 사용자 함수 |
| Firestore | `collection.where(field, op, value)` — `op`이 사용자 입력이면 위험 |
| Elasticsearch | `client.search({body: {query: q}})` — query DSL이 객체 sink. `script_score`/`script_fields`에 사용자 입력 시 painless 코드 실행 가능 |
| Cassandra/CQL | `session.execute("..." + x)` — CQL은 SQL 유사. CQL injection은 SQLi처럼 분류 가능하나 NoSQLi 카테고리에 포함 |
| DynamoDB | `client.query({KeyConditionExpression: x, ExpressionAttributeValues: {...}})` — Expression이 raw 문자열이면 위험 |

## Source-first 추가 패턴

- `req.body.*` 전체를 spread로 쿼리에 삽입: `find({...req.body})`
- `req.query.*` (qs `extended:true` 또는 `allowDots`로 객체 파싱)
- GraphQL/JSON-RPC resolver 인자
- WebSocket 메시지 payload
- 메시지 큐(Kafka/SQS) consumer가 외부 메시지를 그대로 쿼리에 전달
- `JSON.parse(cookie)` 후 쿼리에 사용

## 자주 놓치는 패턴 (Frequently Missed)

- **로그인 우회**: `User.findOne({username: req.body.username, password: req.body.password})` — body가 `{username: "admin", password: {"$ne": null}}`이면 패스워드 검증 우회.
- **`$where` JavaScript 실행**: `db.users.find({$where: \`this.name == '${x}'\`})` — JS 코드 실행, RCE에 가깝다.
- **`$regex` ReDoS**: 사용자 입력이 정규식 패턴으로 들어가면 ReDoS 가능.
- **`$expr` + `$function` (MongoDB 4.4+)**: 서버사이드 JS 실행.
- **aggregate pipeline `$lookup`**: 사용자 입력으로 다른 컬렉션 조인 → 권한 우회.
- **Mongoose `findById(req.body.id)`**: id가 객체로 오면 cast 우회.
- **`.populate(req.query.populate)`**: 사용자가 populate 경로를 지정하면 정보 노출.
- **NoSQL injection in projection**: `find(q, req.query.fields)` → 숨겨진 필드(password hash) 노출.
- **Operator injection via key prefix**: 중첩 객체 키 `user.role` 형식이 `qs`로 객체화되어 `{user: {role: ...}}`로 변환.
- **Elasticsearch script query**: `"script": {"source": "${x}"}` painless 코드 주입 → RCE. 특히 `inline` script 허용 시.
- **MongoDB `$accumulator` / `$function` (4.4+)**: 서버사이드 JS 실행. disabled 기본이지만 활성화 확인 필요.
- **Mongoose `strictQuery: false`**: 미정의 필드도 쿼리 허용 — 예상 외 필드 조작.
- **Time-based NoSQLi**: `$where` 안 `while(true){}` 또는 Redis `DEBUG SLEEP` → 응답 지연 측정.

## 안전 패턴 (FP Guard)

- **명시적 String 캐스트**: `findOne({username: String(req.body.username), password: String(req.body.password)})`.
- **mongo-sanitize / express-mongo-sanitize 미들웨어 등록 확인**: `app.use(mongoSanitize())` — `$` prefix 키 제거.
- **Mongoose Schema validator**: 필드 type이 `String`이면 객체가 들어와도 cast 에러로 거부 (단, `findById` 같은 raw 메서드는 우회 가능).
- **Joi/Zod/express-validator로 type 검증 후 쿼리 진입**: validator 통과 보장 필요.
- **체이닝 API만 사용**: `Model.where('email').equals(email).exec()`.
- **Elasticsearch search-as-you-type / scripted_metric 비활성화**: `script.allowed_types: none` 설정 확인.
- **MongoDB `$where`/`$function` 서버 비활성화**: `--noscripting` 또는 `security.javascriptEnabled: false`.
- **Mongoose `strictQuery: 'throw'` (Mongoose 7+)**: 미정의 필드 자동 거부.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `mongo-sanitize` (`$` prefix만 차단) | 가능 | `.` 표기 (`user.role: admin`)나 nested 객체로 우회 — 일부 라이브러리는 `.`도 차단해야 함 |
| String cast (`String(x)`) | 부분 가능 | `String({...})`은 `[object Object]` 반환이라 안전. 단, `JSON.stringify` 후 다시 parse하는 경로는 우회 |
| Mongoose Schema type validation | 가능 | `findById`/`findByIdAndUpdate` 등 raw 메서드는 schema validator 우회 |
| `$where` 차단했으나 `$expr` 미차단 | 가능 | `$expr`로 동등 효과 달성 가능 (`$eq`/`$gt` 등 expression operator) |
| Elasticsearch `script.allowed_types: stored` | 부분 가능 | stored script ID 추측 가능하면 임의 코드 실행 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| `req.body`/`req.query`가 spread/직접 객체로 쿼리에 전달 | 후보 |
| 인증 관련 쿼리에서 비밀번호 필드를 객체로 받을 수 있음 (mongo-sanitize 없음) | 후보 (라벨: `AUTH_BYPASS`) |
| `$where`/`$function`/`$accumulator`에 사용자 입력 | 후보 (라벨: `SERVER_SIDE_JS`) |
| 명시적 String/Number 캐스트 직전에 적용됨 | 제외 |
| express-mongo-sanitize 전역 미들웨어 등록 확인됨 | 제외 단, 미들웨어를 우회하는 raw body parser 라우트 없음을 확인 |

## 후보 판정 제한

사용자 입력이 쿼리 연산자 위치에 객체로 삽입되는 경우만 후보. 명시적 캐스트나 sanitize 미들웨어 적용 확인 시 제외.
