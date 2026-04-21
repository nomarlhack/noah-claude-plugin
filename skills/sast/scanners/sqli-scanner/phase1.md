---
id_prefix: SQLI
grep_patterns:
  - "connection\\.query\\s*\\("
  - "sequelize\\.query\\s*\\("
  - "knex\\.raw\\s*\\("
  - "\\$queryRaw"
  - "\\$queryRawUnsafe\\s*\\("
  - "pool\\.query\\s*\\("
  - "cursor\\.execute\\s*\\("
  - "Model\\.objects\\.raw\\s*\\("
  - "Model\\.objects\\.extra\\s*\\("
  - "session\\.execute\\s*\\("
  - "find_by_sql"
  - "connection\\.execute"
  - "db\\.run\\s*\\("
  - "db\\.query\\s*\\("
  - "prepareStatement"
  - "createNativeQuery"
  - "nativeQuery"
  - "jdbcTemplate"
  - "NamedParameterJdbcTemplate"
  - "executeQuery\\s*\\("
  - "Statement\\.execute"
  - "\\.raw\\s*\\("
  - "text\\s*\\("
  - "f\"\\s*SELECT"
  - "f'\\s*SELECT"
  - "@Query"
  - "\\.createQuery\\s*\\("
  - "createQueryBuilder"
  - "Arel\\.sql"
  - "\\$\\{[a-zA-Z_][a-zA-Z0-9_.]*\\}"
---

> ## 핵심 원칙: "쿼리가 변경되지 않으면 취약점이 아니다"
>
> SQL 문자열 연결이 있다고 바로 SQLi로 보고하지 않는다. 사용자가 제어한 입력으로 쿼리 구조를 실제로 변경할 수 있어야 취약점이다. ORM(Sequelize, TypeORM, Prisma, Django ORM, ActiveRecord 등)은 기본적으로 파라미터화되므로 raw query만 집중 점검한다.

## Sink 의미론

SQLi sink는 "사용자 입력이 SQL 파서에 의해 SQL 토큰(키워드/연산자/식별자)으로 해석될 수 있는 지점"이다. 파라미터 바인딩(`?`/`:param`/`%s` 튜플)은 입력을 리터럴로 강제하므로 sink가 아니다. 반대로 ORDER BY/LIMIT/컬럼명/테이블명은 파라미터 바인딩이 불가능한 위치이므로 ORM을 쓰더라도 sink가 될 수 있다.

| 언어/라이브러리 | 위험 sink |
|---|---|
| Node.js | `connection.query("..." + x)`, `sequelize.query("..." + x)`, `knex.raw("..." + x)`, `prisma.$queryRawUnsafe(...)`, `pool.query(...)`, `db.run(...)` |
| Node.js (안전 한정) | `prisma.$queryRaw\`...${x}\`` (tagged template은 안전, 문자열 연결만 위험) |
| Python | `cursor.execute("..." + x)`, `cursor.execute("...%s" % x)`, `cursor.execute(f"...{x}")`, `Model.objects.raw(...)`, `Model.objects.extra(where=[...])`, `session.execute(text(...))` |
| Java | `Statement.executeQuery(...)`, `entityManager.createNativeQuery(...)`, `jdbcTemplate.query("..." + x)` |
| Ruby | `Model.where("col = '" + x + "'")`, `connection.execute(...)`, `find_by_sql(...)` |
| PHP | `mysqli_query(..., "..." . $x)`, `$pdo->query("..." . $x)` |
| Go | `db.Query("..." + x)`, `db.Exec(...)`, `gorm.Raw("..." + x)`, `sqlx.MustExec(...)` |
| C#/.NET | `new SqlCommand("..." + x)`, `Dapper.Execute("..." + x)`, EF Core `FromSqlRaw("..." + x)` (안전: `FromSqlInterpolated($"...{x}...")`) |
| Rust | `sqlx::query("..." + &x)`, `diesel::sql_query(...)` (안전: `sqlx::query!` 매크로 — 컴파일 타임 검증) |

## Source-first 추가 패턴

- 헤더값이 로깅/감사 쿼리에 사용되는 경로 (`X-Forwarded-For`, `User-Agent` → audit insert)
- 정렬·페이징 파라미터: `sort`, `order`, `orderBy`, `direction`, `column` — ORDER BY 위치에 들어가는지 확인
- 검색 빌더: `where`, `filter`, `q`, `criteria` 객체가 동적으로 SQL fragment를 만드는 경우
- 관리자 화면의 "쿼리 조건 빌더"
- CSV/Excel import 경로의 컬럼명 매핑
- GraphQL resolver 인자가 raw SQL로 흐르는 경로
- WebSocket 메시지 본문을 파싱해 raw query에 사용
- Webhook 본문 (Stripe/GitHub 등 외부 시스템 콜백)이 검증 없이 SQL에 도달
- 메시지 큐 페이로드 (Kafka/SQS/RabbitMQ) 컨슈머가 raw query로 사용

## 자주 놓치는 패턴 (Frequently Missed)

- **MyBatis/iBatis `${}` 치환**: XML mapper(`*Mapper.xml`, `*-mapper.xml`)에서 `${param}`은 단순 문자열 치환이라 SQLi 후보. `#{param}`은 PreparedStatement 바인딩이라 안전. `${}` 매치는 SQL 문맥(`<select|<update|<insert|<delete>` 태그 또는 `@Select`/`@Update` 어노테이션 내)에서만 후보로 채택. JS template literal, Spring `@Value`, Kotlin string template 등 비-SQL 매치는 제외.
- **ORDER BY / GROUP BY 컬럼명 주입**: `knex.orderBy(userInput)`, `sequelize.query("ORDER BY " + sortColumn)` — 파라미터 바인딩 불가 위치. 화이트리스트가 없으면 후보.
- **LIMIT / OFFSET 인젝션**: 일부 DB(MySQL 구버전)는 LIMIT에 표현식을 허용. 정수 캐스트 없으면 후보.
- **테이블/스키마 동적 지정**: 멀티테넌시 코드에서 `tableName`을 사용자 입력에서 받는 경우.
- **`Model.objects.extra(where=[...])`** (Django) — extra는 raw fragment 허용.
- **ActiveRecord string condition**: `Model.where("name = '#{params[:name]}'")` 또는 `Model.where("name = '" + params[:name] + "'")`.
- **JPQL/HQL 문자열 연결**: `entityManager.createQuery("from User where name = '" + name + "'")` — JPA를 쓴다는 사실이 안전을 보장하지 않음.
- **stored procedure 호출의 동적 인자 조립**: `CALL sp_search('${q}')`.
- **2차 SQLi**: 사용자 입력을 일단 DB에 저장한 후 다른 쿼리에서 그 값을 raw로 다시 사용하는 패턴.
- **LIKE 패턴 와일드카드 미이스케이프**: 자체로 SQLi는 아니지만 정보 노출. 구분해서 기록.
- **`WHERE IN (...)` 동적 절**: `IN (${array.join(",")})` 형태 — 배열 직렬화로 raw 삽입. 매우 흔한 함정.
- **JSON 경로 인젝션**: PostgreSQL `data->>'${userKey}'`, MySQL `JSON_EXTRACT(data, '$.${userKey}')` — JSON 컬럼 키가 사용자 입력일 때 `'`/`*`로 경로 이탈 가능.
- **MyBatis `<foreach>` 내부 `${item}`**: 동적 IN 절을 `${}`로 작성하면 `#{}` 사용해도 우회됨.
- **Stored procedure 동적 SQL**: PostgreSQL PL/pgSQL `EXECUTE`, MSSQL `sp_executesql @stmt`, Oracle `EXECUTE IMMEDIATE` — 클라이언트가 파라미터 바인딩해도 sp 내부에서 raw concat이면 취약.
- **Hibernate `Restrictions.sqlRestriction(...)`**: Criteria API의 raw SQL fragment 허용 — JPA 쓴다고 안전하지 않음.

## 안전 패턴 (FP Guard)

코드에서 직접 확인된 경우에만 제외:

- **파라미터 바인딩**: `connection.query("... WHERE id = ?", [userId])`, `cursor.execute("... %s", (x,))`, `PreparedStatement.setString(1, x)`.
- **ORM 메서드 호출**: `User.findOne({ where: { id: userId } })`, `User.objects.filter(id=user_id)`, `Model.where(id: user_id)` (해시 형태).
- **Prisma tagged template**: `prisma.$queryRaw\`SELECT ... WHERE id = ${userId}\`` — 백틱 tagged template은 자동 바인딩.
- **숫자 강제 캐스트 후 사용**: `const id = parseInt(req.params.id, 10); query("... WHERE id = " + id)` — 단, NaN 처리 확인.
- **ORDER BY 화이트리스트**: `const SORTABLE = ['id','name']; if (!SORTABLE.includes(col)) throw ...`.
- **DB 권한 분리(읽기 전용 계정)**: SQLi 자체는 가능하나 영향도 라벨링 시 참고. 후보 자체는 유지.
- **컴파일 타임 SQL 검증**: Rust `sqlx::query!` 매크로, Go `sqlc` 생성 코드, Scala Slick `sql"..."` interpolator — SQL 문법/타입이 컴파일 시 검증되고 바인딩도 자동.
- **DB측 PREPARE/EXECUTE**: PostgreSQL `PREPARE stmt AS SELECT ... $1; EXECUTE stmt(?)` 구조. 클라이언트 코드가 raw로 보여도 DB가 바인딩 파라미터를 파싱 분리.
- **Stored procedure 파라미터 호출**: `CALL sp_search(?)` — 단, sp 내부에 동적 SQL(`EXECUTE IMMEDIATE`)이 없는 경우에만 안전.
- **`FromSqlInterpolated` (.NET 6+)**: `$"...{x}..."` 보간 형태이지만 EF Core가 자동 파라미터화. `FromSqlRaw`와 혼동 금지.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `split(",")` 후 토큰 사용 | 가능 | 콤마 외 구분자 또는 서브쿼리 (`(SELECT ...)`)로 우회 |
| `replace("'", "")` / `escapeSingleQuote()` | DB 의존 | SQLite는 `''` 표현, MySQL은 `\` 이스케이프 컨텍스트 의존, 다른 파라미터로 컨텍스트 전환 |
| `trim()` / `strip()` (공백 제거) | 가능 | `/**/` 주석, `%09`/`%0a`로 공백 대체 |
| 길이 제한 (예: 32자) | 가능 | 짧은 페이로드 (`'OR 1#`, `1)OR 1#`) |
| 키워드 블랙리스트 (`SELECT`, `UNION`) | 가능 | 대소문자 혼합, `/*!50000SELECT*/` 인라인 주석, `SEL/**/ECT` 분할 |
| 키워드 블랙리스트 (강화 우회) | 가능 | `0x53454c454354`(HEX) 또는 `CHAR(83,69,76,69,67,84)`로 키워드 자체를 우회 |
| 공백 차단 | 가능 | `+`, `(`, `%a0`(non-breaking space, MySQL 일부 버전), `%0b`(VT), `/**/` |
| AND/OR 키워드 차단 | 가능 | `&&`(=AND), `\|\|`(=OR, ANSI/Oracle), `XOR` 대체 |
| `addslashes()` / 싱글쿼트 escape (Multibyte 컨텍스트) | DB·인코딩 의존 | 입력 인코딩이 GBK/SJIS인 MySQL 구버전에서 `0xbf27` 같은 multibyte 시퀀스로 escape 무력화 (CVE-2006-2753 계열) |
| Stacked query 차단 (드라이버가 첫 statement만 실행) | 부분 가능 | `;` 분리한 INSERT/UPDATE 자체는 불가하나, 트리거·뷰·function 정의를 통한 간접 실행 가능 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → 문자열 연결/포맷으로 SQL 본문에 삽입 + 바인딩 없음 | 후보 |
| 사용자 입력 → ORDER BY/LIMIT/식별자 위치 + 화이트리스트 없음 | 후보 (라벨: `IDENTIFIER_INJECTION`) |
| 사용자 입력 → ORM 메서드 인자 (객체 형태) | 제외 |
| 입력이 숫자 캐스트 후 삽입, NaN/오버플로 처리 확인됨 | 제외 |
| 2차 SQLi 의심 (DB값 → raw query) | 후보 (라벨: `SECOND_ORDER`) |
| 방어 코드는 있으나 우회 가능 (위 표 참조) | 후보 (사유에 우회 방식 명시) |
| `prisma.$queryRawUnsafe`/Django `extra`/JPA native query 사용 | 후보 유지하되 주변 검증 확인 |

## 후보 판정 제한

HTTP 입력과 무관한 경로(마이그레이션, 시드, 빌드 스크립트, 테스트 파일)는 후보에서 제외.
