---
id_prefix: LDAPI
grep_patterns:
  - "ldapjs"
  - "activedirectory2"
  - "passport-ldapauth"
  - "python-ldap"
  - "ldap3"
  - "django-auth-ldap"
  - "DirContext\\.search\\s*\\("
  - "LdapTemplate\\.search\\s*\\("
  - "Net::LDAP"
  - "ldap_search\\s*\\("
  - "ldap_bind\\s*\\("
  - "ldap"
  - "LDAP"
---

> ## 핵심 원칙: "LDAP 필터가 변경되지 않으면 취약점이 아니다"
>
> LDAP 쿼리 사용 자체는 취약점이 아니다. 사용자 입력에 `*`/`)(`/`|`/`&` 등 필터 메타문자를 삽입하여 필터 로직을 실제로 변경할 수 있어야 한다.

## Sink 의미론

LDAP Injection sink는 "사용자 입력이 LDAP 필터 문자열의 메타문자 위치(괄호/연산자)에 도달하는 지점"이다. 필터 객체 API(`EqualityFilter`, JNDI `{0}` placeholder)는 입력을 값으로 강제하므로 sink가 아니다.

| 언어 | 라이브러리 / 위험 sink |
|---|---|
| Node.js | `ldapjs` `client.search(base, {filter: "..."})`, `activedirectory2`, `passport-ldapauth` |
| Python | `python-ldap` `ldap.search_s`, `ldap3` `connection.search`, `django-auth-ldap` |
| Java | `javax.naming.directory` JNDI `DirContext.search(String)`, Spring `LdapTemplate.search`, UnboundID SDK |
| Ruby | `Net::LDAP#search`, `ruby-ldap` |
| PHP | `ldap_search`, `ldap_bind` (DN 인젝션), `Adldap2` |
| Go | `gopkg.in/ldap.v3` `conn.Search(searchRequest)` — `Filter` 필드가 raw 문자열이면 위험 |
| C#/.NET | `System.DirectoryServices.DirectorySearcher` `searcher.Filter = "..." + x`, `LdapConnection.SendRequest(SearchRequest)` |

## Source-first 추가 패턴

- 로그인 폼 username/password (LDAP bind 인증)
- 사용자 검색 API의 검색어
- 그룹/조직 조회 파라미터
- SSO/디렉토리 동기화 파라미터
- DN 동적 구성 (`uid=${user},ou=people,dc=...`) — DN injection도 함께 점검

## 자주 놓치는 패턴 (Frequently Missed)

- **인증 우회 (`*` 와일드카드)**: `(&(uid=${u})(userPassword=${p}))`에 `u=*)(&(uid=*`/`p=*` 삽입 → 모든 사용자 매칭.
- **Blind LDAP injection**: 응답 차이로 속성 값 추출 (`(uid=admin)(cn=a*))(...`).
- **DN injection**: `uid=${user},ou=people` 형태에 `,` 삽입으로 다른 OU bind. DN 컴포넌트 메타문자(`,`/`+`/`"`/`\`/`<`/`>`/`;`)는 필터 메타문자와 다른 escape 함수 필요.
- **Java JNDI 자체 RCE**: log4shell 계열 — 사용자 입력이 `ldap://`/`ldaps://` URL로 흘러가서 `InitialContext.lookup(url)` 호출되는 경로. log-injection 케이스. 별도 라벨.
- **속성명 자체에 입력 삽입**: `client.search(base, {filter: ..., attributes: [userInput]})` — 정보 노출.
- **Active Directory `objectClass` 필터 우회**: `(objectClass=*)` 같은 과도 매칭.
- **Unicode/Hex 우회**: `\28`/`\29`로 escape된 괄호가 일부 서버에서 디코딩.
- **AD `userAccountControl` bit 조작**: 비활성 계정의 bit 검사를 우회하는 필터 (`userAccountControl:1.2.840.113556.1.4.803:=2`).
- **Anonymous bind 잔존**: bind DN/password 미설정 시 익명 검색 가능.
- **Referral chasing 활성화**: 외부 LDAP 서버로 referral 따라가서 SSRF 변형.

## 안전 패턴 (FP Guard)

- **JNDI 파라미터화**: `ctx.search(base, "(&(uid={0})(pw={1}))", new Object[]{u,p}, ctrl)`.
- **Python `ldap3.utils.conv.escape_filter_chars(x)`** 적용.
- **`ldap.filter.escape_filter_chars`** (python-ldap).
- **ldapjs 필터 객체 API**: `new ldap.AndFilter({filters: [new ldap.EqualityFilter({...})]})`.
- **Spring LDAP `LdapQueryBuilder`**: `query().where("uid").is(username)`.
- **엄격 화이트리스트** (`/^[a-zA-Z0-9._-]+$/` 후 사용).
- **REST API로 디렉토리 위임** (LDAP 직접 호출 안 함).

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| 메타문자 escape (`(`, `)`만 차단) | 가능 | `\`, `*`, `\0` (NUL) 누락 시 우회. `*`는 와일드카드 매칭 |
| 화이트리스트가 영문/숫자만 허용 | 부분 가능 | 일반 LDAP 인젝션 차단되나 인증 필터에서 username `*` 단독은 별도 차단 필요 |
| DN escape만 적용 (필터 escape 누락) | 가능 | DN 컴포넌트는 안전하나 검색 필터에 같은 입력이 들어가면 우회 |
| Filter 객체 API 사용했지만 일부 필드는 raw concat | 가능 | 보안 가정과 다른 경로 — 모든 필터 위치 점검 필요 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → 필터 문자열 연결 + escape 없음 | 후보 |
| 인증 필터에서 password 필드까지 입력 직접 삽입 | 후보 (라벨: `AUTH_BYPASS`) |
| `attributes`/속성명 위치에 입력 | 후보 (라벨: `ATTR_INJECTION`) |
| DN 컴포넌트 위치에 입력 + DN escape 없음 | 후보 (라벨: `DN_INJECTION`) |
| `escape_filter_chars`/필터 객체/JNDI placeholder 적용 확인 | 제외 |
| LDAP URL이 사용자 입력으로 결정 + JNDI lookup | 후보 (라벨: `JNDI_LOOKUP`, log4shell 계열) |

## 후보 판정 제한

LDAP 서버에 직접 연결하여 필터를 구성하는 코드가 있는 경우만 후보. REST API 위임은 제외.
