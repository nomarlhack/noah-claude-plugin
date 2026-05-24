---
id_prefix: XPATHI
rules_dir: rules/
---

> ## 핵심 원칙: "쿼리 로직이 변경되지 않으면 취약점이 아니다"
>
> XPath 사용 자체는 취약점이 아니다. 사용자 입력에 `'`/`or`/`and`/`[`/`]` 등 XPath 구문을 삽입하여 쿼리 조건을 실제로 변경할 수 있어야 한다.

## Sink 의미론

XPath Injection sink는 "사용자 입력이 XPath 쿼리 문자열의 토큰 위치(따옴표 외부)에 도달하는 지점"이다. 변수 바인딩(`$var` + `setXPathVariableResolver`)은 입력을 값으로 강제하므로 sink가 아니다.

| 언어 | 위험 sink |
|---|---|
| Node.js | `xpath.select(\`...${x}\`, doc)`, `libxmljs` `doc.find/get`, `xmldom`+`xpath` |
| Python | `lxml.etree.xpath(f"...{x}")`, `ElementTree.findall` (제한적), |
| Java | `XPath.evaluate("..."+x, doc)`, `XPath.compile("..."+x)` |
| PHP | `DOMXPath::query("..."+$x)`, `DOMXPath::evaluate`, `SimpleXMLElement::xpath` |
| Ruby | `Nokogiri::XML::Node#xpath("..."+x)`, `REXML::XPath.match` |
| .NET | `XmlNode.SelectNodes("..."+x)`, `XPathNavigator.Evaluate` |

**안전 (변수 바인딩):**
- Java `xPath.setXPathVariableResolver(...)` + `evaluate("//user[name=$name]", doc)`
- Python lxml `doc.xpath("//user[name=$name]", name=x)`
- .NET `XPathExpression` + custom context

## Source-first 추가 패턴

- XML 기반 인증의 username/password
- XML 데이터 검색 기능 (legacy 시스템에서 자주 등장)
- SOAP 응답을 XPath로 파싱 후 사용자 입력으로 필터링
- 설정 XML 파일에서 사용자 키로 lookup
- SAML assertion 처리 중 XPath 사용

## 자주 놓치는 패턴 (Frequently Missed)

- **인증 우회**: `//user[name='${u}' and pw='${p}']`에 `u=' or '1'='1`/`p=' or '1'='1` 삽입.
- **Blind XPath injection**: 응답 차이로 노드 값 추출 (`substring(name(/*[1]),1,1)='a'`).
- **XPath 2.0/3.0 함수 호출**: `doc('http://attacker/')`로 SSRF, `unparsed-text('/etc/passwd')`로 LFI. lxml/Saxon에서 가능.
- **`//`로 시작하는 입력으로 전체 트리 walk**: 의도한 노드 외 전체 검색.
- **`*` 와일드카드 주입으로 모든 자식 매칭**.
- **숫자 컨텍스트 우회**: `position()=${idx}`에 `idx=1 or 1=1`.
- **`name()`/`local-name()` 함수 악용**으로 노드 이름 추출.
- **Double-quote vs single-quote 컨텍스트 혼동**: `"...'${x}'..."`에서 `x`가 `'`을 포함하면 컨텍스트 탈출.
- **XPath 2.0+ `environment-variable()` / `system-property()`**: 서버 환경변수/시스템 속성 노출 (Saxon 등).
- **XQuery injection**: XPath와 별개로 XQuery `declare function`/`let $x :=` 구문 사용 시 코드 실행.
- **XPath injection via attribute name**: `//user[@${attr}='value']` — 속성명 자체가 입력이면 다른 속성 매칭.

## 안전 패턴 (FP Guard)

- **변수 바인딩**: Java `setXPathVariableResolver`, lxml `doc.xpath(..., name=x)`.
- **고정 XPath + 결과를 코드에서 필터링**: XPath는 고정 쿼리, 사용자 입력 비교는 Python/Java에서.
- **`ElementTree.findall`** (Python stdlib): 제한적 XPath만 지원, 함수/연산자 미지원.
- **DOM API 직접 사용** (XPath 미경유).
- **엄격 입력 화이트리스트** (`/^[a-zA-Z0-9_-]+$/`).

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| 싱글쿼트만 escape | 가능 | 더블쿼트 컨텍스트 우회, `concat('a', "'", 'b')` 같은 함수 |
| `'`/`"` 모두 escape | 부분 가능 | 숫자 컨텍스트 (`position()=${idx}`)에 `or 1=1` — 따옴표 불필요 |
| 화이트리스트 (영문/숫자만) | 부분 가능 | 인증 필터에서 username `*` 단독 또는 길이 제한 우회 |
| XPath 1.0으로 제한 (함수 차단) | 부분 가능 | XPath 1.0도 `substring()`, `contains()`로 Blind 가능 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → XPath 문자열 연결 + escape/바인딩 없음 | 후보 |
| 인증 XPath에서 password까지 입력 직접 삽입 | 후보 (라벨: `AUTH_BYPASS`) |
| XPath 2.0+ 환경에서 `doc()`/`document()` 인자에 입력 | 후보 (라벨: `XPATH_SSRF`) |
| 변수 바인딩 적용 확인 | 제외 |
| 화이트리스트 정규식 적용 확인 | 제외 |

## 후보 판정 제한

사용자 입력이 XPath 쿼리 문자열에 연결되는 경우만 후보.
