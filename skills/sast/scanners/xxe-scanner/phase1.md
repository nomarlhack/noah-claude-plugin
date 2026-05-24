---
id_prefix: XXE
rules_dir: rules/
---

> ## 핵심 원칙: "외부 엔티티가 처리되지 않으면 취약점이 아니다"
>
> XML 파서 사용 자체는 XXE가 아니다. `<!DOCTYPE>` 외부 엔티티가 파서에 의해 실제로 해석되어 파일/SSRF가 발생해야 한다. 대부분의 최신 파서는 기본적으로 외부 엔티티를 비활성화한다 — **파서 종류와 버전, 그리고 명시 옵션**을 확인해야 한다.

## Sink 의미론

XXE sink는 "사용자 제어 XML이 파서에 입력되고, 그 파서가 외부 엔티티/DTD를 해석하도록 설정된 지점"이다. 핵심은 **파서 설정**이다. 같은 라이브러리도 옵션에 따라 안전/위험이 갈린다.

| 언어 | 라이브러리 | 기본값 | 위험 옵션 |
|---|---|---|---|
| Node.js | `xml2js` | 안전 | (외부 엔티티 미지원) |
| Node.js | `libxmljs` | 안전 | `noent: true` 또는 `dtdload: true` |
| Node.js | `@xmldom/xmldom` | 부분적 안전 | DOCTYPE 처리 확인 필요 |
| Node.js | `fast-xml-parser` | 안전 | — |
| Python | `xml.etree.ElementTree` (3.7.1+) | 안전 | 구버전 위험 |
| Python | `lxml.etree` | 위험 | `resolve_entities=True` (기본), `no_network=False` |
| Python | `xml.dom.minidom` | 부분 위험 | DTD 처리 |
| Python | `xml.sax` | 위험 | `feature_external_ges=True` |
| Python | `defusedxml` | 안전 | (안전 래퍼) |
| Java | `DocumentBuilderFactory` | **위험 (기본)** | `disallow-doctype-decl=false` |
| Java | `SAXParserFactory` | **위험 (기본)** | `external-general-entities=true` |
| Java | `XMLInputFactory` (StAX) | 위험 | `IS_SUPPORTING_EXTERNAL_ENTITIES=true` |
| Java | `TransformerFactory` (XSLT) | 위험 | `ACCESS_EXTERNAL_DTD/STYLESHEET` |
| Java | JAXB `Unmarshaller` | 위험 | XMLStreamReader 설정에 의존 |
| Ruby | `Nokogiri` | 안전 | `Nokogiri::XML::ParseOptions::NONET` 미적용 + DTDLOAD |
| Ruby | `REXML` | 위험 | DTD 엔티티 확장 |
| PHP | `simplexml_load_string` | 안전 | `LIBXML_NOENT` 옵션 |
| PHP | `DOMDocument::loadXML` | 안전 (PHP 8.0+) | `LIBXML_NOENT` 또는 PHP < 8 + `libxml_disable_entity_loader(false)` |
| Go | `encoding/xml` | 안전 (외부 엔티티 미지원) | — (DTD 자체 미해석) |
| C#/.NET | `XmlDocument` | **위험 (.NET 4.0 미만)** | .NET 4.5.2+ 기본 `XmlResolver=null`이지만 명시 검증 필요 |
| C#/.NET | `XmlReader.Create + XmlReaderSettings` | 옵션 의존 | `DtdProcessing = Parse` 위험. 안전: `DtdProcessing = Prohibit` + `XmlResolver = null` |
| C#/.NET | `XmlTextReader`, `XPathDocument` | 위험 (구버전) | 명시 비활성화 필요 |
| Rust | `quick-xml`, `xml-rs` | 안전 | DTD 미지원 |

## Source-first 추가 패턴

- `Content-Type: application/xml`/`text/xml` 엔드포인트
- SOAP API
- XML 기반 파일 업로드: SVG, XLSX/DOCX/PPTX (Office Open XML), RSS/Atom
- XML-RPC
- SAML SSO assertion 처리
- 사용자 업로드 설정 XML
- KML/GPX 등 도메인 XML
- OData / WCF / SOAP webhook 본문
- WS-Security 헤더 처리 코드

## 자주 놓치는 패턴 (Frequently Missed)

- **OOXML 파일 업로드 (XLSX/DOCX/PPTX)**: 내부적으로 XML. zip 해제 후 XML 파싱 시 XXE.
- **SVG 업로드**: SVG는 XML. `<svg><image href="file:///etc/passwd"/></svg>` + 이미지 처리 라이브러리.
- **SAML XXE**: SAML response를 파싱할 때. 인증 우회로도 이어짐.
- **XInclude 공격**: `<xi:include href="file:///etc/passwd"/>` — DOCTYPE 차단해도 XInclude가 활성화되어 있으면 우회.
- **Parameter entity (OOB XXE)**: `<!ENTITY % x SYSTEM "...">` — 일반 엔티티만 차단하고 parameter entity 미차단 케이스. Java에서 흔함.
- **Blind XXE → SSRF**: 외부 DTD를 fetch하여 내부 IP 스캔.
- **Java SAXParser의 setFeature 누락**: `disallow-doctype-decl`, `external-general-entities`, `external-parameter-entities`, `load-external-dtd` 4개 모두 설정해야 안전. 1개만 누락해도 우회 가능.
- **XSLT 처리기**: TransformerFactory도 XML 파싱하므로 동일 설정 필요.
- **JAXB Unmarshaller**: 내부적으로 SAX/StAX 사용. XMLStreamReader 직접 생성 후 전달해야 안전.
- **Nokogiri의 `parse(io)` vs `parse(string)`** 옵션 차이.
- **PHP < 8.0의 `libxml_disable_entity_loader`**: PHP 8에서 deprecated/no-op. PHP 8 코드에 이 함수가 있다면 방어가 안 됨.
- **XML signature wrapping (XSW)**: SAML 등에서 서명 검증과 파싱 노드가 다르면 우회.
- **DTD validation 활성화**: `setValidating(true)`만으로도 외부 DTD fetch.
- **Local DTD trick (OOB 데이터 추출)**: 외부 네트워크 차단 환경에서도 시스템에 존재하는 DTD 파일(예: `/usr/share/yelp/dtd/...`)을 parameter entity로 활용해 데이터 추출. PortSwigger XXE Lab 시나리오.
- **압축 XML (gzip/zlib decompress 후 파싱)**: HTTP `Content-Encoding: gzip` XML도 동일 위험. 압축 해제 단계에서 감지 누락.
- **XML billion laughs / Quadratic blowup**: XXE는 아니나 같은 파서 설정 영역. DoS 변형. `<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;...">`.
- **인코딩 우회**: UTF-7/UTF-16 BOM으로 입력 검증 우회 — 일부 파서가 BOM 자동 디코딩 후 해석.

## 안전 패턴 (FP Guard)

- **`defusedxml` 사용** (Python).
- **`Nokogiri`** 기본 옵션 (Ruby).
- **Java DocumentBuilderFactory**:
  ```
  factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
  factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
  factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
  factory.setXIncludeAware(false);
  factory.setExpandEntityReferences(false);
  ```
  — **6개 모두** 적용 확인 필요.
- **lxml `etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)`**.
- **`xml2js`/`fast-xml-parser`** 기본값 (Node).
- **.NET `XmlReaderSettings { DtdProcessing = Prohibit, XmlResolver = null }`** 또는 `MaxCharactersFromEntities` 제한.
- **Go `encoding/xml` 표준 라이브러리**: 외부 엔티티 미지원이라 안전 (단, third-party 라이브러리는 별도 확인).
- **OWASP XML External Entity Prevention Cheat Sheet 준수**: 언어/파서별 권장 설정 따름.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `disallow-doctype-decl=true` 만 적용 (Java 1개만) | 가능 | XInclude (`<xi:include>`)는 DOCTYPE 불필요 — `setXIncludeAware(false)` 미적용 시 우회 |
| 일반 엔티티만 차단 (`external-general-entities=false`) | 가능 | Parameter entity (`<!ENTITY % x SYSTEM "...">`)로 우회 — `external-parameter-entities=false`도 필요 |
| 외부 네트워크 차단 환경 (no_network=True) | 부분 가능 | Local DTD trick — 시스템에 존재하는 DTD 파일을 parameter entity로 호출해 OOB 데이터 추출 |
| 일반 XXE 차단되었으나 DTD 검증만 활성화 (`setValidating(true)`) | 가능 | Validation 자체가 외부 DTD를 fetch — `load-external-dtd=false`도 필요 |
| XML 서명 검증만으로 안전하다고 가정 | 가능 | XSW (XML Signature Wrapping) — 서명 노드와 파싱 노드 분리해 다른 페이로드 삽입 (SAML 등) |
| `libxml_disable_entity_loader(true)` (PHP 8.0+) | **방어 무효** | PHP 8.0에서 deprecated/no-op — 코드 존재해도 방어 안 됨 |
| 입력 인코딩 검증 (UTF-8만 허용) | 부분 가능 | UTF-7/UTF-16 BOM으로 검증 우회 — 일부 파서가 BOM 자동 인식 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| Java DocumentBuilderFactory/SAXParserFactory + 위 6개 setFeature 누락 | 후보 |
| lxml + `resolve_entities=True` (또는 옵션 미지정) + 사용자 입력 파싱 | 후보 |
| `defusedxml`/`Nokogiri` 기본 사용 | 제외 |
| SVG/OOXML 업로드 처리 + 내부 XML 파서 미설정 | 후보 (라벨: `OOXML_XXE`) |
| SAML response 파싱 + 파서 설정 미확인 | 후보 (라벨: `SAML_XXE`) |
| `libxml_disable_entity_loader(true)` 호출하지만 PHP 8.0+ | 후보 (no-op이므로 방어 없음) |
| 정적 XML만 파싱 (사용자 입력 없음) | 제외 |

## 후보 판정 제한

사용자 입력 XML을 파싱하는 코드가 있는 경우만 분석 대상. XML 생성만 하는 경우 제외.
