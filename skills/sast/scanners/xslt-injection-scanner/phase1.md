---
id_prefix: XSLTI
grep_patterns:
  - "TransformerFactory"
  - "XSLTProcessor"
  - "lxml\\.etree\\.XSLT"
  - "Nokogiri::XSLT"
  - "xslt-processor"
  - "XslCompiledTransform"
  - "registerPHPFunctions"
  - "XsltSettings"
  - "saxon"
  - "Xalan"
  - "XSLT"
  - "xslt"
---

> ## 핵심 원칙: "XSLT 변환이 조작되지 않으면 취약점이 아니다"
>
> XSLT 변환 사용 자체는 취약점이 아니다. 사용자 입력이 XSLT 스타일시트(구조)에 삽입되거나 확장 함수가 활성화되어 파일 읽기/RCE/SSRF가 발생해야 한다.

## Sink 의미론

XSLT Injection sink는 두 종류:

1. **스타일시트 구조 sink**: 사용자 입력이 XSLT 스타일시트 문자열의 일부가 되거나, 사용자가 스타일시트 파일을 선택/업로드
2. **확장 기능 sink**: 신뢰할 수 없는 스타일시트가 입력되고 프로세서가 확장 함수(PHP/Java/JS) 또는 `document()`/`unparsed-text()`를 허용

| 언어 | 프로세서 | 위험 옵션 |
|---|---|---|
| Node.js | `xslt-processor` | 확장 제한적 |
| Node.js | `node-libxslt` | 확장 함수 가능 |
| Node.js | `saxon-js` / `xslt3` | XSLT 3.0 함수 |
| Python | `lxml.etree.XSLT` | `extensions` 인자, `document()` 함수 |
| Java | `TransformerFactory` (JAXP/Xalan) | `FEATURE_SECURE_PROCESSING=false`, 확장 함수 |
| Java | Saxon | `ALLOW_EXTERNAL_FUNCTIONS=true` |
| PHP | `XSLTProcessor` | `registerPHPFunctions()` 호출 시 PHP 함수 실행 |
| .NET | `XslCompiledTransform` | `XsltSettings.EnableScript=true`, `EnableDocumentFunction=true` |
| .NET | `XslTransform` (deprecated) | 전체 위험 |

## Source-first 추가 패턴

- XML 파일 업로드가 변환 파이프라인으로 흘러가는 경로
- XSLT 파라미터로 사용자 입력 전달 (상대적으로 안전하지만 경로 검증)
- "리포트 템플릿 업로드" 기능
- XSL-FO → PDF 변환 파이프라인
- SOAP 응답 변환

## 자주 놓치는 패턴 (Frequently Missed)

- **PHP `registerPHPFunctions()`**: 호출만 되어 있어도 신뢰할 수 없는 XSLT가 임의 PHP 함수 실행 가능 → RCE.
- **`document('http://attacker/')`**: 외부 XML/리소스 fetch → SSRF + 정보 노출.
- **`document('file:///etc/passwd')`**: 로컬 파일 읽기.
- **Saxon `unparsed-text('/etc/passwd')`** / `unparsed-text-lines()` (XSLT 2.0+).
- **`<xsl:include href="..."/>` / `<xsl:import>`**: 외부 스타일시트 fetch.
- **JAXP secure processing 미적용**: Java 기본 `TransformerFactory`는 secure processing이 꺼져 있을 수 있음. 명시적 `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` 필요.
- **.NET `EnableScript=true`**: `<msxsl:script>`로 C# 코드 실행.
- **lxml `extensions={(ns, name): func}`**: 사용자 신뢰 코드면 안전하나, 동적으로 등록되면 위험.
- **XSL-FO PDF 생성**: 외부 이미지 fetch로 SSRF.
- **사용자 업로드 스타일시트 + 동적 입력 XML 조합**: 두 입력 모두 사용자 제어.
- **XSLT 3.0 `fn:transform()` dynamic evaluation**: 스타일시트 동적 평가 → 메타 XSLT 공격.
- **Xalan `xalan:pipeDocument`/`xalan:write`**: Xalan 확장으로 임의 파일 쓰기/명령 실행.
- **Saxon `saxon:extra-attributes` with `xsl:script`**: Saxon EE에서 Java/C# 바인딩 허용 시 RCE.
- **XSL-FO 외부 이미지 `<fo:external-graphic src="...">`**: URL fetch로 SSRF.

## 안전 패턴 (FP Guard)

- **고정 스타일시트 파일 + XML 데이터만 사용자 입력**: 스타일시트 경로가 환경변수/상수.
- **XSLT 파라미터 전달**: `transformer.setParameter(name, value)` (스타일시트 구조 변경 불가).
- **JAXP secure processing 활성화**: `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`.
- **Saxon `ConfigurationProperty.ALLOW_EXTERNAL_FUNCTIONS=false`**.
- **PHP `registerPHPFunctions` 미호출** + 스타일시트가 신뢰 출처.
- **.NET `XsltSettings.Default`** (script + document 모두 false).

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| JAXP secure processing만 활성화 | 부분 가능 | `document()`/`unparsed-text()` 자체는 secure 대상 아님 — 별도 `ACCESS_EXTERNAL_DTD/STYLESHEET` 속성 설정 필요 |
| 외부 스타일시트 fetch만 차단 (`<xsl:import href="...">`) | 가능 | 인라인 `<msxsl:script>`/Saxon extension 등 내부 확장으로 우회 |
| 확장 함수 비활성화 (`EnableScript=false`) | 부분 가능 | `document()` 함수는 별도 (`EnableDocumentFunction`) — 하나만 끄면 다른 쪽 남음 |
| 화이트리스트 스타일시트만 허용 | 가능 | 파일 선택 자체 제어 안 되면 안전하나, 경로 traversal로 다른 스타일시트 선택 가능 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → 스타일시트 문자열에 삽입/연결 | 후보 |
| 사용자가 스타일시트 파일을 업로드/선택 | 후보 |
| PHP `registerPHPFunctions()` 호출 + 신뢰할 수 없는 스타일시트 | 후보 (라벨: `PHP_RCE`) |
| .NET `EnableScript=true` | 후보 (라벨: `NET_RCE`) |
| Java factory에 `FEATURE_SECURE_PROCESSING` 미설정 + 신뢰할 수 없는 입력 | 후보 |
| 고정 스타일시트 + 사용자 입력은 XML 데이터/파라미터만 | 제외 |
| lxml `extensions` 정적 등록만, 동적 함수 없음 | 제외 |

## 후보 판정 제한

XSLT 변환 코드에 사용자 입력이 삽입되거나 확장 기능이 활성화된 경우만 후보.
