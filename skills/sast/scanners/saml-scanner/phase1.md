---
id_prefix: SAML
grep_patterns:
  - "saml"
  - "SAML"
  - "omniauth-saml"
  - "ruby-saml"
  - "passport-saml"
  - "python-saml"
  - "onelogin"
  - "SAMLResponse"
  - "ds:Signature"
  - "ACS"
---

> ## 핵심 원칙: "변조된 SAML Response로 인증이 우회되어야 취약점이다"
>
> SAML 사용 자체는 취약점이 아니다. 서명 제거, Assertion 변조, XML Signature Wrapping (XSW), 잘못된 노드 선택 등으로 다른 사용자로 인증이 통과되어야 한다.

## Sink 의미론

SAML sink는 "SAML Response를 파싱/검증하는 SP(Service Provider) 코드의 검증 단계가 누락되거나 우회 가능한 지점"이다.

| 언어 | 라이브러리 |
|---|---|
| Node | `passport-saml`/`@node-saml/passport-saml`, `saml2-js`, `samlify`, 직접 구현 |
| Python | `python3-saml` (OneLogin), `pysaml2`, `django-saml2-auth` |
| Java | Spring Security SAML, OpenSAML, OneLogin SAML Java Toolkit |
| Ruby | `ruby-saml`, `omniauth-saml` |
| PHP | `onelogin/php-saml`, `simplesamlphp`, `lightsaml` |

**검증 차원:**
1. Response 또는 Assertion의 서명 검증 (`wantAssertionsSigned`/`wantResponseSigned`)
2. `<ds:Reference URI>`가 실제 검증한 노드를 가리키는지 (XSW 방어)
3. XML 파서 XXE 방어 (xxe-scanner와 겹침)
4. `NotBefore`/`NotOnOrAfter`/시계 skew
5. `InResponseTo` (replay 방어)
6. `Audience`/`AudienceRestriction`/`Recipient`/`Destination`
7. `Issuer` 검증
8. NameID 추출 위치 (서명된 노드인지)

## Source-first 추가 패턴

- ACS (Assertion Consumer Service) 엔드포인트 (`/saml/acs`, `/saml/consume`)
- IdP-initiated SSO 엔드포인트
- SLO (Single Logout) 엔드포인트
- 메타데이터 엔드포인트
- IdP 메타데이터 fetch 코드 (URL 신뢰)
- IdP 인증서 로드 코드

## 자주 놓치는 패턴 (Frequently Missed)

- **XML Signature Wrapping (XSW)**: 서명된 Assertion을 그대로 두고, 같은 Response 안에 두 번째 Assertion을 추가. 코드가 첫 번째(서명 안 된) Assertion을 읽고 권한 결정 → 우회. 가장 흔한 SAML 취약점.
- **`<Response>` 서명만 검증, `<Assertion>` 미검증**: XSW로 Assertion 교체.
- **`<Assertion>` 서명만 검증, `<Response>` 미검증**: 다른 IdP가 만든 Response에 유효한 Assertion 끼워넣기.
- **`<ds:Reference URI>` 미검증**: 서명이 가리키는 노드와 실제 사용된 노드 불일치.
- **Comment injection (`<NameID>admin<!--comment-->@evil.com</NameID>`)**: 일부 파서가 comment를 무시하고 텍스트를 합치는 차이로 NameID 변조. CVE-2018-0489 (ruby-saml).
- **NameID를 서명되지 않은 위치에서 추출**: `<Subject>` 노드가 두 개 있을 때 wrong one 선택.
- **XML 정규화 (Canonicalization) 알고리즘 차이**: `c14n` vs `c14n-exclusive` 처리 다름.
- **DSA/MD5/SHA1 서명 알고리즘**: weak crypto.
- **XXE in SAML Response** (xxe-scanner와 겹침): SAML 파싱 시 XML 파서 설정 미흡.
- **`<EncryptedAssertion>` 미처리**: 암호화된 Assertion이 있어야 하는데 평문 Assertion만 검사.
- **`InResponseTo` 미검증**: Replay attack.
- **`NotBefore`/`NotOnOrAfter` 미검증** 또는 시계 skew 과대.
- **`Audience` 미검증**: 다른 SP용 Assertion 재사용.
- **`Recipient`/`Destination` 미검증**: 다른 ACS URL로 발급된 토큰 재사용.
- **`Issuer` 미검증** 또는 부분 매칭.
- **메타데이터 URL HTTP (HTTPS 아님)**: MITM으로 IdP 키 교체.
- **메타데이터 자체 미서명**: 위조 메타데이터로 IdP 키 교체.
- **IdP 키 회전 미지원**: 새 키 발급 후 영구 stale.
- **`samlp:LogoutRequest`에서 SessionIndex 미검증**: 다른 사용자 강제 로그아웃.
- **SAML Raider 같은 도구로 자동 발견되는 패턴**.
- **`<ds:Transforms>` 조작**: Transform 체인에 XSLT 추가로 서명 범위를 좁히거나 다른 노드로 redirect.
- **IdP-initiated SSO without RelayState 검증**: 공격자 제어 RelayState로 open-redirect.
- **SAML Logout (SLO) request CSRF**: LogoutRequest가 서명되지 않으면 강제 로그아웃.
- **HTTP-Redirect binding의 URL 길이 한계 우회**: POST binding 혼용 시 서명 검증 차이.
- **Metadata trust chain 검증 누락**: Federation 메타데이터가 여러 IdP 포함할 때 중간 IdP의 인증서 검증 실패.

## 안전 패턴 (FP Guard)

- **`wantAssertionsSigned: true` + `wantResponseSigned: true`** 둘 다 활성화.
- **`strict: true`** (OneLogin 라이브러리).
- **OpenSAML**의 `SAML20AssertionValidator` + 모든 검증 단계 활성.
- **`<ds:Reference URI>` 검증 + ID-based dereferencing 사용 안 함**.
- **XML 파서 XXE 방어 적용** (xxe-scanner의 안전 패턴 모두).
- **Comment-aware parser 사용 또는 comment 제거 후 검증**.
- **메타데이터 HTTPS + 서명** + IdP 키 사전 등록.
- **시계 skew 60초 이하**.
- **Assertion 1회용 강제 (cache)**.
- **외부 IdP 위임 (Okta/AzureAD/OneLogin) + 라이브러리 strict 옵션**.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| Response만 서명 검증 | 가능 | XSW — 서명된 Response 내부에 추가 Assertion 삽입 후 앱이 두 번째를 읽음 |
| Assertion만 서명 검증 | 가능 | 다른 IdP에서 유효한 Assertion을 자신의 Response에 래핑 |
| ID-based 검증 (`URI="#id"`) | 가능 | 동일 ID를 가진 여러 노드 생성 — 파서가 첫 번째 검색, 서명은 다른 위치 |
| Comment 무시 파서 | 가능 | `<NameID>admin<!--x-->@evil.com</NameID>` — 일부 파서가 comment 건너뛰고 문자 병합 (CVE-2018-0489) |
| 시계 skew 60초 | 부분 가능 | 공격 윈도우 — Assertion 재사용 캐시 없으면 1분 내 replay 가능 |
| 메타데이터 서명 검증 | 부분 가능 | 메타데이터 서명 키 자체가 HTTP로 fetch 되면 MITM으로 키 교체 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| `wantAssertionsSigned`/`wantResponseSigned` 둘 다 또는 둘 중 하나 false | 후보 (라벨: `SIGN_OPTIONAL`) |
| 서명 검증하지만 검증된 노드와 사용된 노드 불일치 가능성 | 후보 (라벨: `XSW`) |
| comment-aware parser 미사용 + ruby-saml 등 알려진 라이브러리 구버전 | 후보 (라벨: `COMMENT_INJECTION`) |
| `InResponseTo`/`Audience`/`Recipient` 검증 누락 | 후보 |
| XML 파서 XXE 방어 미적용 | **xxe-scanner `SAML_XXE` 단독 담당** — 본 스캐너 후보 아님 (위임) |
| 메타데이터 HTTP fetch | 후보 (라벨: `METADATA_MITM`) |
| `strict: true` + 모든 검증 옵션 + 최신 라이브러리 | 제외 |

## 후보 판정 제한

SAML 라이브러리를 직접 사용하는 코드가 있는 경우만 분석. 외부 서비스에 완전 위임 시 제외 (단 callback 처리 코드는 확인).
