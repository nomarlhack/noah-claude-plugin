---
id_prefix: SOAPACT
rules_dir: rules/
---

> ## 핵심 원칙: "SOAPAction 변조로 인가가 우회되어야 취약점이다"
>
> SOAPAction 헤더 변조 가능성 자체가 취약점이 아니다. 변조로 권한 없는 오퍼레이션이 실행되거나 인증/인가가 우회되어야 한다.

## Sink 의미론

SOAPAction Spoofing sink는 "SOAP 서비스가 SOAPAction 헤더와 SOAP Body의 오퍼레이션을 일치시키지 않거나, SOAPAction 기반 인가와 실제 실행 오퍼레이션 사이에 불일치가 있는 지점"이다.

| 언어 | 프레임워크 |
|---|---|
| Java | JAX-WS (`@WebService`/`@WebMethod`), Apache CXF, Apache Axis/Axis2, Spring-WS (`@Endpoint`/`@PayloadRoot`) |
| Python | `zeep` (client), `spyne` (server), `suds` (client) |
| Node | `soap`, `strong-soap`, Express + 직접 XML |
| .NET | WCF, ASP.NET Web Services (`.asmx`) |
| PHP | `SoapServer` (내장), `NuSOAP` |

## Source-first 추가 패턴

- WSDL 파일 (`.wsdl`)
- `@WebService`/`@WebMethod` 어노테이션
- Spring-WS `@Endpoint`/`@PayloadRoot`
- WCF `[OperationContract]`
- WAF/gateway의 SOAPAction 라우팅 규칙
- 인터셉터/handler chain
- WS-Security 설정

## 자주 놓치는 패턴 (Frequently Missed)

- **SOAPAction 헤더와 Body 오퍼레이션 불일치 미검증**: gateway는 SOAPAction으로 인가, 백엔드는 Body로 디스패치 → 가벼운 SOAPAction으로 통과 후 권한 있는 오퍼레이션 호출.
- **빈 SOAPAction (`SOAPAction: ""`)**: 일부 서버가 모든 오퍼레이션 허용 또는 디폴트 처리.
- **SOAPAction 누락**: 동일.
- **SOAPAction 인용부호 처리 차이**: `SOAPAction: "op"` vs `SOAPAction: op`.
- **WAF가 SOAPAction만 검사, Body 미검사**: signature-based WAF 회피.
- **여러 오퍼레이션 동일 SOAPAction**: namespace collision.
- **WS-Addressing `wsa:Action` vs SOAPAction 불일치**: SOAP 1.2.
- **SOAPAction이 case-insensitive 매칭**: `getUserInfo` vs `getuserinfo`.
- **Method-level 인가 어노테이션 누락**: `@RolesAllowed` 미적용 + 클래스 레벨만.
- **WSDL operation overloading**: 같은 이름 다른 인자 → 디스패치 혼동.
- **WS-Security UsernameToken 검증 누락**.
- **`mustUnderstand` 헤더 처리 미흡**.
- **SOAP Body의 namespace 변조**: 다른 namespace의 동명 오퍼레이션.
- **`xsi:type` 인젝션**: polymorphic deserialization (deserialization-scanner와 결합).
- **WS-Trust/WS-Federation 토큰 검증 누락**.
- **MTOM/XOP 첨부에 페이로드 숨김**.
- **PHP `SoapServer` `actor`/`mustUnderstand` 처리**.
- **WS-Addressing `wsa:To` / `wsa:ReplyTo` 조작**: 요청 재전송 경로를 공격자 endpoint로 변경 — XXE/SSRF 결합.
- **CXF/Axis MessageContext poisoning**: 인터셉터에서 헤더 조작 후 다음 handler 믿음 체인 붕괴.
- **SAML assertion in SOAP header (WS-Security SAML Token Profile)**: SAML 검증 우회 결합.
- **Polyglot SOAP/REST endpoint**: 같은 URL이 Content-Type에 따라 분기 — Content-Type 위조로 다른 처리 유도.

## 안전 패턴 (FP Guard)

- **메서드 레벨 인가** (`@PreAuthorize`/`@RolesAllowed`/`@Secured`).
- **JAX-WS handler chain에서 SOAPAction == Body operation 검증**.
- **Spring-WS `@PayloadRoot`** 매칭 (Body 기반 디스패치) + 메서드 레벨 인가.
- **WS-Security UsernameToken/Timestamp/Signature 검증** 활성.
- **gateway 인가를 SOAPAction이 아닌 인증 토큰 기반**.
- **WSDL 비공개** + 정확한 schema validation.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| SOAPAction 인가만 | 가능 | Body operation이 다른 경우 백엔드가 Body로 디스패치 — 가벼운 op로 통과 후 권한 op 실행 |
| SOAPAction 대소문자 정확 매칭 | 부분 가능 | 백엔드가 case-insensitive면 대소문자 변형으로 우회 가능 |
| WS-Security 서명 검증 | 부분 가능 | XSW (XML Signature Wrapping) — 서명된 부분과 파싱되는 부분 분리 |
| `mustUnderstand=true` 헤더 적용 | 가능 | 일부 서버가 `mustUnderstand` 자체를 인식 못 하면 silent skip |
| XML schema validation | 부분 가능 | `xsi:type` 다형성 허용 시 추상 타입으로 우회, XML encoding 차이 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| SOAPAction 기반 인가 + Body 기반 디스패치 (불일치 가능) | 후보 |
| 빈/누락 SOAPAction 처리가 default 오퍼레이션 호출 | 후보 |
| 메서드 레벨 인가 어노테이션 누락 (클래스 레벨만) | 후보 |
| WS-Security 설정 없음 + 외부 노출 | 후보 (라벨: `NO_WSSEC`) |
| Spring-WS `@PayloadRoot` + `@PreAuthorize` 메서드 레벨 | 제외 |
| WAF SOAPAction 필터링이 유일 방어 | 후보 (라벨: `WAF_BYPASS`) |
| `xsi:type` polymorphic 처리 + 화이트리스트 없음 | 후보 (라벨: `TYPE_INJECTION`) |

## 후보 판정 제한

SOAP 엔드포인트를 직접 구현하는 코드가 있는 경우만 분석. 외부 SOAP 클라이언트 호출만 있는 경우 제외.
