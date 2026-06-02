---
id_prefix: SPRING
rules_dir: rules/
---

> ## 핵심 원칙: "Prod 환경의 effective config가 안전하지 않으면 후보이다"
>
> 이 스캐너는 Source→Sink 코드 취약점이 아닌 **Spring Boot 설정 파일 기반 보안 구성**을 점검한다. Spring Boot의 프로파일 시스템(`application.yml` vs `application-prod.yml`)을 고려하여, prod 환경의 effective config(base + prod override 병합 결과)를 기준으로 판정한다.

## 분석 방법 — Prod 프로파일 해석 모델

### Step A: Spring Boot 프로젝트 식별

`pom.xml` 또는 `build.gradle`/`build.gradle.kts`에서 `spring-boot` 관련 dependency를 확인한다. Spring Boot 프로젝트가 아니면 "이상 없음" 반환.

### Step B: 설정 파일 수집 및 Prod 프로파일 해석

1. 프로젝트 전체에서 설정 파일을 탐색:
   - `application.yml`, `application.yaml`, `application.properties`
   - `application-{profile}.yml/yaml/properties`
   - `bootstrap.yml/yaml/properties`, `bootstrap-{profile}.yml/yaml/properties`
   - `src/main/resources/` 하위 포함

2. **Prod 프로파일 식별** — 아래 이름을 prod 프로파일로 간주:
   - `prod`, `production`, `prd`, `release`, `live`, `real`

3. **Effective config 산출**: base 설정(`application.yml`)에 prod 프로파일 설정을 overlay한 결과를 effective config으로 간주. **prod 프로파일에 명시된 값이 base 값을 override한다.**

4. prod 프로파일 설정 파일이 없으면, base 설정만으로 점검하되 "prod 프로파일 설정 파일 부재" 사실을 후보 설명에 기재.

### Step C: 빌드 파일 분석

`pom.xml` / `build.gradle`에서 dependency 존재 여부와 scope를 확인한다:
- `spring-boot-devtools`의 scope (`developmentOnly`, `optional`)
- `h2database`의 scope (`runtime`, `test`)
- `spring-boot-starter-actuator` 존재 여부

### Step D: 항목별 점검

아래 13개 항목 각각에 대해, 패턴 인덱스에서 관련 파일 위치를 확인하고 Read로 읽어 effective config 값을 판정한다.

---


## 점검 항목 및 판정 테이블

### DAEMON_ROOT — 데몬 root 실행

Dockerfile 또는 docker-compose.yml을 확인한다.

| 패턴 | 판정 |
|------|------|
| Dockerfile에 `USER` 지시어 없음 (기본 root) | 후보 |
| `USER root` 명시 | 후보 |
| `USER nobody`, `USER daemon`, `USER appuser` 등 비root 계정 | 제외 |
| Dockerfile 자체가 없음 | 점검 불가 — 후보에서 제외하되 "Dockerfile 부재로 미점검" 기재 |

### LOG_PERMISSION — 액세스 로그

Effective config에서 embedded 서버 종류에 맞는 액세스 로그 설정을 확인한다.

| 패턴 | 판정 |
|------|------|
| `server.tomcat.accesslog.enabled=true` | 제외 |
| `server.jetty.accesslog.enabled=true` | 제외 |
| `server.undertow.accesslog.enabled=true` | 제외 |
| 위 설정이 모두 없음 (embedded 서버에 맞는 로그 미활성화) | 후보 |

### TRACE_ENABLED — TRACE 메서드 허용

Spring Boot의 기본값은 `spring.mvc.dispatch-trace-request=false`(TRACE 미처리, embedded Tomcat은 자체적으로 TRACE 반환). Jetty/Undertow는 이 설정으로 차단 가능.

| 패턴 | 판정 |
|------|------|
| effective config에 `spring.mvc.dispatch-trace-request` 설정 없음 + embedded Tomcat | 후보 (Tomcat 기본 동작이 TRACE 응답) |
| `spring.mvc.dispatch-trace-request=true` + Jetty 또는 Undertow | 제외 (405/500 반환) |
| `spring.mvc.dispatch-trace-request=true` + Tomcat | 후보 (Tomcat은 이 설정으로도 TRACE 차단 안 됨, 별도 Connector 설정 필요) |
| 웹서버(Nginx/Apache)에서 TRACE 차단 설정 확인됨 | 제외 |

### WHITELABEL_ENABLED — Whitelabel 에러페이지

기본값은 `server.error.whitelabel.enabled=true`.

| 패턴 | 판정 |
|------|------|
| effective config에 `server.error.whitelabel.enabled` 없음 (기본값 true) | 후보 |
| `server.error.whitelabel.enabled=true` | 후보 |
| `server.error.whitelabel.enabled=false` | 제외 |
| 커스텀 ErrorController 구현 확인 | 제외 |

### WHITELABEL_SPEL_RISK — 에러 메시지 SpEL 평가·입력 반사

에러 응답이 사용자 입력을 메시지에 반사하고 그 값이 SpEL로 평가되면 RCE로 이어진다 (spring-boot#4763, CVE-2022-22963). 빌드 파일의 버전과 effective config의 입력 반사 설정을 본다. 실제 평가 여부는 Phase 2(`${31337*1}`)에서 확정한다.

| 패턴 | 판정 |
|------|------|
| Spring Boot < 1.3.0 (whitelabel SpEL 평가, #4763 미수정) | 후보 |
| `spring-cloud-function-context` 의존 + CVE-2022-22963 영향 범위(3.1.x ≤ 3.1.6, 3.2.x ≤ 3.2.2) | 후보 |
| `server.error.include-message=always` (입력값 에러 메시지 반사) | 후보 |
| `server.error.include-binding-errors=always` (바인딩 실패 시 입력 반사) | 후보 |
| 위 신호 없음 + 최신 버전(2.x/3.x) | 제외 (`getMessage()` SpEL 미평가 — Whitelabel 노출만이면 `WHITELABEL_ENABLED`로 처리) |

### STACKTRACE_EXPOSED — StackTrace 노출

기본값은 `server.error.include-stacktrace=never` (Spring Boot 2.3+). 2.3 미만은 `on-trace-param`.

| 패턴 | 판정 |
|------|------|
| effective config에 `server.error.include-stacktrace=always` | 후보 |
| `server.error.include-stacktrace=on-param` 또는 `on-trace-param` | 후보 |
| `server.error.include-stacktrace=never` 또는 설정 없음 (Spring Boot 2.3+) | 제외 |
| 설정 없음 + Spring Boot 2.3 미만 | 후보 (기본값이 `on-trace-param`) |

### SWAGGER_ENABLED — Swagger docs 노출

빌드 파일에서 springdoc/swagger 의존성을 확인하고, 설정 파일에서 비활성화 여부를 확인한다.

| 패턴 | 판정 |
|------|------|
| springdoc/springfox 의존성 없음 | 제외 |
| 의존성 존재 + `springdoc.api-docs.enabled=false` | 제외 |
| 의존성 존재 + 비활성화 설정 없음 | 후보 |
| 의존성 존재 + Spring Security로 swagger 경로에 인증 적용 | 제외 |

### ACTUATOR_EXPOSED — Actuator 외부 노출

| 패턴 | 판정 |
|------|------|
| `spring-boot-starter-actuator` 의존성 없음 | 제외 |
| 의존성 존재 + `management.server.port`로 별도 포트 분리 | 제외 |
| 의존성 존재 + Spring Security로 actuator endpoint에 인증 적용 (`EndpointRequest` 사용) | 제외 |
| 의존성 존재 + 접근 제어 없음 | 후보 |

### ACTUATOR_OVEREXPOSED — 불필요 Actuator endpoint 활성화

**[필수] `exposure.include` 리스트의 각 값을 개별 평가한다.** `health`/`info` 외에 포함된 endpoint가 있으면 해당 endpoint들을 모두 후보 제목·본문·POC에 기재한다 (guidelines-phase1.md 지침 11).

| 패턴 | 판정 |
|------|------|
| `management.endpoints.enabled-by-default=false` + 필요 endpoint만 활성화 | 제외 |
| `exposure.include`가 `health`/`info`만 | 제외 |
| `exposure.include=*` | 후보 |
| `exposure.include`에 `health`/`info` 외 endpoint 포함 | 후보 |
| `management.endpoint.shutdown.enabled=true` | 후보 |
| 노출 설정 없음 | Spring Boot 2.x: 제외 / 1.x: 후보 |

### ADMIN_MBEAN_ENABLED — Admin MBean 활성화

기본값은 `spring.application.admin.enabled=false`.

| 패턴 | 판정 |
|------|------|
| `spring.application.admin.enabled=true` | 후보 |
| 설정 없음 (기본값 false) | 제외 |

### DEVTOOLS_PROD — DevTools 운영 포함

| 패턴 | 판정 |
|------|------|
| `spring-boot-devtools` 의존성 없음 | 제외 |
| 의존성 scope가 `developmentOnly` (Gradle) 또는 `optional=true` (Maven) | 제외 |
| 의존성 scope가 `compile`/`implementation` (운영 포함) | 후보 |
| `spring.devtools.remote.secret` 설정 존재 | 후보 (**원격 접속 활성화**) |

### H2_CONSOLE_ENABLED — H2 Console 활성화

기본값은 `spring.h2.console.enabled=false`.

| 패턴 | 판정 |
|------|------|
| `h2database` 의존성 없음 | 제외 |
| 의존성 scope가 `test` | 제외 |
| `spring.h2.console.enabled=true` (effective config) | 후보 |
| 의존성 존재 + 설정 없음 (기본값 false) | 제외 |

### OUTDATED_DEPS — 취약 버전 사용

빌드 파일에서 Spring Boot 버전과 주요 dependency 버전을 확인한다.

| 패턴 | 판정 |
|------|------|
| Spring Boot 버전이 현재 지원 종료(EOL) 브랜치 | 후보 |
| 알려진 CVE가 있는 dependency 버전 사용 | 후보 |
| 최신 패치 버전 사용 중 | 제외 |

**참고**: 버전 판정은 에이전트의 학습 데이터 기준이므로, 최신 CVE 정보와 차이가 있을 수 있다. "정확한 취약 버전 목록은 OSS 도구(OWASP Dependency-Check 등)로 별도 확인을 권장한다"는 안내를 후보 설명에 포함한다.

---

## Sink 의미론

본 스캐너의 "Sink"는 전통적인 코드 흐름(Source→Sink)이 아닌 **보안에 영향을 미치는 설정 속성**이다. 설정값 자체가 공격 표면을 넓히거나 정보를 노출한다.

| 설정 카테고리 | 위험 성격 | 대표 속성 |
|---|---|---|
| Actuator 노출 | 내부 정보 노출 + 원격 조작 | `management.endpoints.web.exposure.include` |
| 디버그/개발 기능 | 상세 에러 정보, 내부 상태 노출 | `spring.devtools.*`, `debug=true` |
| 인메모리 DB 콘솔 | 인증 없는 DB 접근 | `spring.h2.console.enabled` |
| 에러 처리 | 스택 트레이스/내부 경로 노출 | `server.error.include-stacktrace` |
| HTTP 메서드 | 의도하지 않은 메서드 허용 | TRACE 메서드 활성화 |
| 직렬화 | 클래스 정보/내부 필드 노출 | `spring.jackson.default-property-inclusion` |
| 의존성 취약점 | 알려진 CVE 포함 | `spring-boot-starter-*` 버전 |

**판정 원칙**: 설정값이 prod 환경에서 공격 표면을 넓히거나 민감 정보를 노출하면 후보. 기본값이 안전하거나 다른 계층에서 방어하면 제외.

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| Actuator 엔드포인트가 웹에 노출 + 인증 없음 | 후보 (ACTUATOR_EXPOSED) |
| Actuator `exposure.include`에 `health`/`info` 외 endpoint 포함 | 후보 (ACTUATOR_OVEREXPOSED) |
| Actuator가 별도 management 포트로 분리 또는 Spring Security 보호 | 제외 |
| `spring.devtools.*` 의존성/설정이 prod effective config에 존재 | 후보 (DEVTOOLS_PROD) |
| devtools가 `developmentOnly` scope로 제한 | 제외 |
| H2 콘솔 활성화가 prod effective config에 존재 | 후보 (H2_CONSOLE_ENABLED) |
| H2가 `testOnly` scope 또는 dev 프로파일 한정 | 제외 |
| Whitelabel 에러 페이지 활성 | 후보 (WHITELABEL_ENABLED) |
| StackTrace 노출(`include-stacktrace=always/on-param`) | 후보 (STACKTRACE_EXPOSED) |
| 커스텀 ErrorController로 대체 확인 | 제외 |
| TRACE 메서드 허용 (웹서버/프레임워크 레벨) | 후보 (TRACE_ENABLED) |
| 웹서버 설정(Nginx/Apache)에서 TRACE 차단 확인 | 제외 |
| Swagger/springdoc 의존성 + 비활성화 설정 없음 | 후보 (SWAGGER_ENABLED) |
| Dockerfile USER 미지정 (root 기본) | 후보 (DAEMON_ROOT) |
| 액세스 로그 미활성화 | 후보 (LOG_PERMISSION) |
| `spring.application.admin.enabled=true` | 후보 (ADMIN_MBEAN_ENABLED) |
| Spring Boot 버전이 알려진 취약 버전 | 후보 (OUTDATED_DEPS) |
| 최신 패치 버전 사용 확인 | 제외 |

## 자주 놓치는 패턴 (Frequently Missed)

1. **프로파일 override 역전**: `application.yml`(base)에서 `management.endpoints.web.exposure.include=*`로 설정하고, `application-prod.yml`에서 override하지 않은 경우. base 설정이 prod effective config에 그대로 반영된다.
2. **커스텀 actuator 경로**: `management.endpoints.web.base-path`를 `/admin`이나 `/internal`로 변경한 경우, 기본 `/actuator` 경로를 차단하는 웹서버 규칙을 우회한다.
3. **Spring Boot 3.x 기본값 변경**: Boot 2.x에서 3.x로 마이그레이션 시 일부 기본값이 변경됨. 개발자가 2.x 시절 설정을 명시적으로 유지한 경우 의도치 않은 노출 가능.
4. **Conditional actuator 노출**: `@ConditionalOnProperty`로 특정 환경 변수가 설정되면 actuator를 활성화하는 커스텀 설정. 환경 변수 기본값이 `true`이면 prod에서도 활성화.
5. **management 포트 ≠ 네트워크 격리**: `management.server.port`를 설정했더라도 해당 포트가 외부에서 접근 가능하면 방어로 인정하지 않는다. 네트워크 격리를 설정 파일에서 확인할 수 없으므로, management 포트 분리는 조건부 제외로 판정한다.
6. **Actuator `heapdump`/`threaddump` 노출**: exposure.include에 포함되면 heap/thread 상태 덤프 — 메모리 내 시크릿/토큰 노출.
7. **`spring.jpa.show-sql=true` 또는 `logging.level.org.hibernate.SQL=DEBUG`**: prod에서 SQL 전체 로깅 — 민감 데이터 로그 노출.
8. **Spring4Shell (CVE-2022-22965) 미패치**: Spring Framework 5.2.x, 5.3.x 구버전 + JDK 9+ + RequestMapping 객체 바인딩.
9. **Log4Shell (CVE-2021-44228) 잔존**: `log4j-core` 2.x 구버전 직접/전이 의존성.
10. **`server.servlet.session.tracking-modes`**: `URL` 포함 시 JSESSIONID가 URL에 노출 (쿠키 외).
11. **`spring.sql.init.*` data-locations이 사용자 입력 경로**: 초기화 스크립트 경로 변조 시 임의 SQL 실행.

## 안전 패턴 (FP Guard)

- **Spring Security actuator 보호**: `EndpointRequest.toAnyEndpoint()` + `.hasRole()` 설정 확인
- **별도 management 포트**: `management.server.port`로 내부 포트 분리
- **프로파일 override**: base에서 `true`지만 prod 프로파일에서 `false`로 override된 경우 → 제외
- **커스텀 ErrorController**: `BasicErrorController`를 상속/대체하는 클래스가 존재하면 Whitelabel 판정에서 제외
- **웹서버 레벨 차단**: Nginx/Apache 설정에서 TRACE 차단, actuator 경로 차단 등 확인

## 후보 판정 제한

- **점검 대상은 prod 환경 설정만이다**: 이 스캐너의 점검 범위는 prod 프로파일의 effective config(base + prod override)에 한정한다. cbt, dev, staging 등 비-prod 프로파일에서만 발현되는 설정 문제는 후보로 등록하지 않는다.
- **프로파일 분리 존중**: `application-dev.yml`에만 있는 설정(예: `spring.h2.console.enabled=true`)은 prod effective config에 포함되지 않으므로 후보가 아니다.
- **기본값 숙지**: Spring Boot 버전별 기본값이 다르다. 설정 파일에 명시되지 않은 항목은 해당 버전의 기본값으로 판정한다.
- **scope 존중**: `developmentOnly`/`testOnly` scope의 dependency는 운영 환경에 포함되지 않으므로 후보가 아니다.
