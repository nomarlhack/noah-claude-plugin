---
id_prefix: LOGINJ
archetype: presence
---

> ## 핵심 원칙: "로그에 들어간 사용자 입력은 개행 주입과 민감 정보 노출 두 가지를 동시에 야기한다"
>
> Log Injection은 두 가지 위협을 포함한다: (1) CRLF 주입으로 로그 위조·포렌식 방해, (2) 사용자 입력(비밀번호·토큰·PII)이 로그에 그대로 기록되어 로그 파일 접근자에게 노출. 두 경우 모두 source가 외부 입력이면 후보다.

## Sink 의미론

로그 기록 함수가 sink다.

| 언어 | 라이브러리 | sink 함수 |
|------|----------|---------|
| Python | logging, loguru, structlog | `logger.info/debug/warning/error/critical(user_input)` |
| JS/TS | console, winston, pino, bunyan | `console.log/error(req.body)`, `logger.info({user: req.body.user})` |
| Java | slf4j, log4j, logback | `log.info("{}", userInput)`, `LOG.debug(userInput)` |
| Kotlin | slf4j, kotlin-logging | `logger.info { userInput }`, `log.debug(userInput)` |
| Ruby | Rails logger, Logger | `logger.info(params[:user])` |
| Go | log, zap, logrus | `log.Printf("%s", r.FormValue("q"))` |

**점검 차원:**
1. CRLF 주입 (개행으로 로그 라인 위조)
2. 민감 정보 로깅 (비밀번호, 토큰, 카드번호가 그대로 기록)
3. 비정형 로그 (구조화되지 않은 문자열 보간)

## Source-first 추가 패턴

- 로그인 실패 핸들러: `username`, `password` 파라미터가 로그에 기록되는 경우
- 에러 핸들러: `request.body` 전체가 로그에 dump되는 경우
- 디버그 미들웨어: 요청 헤더/바디 전체 로깅

## 자주 놓치는 패턴 (Frequently Missed)

- **비밀번호 로깅**: `log.debug(f"Login attempt: {username}:{password}")` 로그인 실패 시
- **전체 요청 로깅**: `logger.info(JSON.stringify(req.body))` — 바디에 비밀번호 포함 가능
- **예외 메시지에 민감 데이터**: `logger.error(str(e))` — e가 SQL 에러(DB구조 노출) 또는 인증 에러(자격증명 노출)일 때
- **F-string 보간**: `logger.info(f"Request: {request.POST}")` — dict 전체 덤프

## 안전 패턴 (FP Guard)

- 로그 전 개행 제거: `logger.info(user_input.replace('\n', '').replace('\r', ''))` → 제외
- 구조화 로깅 (키-값 분리): `logger.info("login_attempt", username=username)` — 값이 분리되어 파싱됨 → CRLF 위험 감소 (단, 민감 정보 여부는 별도 확인)
- 로깅 라이브러리 자체 개행 이스케이프 (loguru 일부 버전) → RUNTIME_DEPENDENT 후보

## 우회 가능 패턴

| 방어 코드 | 우회 가능성 |
|----------|----------|
| `str(user_input)` 타입 캐스트만 | CRLF 여전히 포함 가능 |
| `repr(user_input)` | CRLF를 `\r\n`으로 표현 — 로그 파서에 따라 여전히 위험 |

## 후보 판정 의사결정

| 조건 | 판정 |
|------|------|
| 사용자 입력이 개행 제거 없이 로그 함수에 직접 전달 | 후보 (라벨: `CRLF_LOG_INJECTION`) |
| 비밀번호/토큰 파라미터가 로그에 기록 | 후보 (라벨: `SENSITIVE_LOG`) |
| request.body/POST 전체가 로그에 기록 | 후보 (라벨: `SENSITIVE_LOG`, `POTENTIAL_CRLF`) |
| 에러 메시지에 DB 구조/자격증명이 포함될 수 있는 패턴 | 후보 (라벨: `SENSITIVE_LOG`) |
| 개행 제거 후 로깅 | 제외 (CRLF) |
| 구조화 로깅으로 값 분리 + 민감 정보 아닌 필드 | 제외 |

## 후보 판정 제한

순수 로컬 내부 값(서버 생성 로그 ID, 타임스탬프, 고정 상수)은 제외. 분석 도구 자체 로그 출력은 제외.
