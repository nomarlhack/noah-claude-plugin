---
id_prefix: REDOS
rules_dir: rules/
---

> ## 핵심 원칙: "응답 지연이 발생하지 않으면 취약점이 아니다"
>
> 취약해 보이는 정규식 자체가 취약점이 아니다. (1) 사용자 입력이 그 정규식의 매칭 대상으로 도달하고, (2) 악의적 입력으로 유의미한 응답 지연(수 초 이상)이 발생해야 한다.

## Sink 의미론

ReDoS sink는 "사용자 입력이 backtracking NFA 정규식 엔진에서 catastrophic backtracking이 가능한 패턴에 매칭되는 지점"이다. RE2 기반 엔진(Go regexp, Rust regex)은 선형 시간 보장 → sink 아님.

| 언어 | 엔진 | 위험도 |
|---|---|---|
| JavaScript (V8) | NFA backtracking | **높음** (Node 메인 스레드 블로킹) |
| Python `re` | NFA backtracking | 높음 (`re2` 모듈은 안전) |
| Java `java.util.regex` | NFA backtracking | 높음 |
| Ruby Onigmo | NFA | 높음 |
| PHP PCRE | NFA | 중간 (`pcre.backtrack_limit`로 완화) |
| Go `regexp` | RE2 | **안전 (선형)** |
| Rust `regex` | RE2 | **안전** |
| .NET `Regex` | NFA | 높음 (4.5+ `MatchTimeout` 지원) |

**sink 함수:**
- JS: `regex.test(x)`, `x.match(regex)`, `x.replace(regex, ...)`, `x.split(regex)`, `new RegExp(p).test(x)`
- Python: `re.match/search/findall/sub/fullmatch`
- Java: `Pattern.matcher(x).matches`, `String.matches(p)`, `String.replaceAll(p, r)`
- Ruby: `=~`, `String#match`, `gsub`
- PHP: `preg_match`, `preg_match_all`, `preg_replace`

## Source-first 추가 패턴

- 사용자 입력 검증 (이메일/URL/전화번호/날짜)
- 검색어
- 파일명/경로
- 사용자가 직접 정규식 입력 (검색 필터, 알림 규칙)
- 로그/메시지 파싱 (사용자 데이터를 정규식으로 split)
- HTTP User-Agent 파싱
- Markdown/BBCode 파서 내부 정규식
- WAF/보안 미들웨어 자체의 정규식

## 자주 놓치는 패턴 (Frequently Missed)

- **중첩 반복**: `(a+)+`, `(a*)*`, `(a+)*`, `(.*)*`. 가장 전형적.
- **겹치는 교대 + 반복**: `(a|ab)+`, `(a|a?)+`, `(a|aa)+`. 같은 입력이 두 가지 path로 매칭됨.
- **욕심많은 매칭 + anchor 부재**: `^(a+)+$` — 매칭 실패 시 catastrophic.
- **이메일 정규식 (RFC 5322 흉내)**: `^([a-zA-Z0-9_\-\.]+)@(...)+\.(...)+$` 형태가 ReDoS 자주 유발. 유명 CVE 다수.
- **URL 정규식**.
- **CSS selector 정규식**.
- **`(.*)+` 또는 `.*?` + lookahead**: 일부 lookahead 조합이 NFA를 폭발.
- **`new RegExp(userInput)` (regex injection + ReDoS)**: 사용자가 정규식 자체를 제공.
- **`replace`의 replacement 콜백 안에서 또 정규식**: 중첩 호출.
- **JSON Schema validator 내부 정규식 (`pattern` 키)**: Ajv는 옵션으로 ReDoS 차단 가능하지만 기본 미적용.
- **markdown-it 이전 버전, marked 이전 버전**: 다수 ReDoS CVE.
- **moment.js 파싱 정규식**.
- **`validator.js`의 `isURL`/`isEmail`** 일부 버전.
- **`semver` 라이브러리** 일부 버전.
- **express path-to-regexp 5.x 이전**: route 정의 자체에서 ReDoS.
- **WAF/방화벽 우회용 입력**: `aaaa...!` 형태 (n=30 이상이면 수 초).
- **백트래킹 트리거 위치를 못 잡는 경우**: 패턴이 짧아 보여도 입력 패턴과 결합 시 폭발.
- **Node.js `pcre-to-regexp` / `path-to-regexp` 6.x 미만**: route 정의 자체 ReDoS (CVE-2024-45296).
- **AWS WAF/Cloudflare 정규식 룰**: 관리자 입력으로 룰 추가 가능 시 WAF 자체가 ReDoS 증폭기.
- **JSON Schema `pattern` 필드**: Ajv 기본 설정에서 사용자 schema 허용 시 ReDoS.
- **`xml2js` attribute parsing**: 구버전에서 정규식 기반 파싱 ReDoS 사례.
- **Prometheus/Grafana label selector**: 레이블 매칭 정규식에 사용자 입력 허용.

## 안전 패턴 (FP Guard)

- **RE2 엔진 사용**: Go `regexp`, Rust `regex`, Python `google-re2`.
- **타임아웃 설정**: .NET `Regex(p, opts, TimeSpan.FromMilliseconds(100))`, Node `vm.runInNewContext` with timeout (간접적), Java `Pattern.compile` + thread interrupt.
- **입력 길이 제한** (예: 256자) — 짧은 입력은 backtrack도 빠름.
- **단순 정규식만 사용** (반복 없거나 atomic group `(?>...)`).
- **possessive quantifier** (Java/PCRE `*+`/`++`): backtracking 차단.
- **atomic group `(?>...)`** (Java/PCRE/Ruby).
- **고유 라이브러리 사용**: 이메일 검증은 `validator.js` 대신 `email-validator` 같은 단순 라이브러리.
- **Linter (ESLint `security/detect-unsafe-regex`, `safe-regex` npm)** 적용 확인.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| 입력 길이 제한 (예: 256자) | 부분 가능 | 짧은 입력으로도 최악 케이스 가능한 패턴 — 입력 30자에 수 초 소요 사례 다수 |
| 타임아웃 설정 | 부분 가능 | 타임아웃이 너무 길면 (예: 10초) 동시 요청 N개로 서비스 고갈. 100ms 정도 권장 |
| 단일 정규식 RE2 이식 | 부분 가능 | 다른 정규식은 여전히 NFA. 전체 코드베이스 일괄 이식 필요 |
| `new RegExp(escape(userInput))` (regex injection만 방어) | 부분 가능 | escape해도 긴 literal은 여전히 매칭 부담. ReDoS는 여전 |
| Possessive quantifier (Java `++`) | 부분 가능 | 패턴 일부만 적용 시 다른 부분이 취약 — 전체 리팩터링 필요 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 중첩 반복 또는 겹치는 교대 + 사용자 입력 도달 | 후보 |
| RE2 엔진 사용 | 제외 |
| 타임아웃 명시 적용 | 제외 (라벨: 영향도 낮음) |
| 입력 길이 제한 명시 (예: 256자 이하) + 패턴 복잡도 보통 | 영향도 낮음, 후보 유지하되 라벨 |
| `new RegExp(userInput)` | 후보 (라벨: `REGEX_INJECTION`) |
| 라이브러리 알려진 ReDoS CVE 버전 + 호출부 사용자 입력 | 후보 (라벨: `LIB_CVE`) |
| Node.js + 메인 스레드에서 동기 매칭 | 후보 (영향도 격상, 전체 서비스 블로킹) |

## 후보 판정 제한

중첩 반복 + 모호 교대 패턴이 있고, 사용자 입력이 매칭 대상으로 도달하는 경우만 후보. RE2 기반 엔진은 제외.
