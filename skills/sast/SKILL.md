---
name: sast
description: "46개 취약점 스캐너 + AI 자율 탐색을 실행하고 결과를 통합 보고서로 작성하는 스킬. XSS, SSRF, SQLi, CSRF, TLS, 비즈니스 로직, LLM 취약점 등 모든 취약점 유형을 소스코드 분석, AI 자율 탐색, 동적 테스트로 점검한다. 사용자가 'noah-8719:sast', 'sast', '소스코드 취약점 스캔' 등을 요청할 때 이 스킬을 사용한다."
---

# Noah SAST — 통합 취약점 스캐너

46개 개별 취약점 스캐너와 AI 자율 탐색을 실행하고, 모든 결과를 하나의 통합 보고서로 작성하는 스킬이다.

> `[필수]`는 writer 권한 위반·보안 사고 등 위반 시 치명적 결과를 초래하는 항목에만 붙인다. 태그 없는 항목도 모두 준수 의무이며, 태그는 우선순위가 아닌 경고 수위 표시다.

## 실행 원칙

백그라운드 Bash 호출의 완료는 시스템 알림으로 감지한다. polling/`sleep` 금지.

## 실행 프로세스

### Step 1: 실행 경로 확정

모든 Step보다 먼저 실행한다. 이 스킬의 루트 디렉토리 절대 경로를 결정한다. 모든 스캐너와 유틸리티가 이 디렉토리 하위에 있다.

`NOAH_SAST_DIR`은 다음 경로이다:

```
${CLAUDE_PLUGIN_ROOT}/skills/sast
```

> `${CLAUDE_PLUGIN_ROOT}`는 Claude Code가 플러그인 로드 시 자동 치환하는 변수이다. 치환되지 않은 경우(리터럴 문자열 그대로 보이는 경우), 아래 Bash fallback을 실행한다:
>
> ```bash
> for base in "$HOME/.claude/skills/noah-8719" "$HOME/.claude/skills/noah-sast" "$HOME/.claude/plugins/noah-8719"; do
>   if [ -d "$base/skills/sast/scanners" ]; then cd "$base/skills/sast" && pwd; break; fi
> done
> ```

이 값을 `NOAH_SAST_DIR` 변수로 보관한다. 이후 모든 경로 참조에 사용한다. 서브 에이전트 프롬프트에는 `<NOAH_SAST_DIR>`을 변수명이 아닌 **resolve된 실제 경로 문자열**로 치환하여 삽입한다. 서브 에이전트가 경로를 스스로 결정하거나 해석하도록 맡기지 않는다.

**디렉토리 구조:**
```
<NOAH_SAST_DIR>/                   ← ${CLAUDE_PLUGIN_ROOT}/skills/sast
  SKILL.md                         ← 이 파일 (오케스트레이터)
  prompts/                         ← 서브 에이전트 지시 문서
    guidelines-phase1.md           ← Phase 1 공통 지침
    guidelines-phase2.md           ← Phase 2 공통 지침
    phase1-group-agent.md          ← Phase 1 그룹 에이전트 프롬프트
    ai-discovery-agent.md          ← AI 자율 취약점 탐색 에이전트 프롬프트
    phase2-agent.md                ← Phase 2 동적 테스트 에이전트 프롬프트
  scanners/                        ← 46개 취약점 스캐너
    xss-scanner/
    sqli-scanner/
    ...
  tools/                           ← Python 유틸리티 스크립트
    grep_index.py              ← grep 인덱싱 (Step 2)
    select_scanners.py
    phase1_build_master_list.py
    phase2_review_assert.py
    phase2_actuator_check.py
  sub-skills/                      ← 내부 서브스킬
    scan-report/
    scan-report-review/
    chain-analysis/
  tests/                           ← grep 커버리지 테스트
```

### Step 2: grep 인덱싱

Step 3 진입 전에 완료한다. 개별 취약점 스캐너 에이전트가 코드베이스를 중복 탐색하는 것을 방지하기 위해, 모든 스캐너 패턴을 일괄 인덱싱한다.

#### Step 2-1: 디렉토리 경로 생성

메인 에이전트가 Bash로 두 디렉토리 경로를 생성한다:

```bash
echo "/tmp/scan_index_$(basename <PROJECT_ROOT>)_$(date +%s)"
echo "/tmp/phase1_results_$(basename <PROJECT_ROOT>)_$(date +%s)"
```

출력값을 각각 `PATTERN_INDEX_DIR`, `PHASE1_RESULTS_DIR` 변수로 보관한다. 이후 모든 경로 참조에 사용한다. 서브 에이전트 프롬프트에는 **resolve된 실제 경로 문자열**로 치환하여 삽입한다.

#### Step 2-2: 인덱싱 실행

아래 래퍼 스크립트로 실행한다. 스크립트 exit code는 stdout의 `run_grep_index_exit=N` 줄에서 읽는다 (Bash tool 최종 exit는 항상 0).

```bash
python3 <NOAH_SAST_DIR>/tools/grep_index.py --scanners-dir <NOAH_SAST_DIR>/scanners --project-root <PROJECT_ROOT> --out-dir <PATTERN_INDEX_DIR>
```

**분기 판정 (메인 에이전트):**

| `run_grep_index_exit` | `json_count` vs `expected` | 의미 | 조치 |
|------|------|------|------|
| `0` | 일치 | 모든 스캐너 정상 | Step 3 진행 |
| `2` | 일치 | 부분 실패 (`_failures.json` 존재) | 아래 "실패 사유별 대응" 참조 후 조치 |
| `1` 또는 불일치 | — | 환경/CLI 오류 또는 무결성 실패 | 원인 파악 후 재실행 |

**exit 2 시 실패 사유별 대응:**

메인 에이전트가 `<PATTERN_INDEX_DIR>/_failures.json`을 Read하여 `reason` 필드로 분기:

- `yaml_parse_error`: 해당 스캐너 `phase1.md` frontmatter 수정 필요 (버그 — 이슈 보고)
- `regex_error`: 해당 스캐너 `phase1.md`의 `grep_patterns` 중 정규식 오류 (버그 — 이슈 보고)
- `grep_timeout`: 프로젝트 크기가 크거나 패턴이 과다 매치. `PROJECT_ROOT` 서브디렉토리 분할 검토
- `io_error`: 파일 시스템 권한/경로 점검 후 전체 재실행
- `phase1_md_missing`: 스캐너 디렉토리 구조 오류 (버그 — 이슈 보고)

`yaml_parse_error`, `regex_error`, `phase1_md_missing`은 해당 스캐너의 JSON이 빈 `{}`로 저장되므로 나머지 스캐너는 정상 진행된다.

### Step 3: 프로젝트 스택 파악

모든 스캐너에 공통으로 필요한 프로젝트 정보를 먼저 파악한다:
- `package.json`, `requirements.txt`, `pom.xml`, `Gemfile` 등에서 프레임워크/언어/라이브러리 확인
- 프로젝트 구조 파악 (서버, 클라이언트, 설정 파일 위치)
- 인증 방식 확인 (세션, JWT, OAuth, SAML 등)
- DB 종류 확인 (SQL, NoSQL, LDAP 등)
- 프록시/CDN/로드밸런서 구조 확인
- **sandbox/dev 도메인 추출**: 환경별 설정 파일, 인프라 설정, CORS/OAuth 설정 등에서 sandbox/dev 도메인을 추출하여 `SANDBOX_DOMAINS`에 보관한다. 보고서 POC URL의 호스트 플레이스홀더를 실제 도메인으로 채우는 데 사용한다.

### Step 4: 스캐너 선별

**기본 원칙: 포함이 기본이고, 제외에는 근거가 필요하다.**

#### Step 4-1: 제외 여부 결정 (자동화 스크립트)

> Step 2에서 `grep_index.py` stdout의 카운트 요약은 보관만 하면 되며, 메인 에이전트가 별도 테이블로 출력할 의무는 없다. `select_scanners.py`가 동일 정보를 더 풍부한 형태로 출력한다.

`select_scanners.py`를 실행하여 grep 인덱스 + 프로젝트 아키텍처 기반으로 자동 선별한다:

```bash
python3 <NOAH_SAST_DIR>/tools/select_scanners.py <PATTERN_INDEX_DIR> <PROJECT_ROOT> \
  --write-expected-file=<PHASE1_RESULTS_DIR>/_expected_scanners.json
```

스크립트 출력:
- 적용/제외 판정 테이블 (grep 히트 건수 + 사유 포함)
- 적용 스캐너 목록
- `<PHASE1_RESULTS_DIR>/_expected_scanners.json`: 적용 스캐너 이름 목록 (JSON). `phase1_build_master_list.py`가 자동으로 읽어 Phase 1 완료 후 누락 파일을 MISSING_FILE 에러로 보고한다.

**기본 원칙: 포함이 기본이고, 제외에는 근거가 필요하다.**
- grep 결과 1건 이상 → 반드시 포함
- grep 결과 0건 → 스크립트가 아키텍처 조건을 검사하여 제외 가능 여부 판단

#### Step 4-2: 스캐너 선별 결과 AI 검토

`select_scanners.py`는 라이브러리 의존성 + grep 히트 수만으로 판단하므로 아래 케이스를 놓친다. 메인 에이전트가 제외된 스캐너 목록을 아래 체크리스트로 검토하여 복원 여부를 결정한다.

**검토 체크리스트 (제외된 각 스캐너에 대해):**

1. **커스텀 구현 확인**: 알려진 라이브러리 없이 네이티브 API로 직접 구현한 경우가 있는가?
   - 예: `fetch()` (Node 18+ 내장)로 서버사이드 HTTP 요청 → SSRF 스캐너 복원
   - 예: `net/http` (Go 표준 라이브러리)로 HTTP 요청 → SSRF 스캐너 복원
   - 예: `string.format()` + `cursor.execute()` (Python 내장)으로 SQL 쿼리 → SQLi 스캐너 복원
   - 예: `xml.etree.ElementTree` (Python 내장)으로 XML 파싱 → XXE 스캐너 복원

2. **프레임워크 내장 기능 확인**: 프레임워크 자체가 해당 기능을 제공하는 경우가 있는가?
   - 예: Spring의 `RestTemplate`/`WebClient` → SSRF 스캐너 복원
   - 예: Rails의 `render inline:` → SSTI 스캐너 복원
   - 예: Django ORM의 `raw()`, `extra()` → SQLi 스캐너 복원

3. **멀티 언어 프로젝트**: `package.json`에 없지만 다른 언어 서브프로젝트에서 사용하는 경우가 있는가?
   - Step 3에서 파악한 프로젝트 스택 정보 활용

**적용**: 체크리스트에 해당하는 스캐너가 있으면 적용 목록에 복원한다. 검토 결과를 1줄 요약으로 기록하고 진행한다.

### Step 5: 정적 분석

선별된 스캐너를 `select_scanners.py`가 출력한 그룹 편성에 따라 묶어, 그룹당 1개 에이전트로 실행한다.

**그룹 편성**: Step 4-1에서 실행한 `select_scanners.py`의 `--- 그룹 편성 ---` 출력을 그대로 사용한다. 이 스크립트는 의미적 연관성 기반 기본 그룹에서 시작하되, grep 히트 수 합계가 150건을 초과하거나 그룹 내 스캐너가 5개 이상이면 자동 분할한다. 적용 스캐너가 없는 그룹은 자동 제거된다.

**기본 그룹 (참고용, 실제 편성은 스크립트 출력을 따름):**

| 그룹 | 스캐너 |
|------|--------|
| url-navigation | xss, dom-xss, open-redirect |
| response-header | crlf-injection, host-header, http-method-tampering |
| db-query | sqli, nosqli |
| process-execution | command-injection, ssti |
| server-request | ssrf, pdf-generation |
| file-system | path-traversal, file-upload, zipslip |
| xml-serialization | xxe, xslt-injection, deserialization |
| auth-protocol | jwt, oauth, saml, csrf, idor, cookie-security |
| client-rendering | redos, css-injection, prototype-pollution |
| infra-config | http-smuggling, sourcemap, subdomain-takeover, security-headers, springboot-hardening, tls |
| data-export | csv-injection |
| protocol-check | graphql, websocket, soapaction-spoofing, ldap-injection, xpath-injection |
| business-logic | business-logic, validation-logic |
| llm | prompt-injection, system-prompt-leakage, insecure-output-handling, unbounded-consumption |
| mobile | android-deeplink |

과부하 시 분할 예시: `auth-protocol`이 분할되면 → `auth-protocol-1` (jwt, oauth, saml) + `auth-protocol-2` (csrf, idor).

Phase 1 에이전트는 단일 메시지 안에서 모든 그룹의 Agent 도구를 동시에 호출하여 병렬 실행한다. 모든 에이전트가 완료된 후에만 Step 6로 진행한다. 완료 후 그룹 수와 수신된 결과 수를 대조하여, 누락된 에이전트가 있으면 해당 그룹만 재실행한다. 반환 요약에 `[INCOMPLETE: scanner-name]`이 있으면 해당 스캐너만 별도 그룹으로 재실행한다.

**Phase 1 결과 디렉토리 생성:** 그룹 에이전트 실행 전에 디렉토리를 생성한다.

```bash
mkdir -p <PHASE1_RESULTS_DIR>
```

메인 에이전트는 그룹 에이전트 프롬프트 본문(절차/결과 형식)을 인라인으로 복사하지 않는다. 대신 아래 형식의 짧은 프롬프트를 사용한다. `<NOAH_SAST_DIR>`/`<PATTERN_INDEX_DIR>`/`<PHASE1_RESULTS_DIR>`는 resolve된 실제 경로 문자열로 치환한다.

```
<NOAH_SAST_DIR>/prompts/phase1-group-agent.md를 Read 도구로 읽고 그 안의 절차를 정확히 따르세요.
변수: NOAH_SAST_DIR=<NOAH_SAST_DIR>, PHASE1_RESULTS_DIR=<PHASE1_RESULTS_DIR>

이 그룹에서 분석할 스캐너:
- xss-scanner
  - phase1.md: <NOAH_SAST_DIR>/scanners/xss-scanner/phase1.md
  - 패턴 인덱스: <PATTERN_INDEX_DIR>/xss-scanner.json
  - 결과 파일: <PHASE1_RESULTS_DIR>/xss-scanner.md
- dom-xss-scanner
  - phase1.md: <NOAH_SAST_DIR>/scanners/dom-xss-scanner/phase1.md
  - 패턴 인덱스: <PATTERN_INDEX_DIR>/dom-xss-scanner.json
  - 결과 파일: <PHASE1_RESULTS_DIR>/dom-xss-scanner.md
- ...(그룹의 모든 스캐너)
```

`prompts/phase1-group-agent.md`에 파일 작성 형식과 공통 절차가 정의되어 있으므로, 메인 에이전트는 본문을 절대 축약·재작성·재인용하지 않는다.

> **주의: Phase 1 완료 시점에서 보고서 파일(.md/.html)을 생성하지 않는다.** 보고서는 Step 12에서만 작성한다.

**Phase 1 결과 검증 및 마스터 목록 생성:**

모든 그룹 에이전트가 완료되면, `phase1_build_master_list.py`를 실행하여 결과를 검증하고 후보 마스터 목록을 생성한다:

```bash
python3 <NOAH_SAST_DIR>/tools/phase1_build_master_list.py <PHASE1_RESULTS_DIR> <PHASE1_RESULTS_DIR>/master-list.json
```

스크립트 검증 항목:
- manifest `declared_count`와 실제 `## <ID>:` 헤더 수 일치
- manifest ID와 prose 헤더 교차 대조
- 필수 섹션(`### Code`, `### Source→Sink Flow` 등) 존재 및 최소 길이
- 동일 file:line 후보 그룹핑 (중복 sink 감지)

**ERROR 발생 시**: 해당 스캐너의 그룹 에이전트를 재실행한다.
**WARNING 발생 시**: 해당 후보의 결과 파일(`<PHASE1_RESULTS_DIR>/<scanner-name>.md`)을 확인하고 필요 시 보완한다.

**중단 후 재개 (토큰 한도 등):** 재개 요청 시 `python3 <NOAH_SAST_DIR>/tools/phase1_resume.py <PHASE1_RESULTS_DIR>` 실행 후 출력의 `RECOMMENDED` 순서대로 수행한다. 이 스크립트는 Step 5(스캐너 그룹)과 Step 6(AI 자율 탐색)의 재개 지점을 한 번에 판별한다. `phase1-group-agent`는 유효한 기존 결과 파일을 자동 스킵한다.

**`DUPLICATE SINK` 경고 발생 시 — AI 자율 탐색(Step 6) 진입 전에 즉시 통합 여부를 결정한다:**

1. 두 후보의 Phase 1 결과 파일을 Read하여 관점 차이를 확인한다.
2. **의사 테스트**: 한 후보의 권장 조치만 적용해도 다른 후보가 해소되면 통합한다. `master-list.json`을 Edit하여 한쪽 후보를 `candidates` 배열에서 제거하고, 남은 쪽의 `scanner` 필드에 양쪽 스캐너를 모두 기록한다.
3. 의사 테스트가 "아니오"이거나 불확실하면 분리 유지한다.

생성된 `<PHASE1_RESULTS_DIR>/master-list.json`은 AI 자율 탐색(Step 6), 동적 분석(Step 8-4), 연계 분석(Step 10), 리포팅(Step 12) 전체에서 **단일 진실 원천(single source of truth)**으로 사용한다. **마스터 목록에 있는 후보는 동적 분석에서 "안전"으로 판정되지 않는 한, 반드시 최종 보고서에 포함되어야 한다.**

### Step 6: AI 자율 분석

Phase 1 정적 분석 완료 후, 구조화된 스캐너가 놓칠 수 있는 취약점을 AI가 자율적으로 탐색한다. 에이전트가 내부적으로 3단계 탐색(자유 탐색 → Phase 1 공백 영역 집중 → 잔여 영역)을 수행하고 결과를 저장한다.

**실행 절차:**

Agent 도구로 AI 자율 탐색 에이전트를 생성한다. `<NOAH_SAST_DIR>`/`<PHASE1_RESULTS_DIR>` 변수를 resolve된 실제 경로 문자열로 치환한다.

```
<NOAH_SAST_DIR>/prompts/ai-discovery-agent.md를 Read 도구로 읽고 그 안의 지시를 정확히 따르세요.
변수: PHASE1_RESULTS_DIR=<PHASE1_RESULTS_DIR>
Phase 1 마스터 목록: <PHASE1_RESULTS_DIR>/master-list.json (Read 도구로 읽어 Phase 1이 발견한 후보의 파일·라인·취약점 유형을 파악하세요)
프로젝트 컨텍스트: <PROJECT_CONTEXT>

3단계 탐색을 내부적으로 수행하세요:
1. 이 프로젝트의 소스코드를 분석하여 보안 취약점을 탐색하세요.
[전환] 1단계 탐색 후, master-list.json을 다시 Read하여 Phase 1이 어떤 스캐너에서 후보를 찾았고 어떤 스캐너가 이상 없음인지 재확인한 뒤 2단계로 넘어가세요.
2. Phase 1 커버리지를 바탕으로, Phase 1이 다루지 않은 영역을 집중 탐색하세요. 특히 비즈니스 로직 결함, 인증·인가 흐름 전체 경로, Race Condition, Mass Assignment처럼 grep 패턴으로는 잡기 어려운 취약점에 집중하세요.
[전환] 2단계 탐색 후, 지금까지 Read 도구로 열어본 파일과 디렉토리를 점검하고, 아직 열어보지 않은 영역을 파악한 뒤 3단계로 넘어가세요.
3. 미탐색 영역을 중심으로 취약점을 탐색하세요.

탐색 완료 후 "후보 등록 제외 기준" 7개 항목을 적용하여 걸러내고, "결과 파일 형식"에 따라 <PHASE1_RESULTS_DIR>/ai-discovery.md에 저장하라. 저장 전 "자기 검증" 절차를 수행하라.
반환 요약에 통과 후보 건수와 필터링 제외 건수를 함께 표기하라 (예: `ai-discovery: 후보 3건 (필터링 제외 2건)`).
```

**결과 파일 저장 및 마스터 목록 갱신:**

에이전트가 `<PHASE1_RESULTS_DIR>/ai-discovery.md`에 결과를 저장하고 후보 건수 요약을 반환한다. 이 파일은 하류의 동적 분석(Step 8-4), 연계 분석(Step 10), 보고서(Step 12)에서 Phase 1 스캐너 결과 파일과 동일하게 참조된다.

**`[INCOMPLETE]` 후속 탐색**: 반환에 `[INCOMPLETE]`이 포함된 경우, 탐색이 컨텍스트 한계로 중단된 것이다. 메인 에이전트는 반환의 "미탐색 영역" 정보를 활용하여 후속 탐색 에이전트를 디스패치한다. 후속 에이전트 프롬프트에는:
- 동일한 `ai-discovery-agent.md` Read 지시
- 이전 에이전트가 저장한 `ai-discovery.md`를 Read하여 이미 발견된 후보와 탐색 범위를 파악하라는 지시
- 이전 에이전트의 마지막 AI-N 번호를 명시 (continued 에이전트의 번호 매김 근거)
- "미탐색 영역을 중심으로 자율 탐색하되, 이전 에이전트가 발견한 후보와 중복되지 않는 새로운 발견에 집중하라"는 안내

후속 에이전트의 결과는 `ai-discovery-continued.md`에 저장하고, 메인 에이전트가 두 파일의 후보를 `ai-discovery.md`로 통합한다 (ID가 이어서 부여되므로 충돌 없이 append). 후속 에이전트도 `[INCOMPLETE]`를 반환하면 저장된 후보만으로 진행한다 (무한 재시도 방지).

에이전트 응답을 확인한 후:

1. `<PHASE1_RESULTS_DIR>/ai-discovery.md`를 Read하여 manifest의 후보를 확인한다.
2. `phase1_build_master_list.py`를 재실행하여 AI 결과를 포함한 전체 마스터 목록을 재생성하고 구조 검증한다:

```bash
python3 <NOAH_SAST_DIR>/tools/phase1_build_master_list.py <PHASE1_RESULTS_DIR> <PHASE1_RESULTS_DIR>/master-list.json
```

`ai-discovery.md`가 `<PHASE1_RESULTS_DIR>/` 디렉토리에 있으므로 스크립트가 자동 수집한다. ERROR 발생 시 `ai-discovery.md`의 해당 부분을 수정하고 재실행한다.

**Phase 1과의 중복 제거를 수행하지 않는다.** AI 자율 탐색과 Phase 1 스캐너가 같은 취약점을 발견하면 이중 검증으로 간주한다. 보고서에서 AI 자율 탐색 결과는 별도 섹션(`## AI 자율 탐색 결과`)으로 분리되므로 중복이 혼란을 주지 않는다.

AI 자율 탐색에서 후보가 0건이어도 정상이다. 스캐너가 이미 충분히 커버한 경우이며, "AI 자율 탐색: 추가 후보 없음"으로 기록하고 다음 단계로 진행한다.

### Step 7: 정적 및 AI 자율 분석 결과 리뷰 (phase1-review)

AI 자율 탐색 완료 후, 동적 분석 정보 요청(Step 8-1) 진입 **전에** Phase 1 결과 품질 평가를 수행한다. 잘못된 후보가 Phase 2까지 흘러가는 낭비를 방지하기 위한 정적 정제 단계.

**호출 방식**: `scan-report-review`를 `mode=phase1-review`로 호출.

```
Agent 도구로 평가 에이전트를 생성한다. <NOAH_SAST_DIR>/<PHASE1_RESULTS_DIR>는 resolve된 실제 경로 문자열로 치환.

[MODE=phase1-review 전용 에이전트]

진입 즉시 아래 3개 파일을 순서대로 Read하세요. 그 외 파일(dispatcher SKILL.md, 다른 모드 파일)은 Read하지 마세요.

1. <NOAH_SAST_DIR>/sub-skills/scan-report-review/phase1-review.md (MODE GUARD 및 전체 절차)
2. <NOAH_SAST_DIR>/sub-skills/scan-report-review/_principles.md (공통 판정 원칙)
3. <NOAH_SAST_DIR>/sub-skills/scan-report-review/_contracts.md (공통 계약)

위 3개 파일의 지시를 정확히 따라 mode=phase1-review 절차를 수행하세요. 다른 모드(phase2-review, report-review)의 절차를 수행하면 안 됩니다.

변수: NOAH_SAST_DIR=<NOAH_SAST_DIR>, PHASE1_RESULTS_DIR=<PHASE1_RESULTS_DIR>
대상: master-list.json의 후보 — `phase1_validated != true` 또는 `phase1_eval_state.reopen == true`인 후보
출력:
  1. <PHASE1_RESULTS_DIR>/evaluation/<scanner-name>-eval.md (각 후보의 Override 판정)
  2. master-list.json의 phase1_validated / phase1_discarded_reason / phase1_eval_state / safe_category 필드 갱신

blind eval 메커니즘(phase1_review_blind_read.py 헬퍼)을 반드시 적용하세요.
```

**완료 후 검증**:
```bash
mkdir -p <PHASE1_RESULTS_DIR>/evaluation
python3 <NOAH_SAST_DIR>/tools/phase1_review_assert.py \
  <PHASE1_RESULTS_DIR>/master-list.json \
  <PHASE1_RESULTS_DIR>
```

**exit code 처리**:
- `0`: 모든 후보 평가 완료 → Step 8-1 진행
- `1`: 평가 미완료 또는 eval MD 고아 상태 → phase1-review 재호출
- `3`: 비차단 경고 (rederivation 편향 등) → 로그만 남기고 진행

**Phase 2 진입 시 사용할 Phase 1 결과 경로**: `<PHASE1_RESULTS_DIR>/evaluation/<scanner>-eval.md` (Phase 1 원본 MD가 아님). 이후 Step 8-4(Phase 2) 에이전트 프롬프트는 eval MD를 Phase 1 결과로 참조한다 (`sub-skills/scan-report-review/_contracts.md §6` C1 lint 강제).

### Step 8: 동적 분석

동적 분석 정보 요청(사용자 응답 대기) → 도구 권한 확인 → Phase 2 에이전트 실행 순으로 진행한다.

#### Step 8-1: 동적 분석 정보 일괄 요청 → 사용자 응답 대기

`<PHASE1_RESULTS_DIR>/master-list.json`을 읽어 후보 목록을 확인하고 (AI 자율 탐색의 AI-N 후보 포함), 동적 테스트에 필요한 정보를 한번에 정리하여 사용자에게 요청한 뒤 **응답을 대기한다. 보고서를 작성하지 않는다.**

요청 항목:
1. **테스트 환경 URL (sandbox 도메인)** — 보고서 개요 `**테스트 환경**` 필드와 모든 POC curl 호스트의 단일 진실 원천. Step 3에서 추출된 `SANDBOX_DOMAINS`가 있으면 기본값으로 제시.
2. **세션 쿠키/인증 토큰**
3. **후보별 추가 정보** — SSRF의 외부 콜백 URL, OAuth 인가 코드 등 직접 획득 불가 항목만 나열

사용자가 제공한 sandbox 도메인은 `SANDBOX_DOMAINS`에 추가하여 scan-report 서브에이전트로 전달한다. 동적 테스트 거부 시 `**테스트 환경**` 필드는 "해당 없음"으로 기재하고 POC curl 호스트는 `<TARGET_HOST>` 플레이스홀더를 유지한다.

#### Step 8-2: 도구 권한 사전 확인

**절차:**

1. `~/.claude/settings.json` 및 프로젝트 `.claude/settings.json`을 **Read 도구로** 읽어 `permissions.allow` 배열을 확인한다.
2. 필요 권한은 경로에 따라 다르다:
   - **동적 테스트 수행 경로**: 아래 4개 모두 필요
     - `Bash(curl:*)` — HTTP 요청 테스트 (모든 스캐너 동적 분석 필수)
     - `Bash(node:*)` — Playwright/Node.js 테스트 (XSS, ReDoS 등 클라이언트 측 테스트 필요 시)
     - `Bash(npx:*)` — npx playwright 실행 (Playwright 필요 시, `Bash(node:*)`로 대체 가능)
     - `Bash(python3:*)` — 검증 스크립트 실행 (보고서 생성·검증 시)
   - **동적 테스트 거부 경로**: **`Bash(python3:*)`만 확인**한다(보고서 생성에 필요). `curl`/`node`/`npx` 확인은 생략한다.
3. 해당 경로에서 필요한 권한이 누락되어 있으면 사용자에게 추가 여부를 묻고, 동의하면 직접 `settings.json`에 추가한다.

#### Step 8-3: 그룹 사전 단계 (Group Prerequisite — 조건부 실행)

**개념.** 일부 스캐너 그룹은 Phase 2 동적 검증 전에 그룹 단위 사전 단계를 통과해야 한다. 사전 단계는 그룹의 모든 스캐너 Phase 2가 공유하는 입력 산출물을 만든다. 사전 단계가 정의되지 않은 그룹은 본 단계를 건너뛰고 곧장 Step 8-4로 진행한다. 비-LLM 스캐너는 본 단계의 영향을 받지 않는다.

**현재 정의된 그룹 사전 단계:**

| 그룹 | 사전 단계 에이전트 | 산출물 (입력 contract) |
|------|---------------------|------------------------|
| `llm` | `prompts/llm-endpoint-probe-agent.md` | `<LLM_PROBE_DIR>/llm_endpoint.json` (+ `llm_endpoint_probe.jsonl` 디버그 로그) |

**LLM 그룹 사전 단계 실행 절차:**

LLM 그룹에 후보가 1건 이상 존재하는 경우(Phase 1 결과 기준) 다음을 수행한다.

1. probe 결과 디렉토리 생성:
   ```bash
   echo "/tmp/llm_probe_$(basename <PROJECT_ROOT>)_$(date +%s)"
   ```
   출력값을 `LLM_PROBE_DIR` 변수로 보관한다.

2. Agent 도구로 사전 단계 에이전트를 디스패치한다. 변수는 resolve된 실제 경로 문자열로 치환:

   ```
   <NOAH_SAST_DIR>/prompts/llm-endpoint-probe-agent.md를 Read 도구로 읽고 그 안의 절차를 정확히 따르세요.
   변수: NOAH_SAST_DIR=<NOAH_SAST_DIR>, PROJECT_ROOT=<PROJECT_ROOT>, PHASE1_RESULTS_DIR=<PHASE1_RESULTS_DIR>, LLM_PROBE_DIR=<LLM_PROBE_DIR>
   세션 정보: <SESSION_INFO>
   sandbox 도메인: <SANDBOX_DOMAIN>
   ```

3. 에이전트 반환 후 `<LLM_PROBE_DIR>/llm_endpoint.json`을 Read하여 `endpoints` 배열을 확인한다.

**성공/실패 처리:**

- `endpoints`가 1개 이상 확정되면 LLM 그룹의 Step 8-4(Phase 2) 진입. 4개 LLM 스캐너 Phase 2 에이전트 프롬프트에는 `LLM_PROBE_DIR` 변수와 `llm_endpoint.json` 경로를 함께 전달한다. 다중 endpoint면 각 endpoint에 대해 Phase 2를 반복한다.
- `endpoints`가 비어 있으면 LLM 그룹의 Phase 2를 skip한다. 메인 에이전트는 LLM 4개 스캐너의 Phase 1 후보 status를 `phase2-review`가 `endpoint_unverified`로 표기할 수 있도록, Phase 2 결과 파일 대신 placeholder 결과 파일을 생성한다:
  ```
  <PHASE1_RESULTS_DIR>/<llm-scanner>-phase2.md  ← evidence_summary에 "endpoint_unverified — chat endpoint not reachable"를 기록한 manifest만 포함
  ```
  비-LLM 스캐너의 Phase 2는 본 실패의 영향을 받지 않고 정상 진행한다.

**상한.** probe 에이전트의 내부 상한(라우트 ≤ 5, 변형 ≤ 8, 멀티턴 ≤ 3, 전체 호출 ≤ 30)은 `llm-endpoint-probe-agent.md`에 정의되어 있으므로 메인 에이전트가 별도 강제하지 않는다.

#### Step 8-4: 동적 분석 (개별 스캐너의 Phase 2 실행)

사용자가 필요한 정보를 제공하면, 후보가 발견된 모든 스캐너에 대해 동적 분석을 수행한다. 스캐너당 1 에이전트 원칙을 따른다. 메인 에이전트는 Phase 2 에이전트 프롬프트 본문을 인라인으로 복사하지 않고, 아래 형식의 짧은 프롬프트를 사용하되 변수를 resolve된 실제 경로 문자열로 치환한다.

```
<NOAH_SAST_DIR>/prompts/phase2-agent.md를 Read 도구로 읽고 그 안의 절차를 정확히 따르세요.
변수: NOAH_SAST_DIR=<NOAH_SAST_DIR>, PHASE1_RESULTS_DIR=<PHASE1_RESULTS_DIR>

스캐너: <scanner-name>
  - phase2.md: <NOAH_SAST_DIR>/scanners/<scanner-name>/phase2.md
  - Phase 1 결과: <PHASE1_RESULTS_DIR>/<scanner-name>.md
세션 정보: <SESSION_INFO>
sandbox 도메인: <SANDBOX_DOMAIN>
```

**LLM 그룹 스캐너의 추가 입력.** LLM 4개 스캐너(`prompt-injection-scanner`, `system-prompt-leakage-scanner`, `insecure-output-handling-scanner`, `unbounded-consumption-scanner`)는 Step 8-3 사전 단계 산출물을 추가 변수로 받는다. Phase 2 에이전트 프롬프트 끝에 다음 줄을 덧붙인다:

```
LLM endpoint: <LLM_PROBE_DIR>/llm_endpoint.json (Step 8-3 사전 단계 산출물 — chat endpoint의 base_url/route/headers/request_schema/response_path/multiturn_mode가 확정되어 있음. Phase 2 에이전트는 이 파일만 읽고 코드 재분석 없이 동적 테스트를 수행한다)
```

다중 endpoint가 확정된 경우 각 endpoint에 대해 Phase 2를 반복 실행한다(각 실행마다 endpoint index를 프롬프트에 명시). Step 8-3 사전 단계가 실패했거나 endpoint 미확보면 본 LLM 그룹 Phase 2는 디스패치하지 않고 `endpoint_unverified` 처리 절차(Step 8-3 참조)를 따른다.

**AI 자율 탐색 후보(AI-N)의 동적 분석:**
- AI 후보가 기존 스캐너 카테고리(XSS, SQLi 등)에 속하면, 해당 스캐너의 Phase 2 에이전트 프롬프트에 AI 후보 정보를 함께 전달한다.
- 기존 카테고리에 속하지 않는 AI 후보(예: Race Condition, Mass Assignment 등)는 `phase2-agent.md`의 "비카테고리 AI 후보 처리" 절차에 따라 별도 Phase 2 에이전트로 실행한다.

**동적 분석 실행 순서 — Tier 기반 병렬화:**

`select_scanners.py` 출력의 `--- Tier 요약 ---` 섹션을 참조한다. 각 스캐너가 속한 Tier(A/B/C)와 실행 규칙이 해당 출력에 명시된다. 메인 에이전트는 Tier 간 병렬, Tier 내 순차로 Phase 2 에이전트를 디스패치한다. 동일 세션을 사용하는 스캐너끼리의 병렬 실행은 금지한다.

Step 4-2 AI 검토로 복원된 스캐너는 `select_scanners.py` 출력에 포함되지 않으므로, 메인 에이전트는 `<NOAH_SAST_DIR>/tools/select_scanners.py`의 `TIER_A`·`TIER_C` 상수를 확인하여 직접 분류한다 (양쪽 모두 해당하지 않으면 Tier B).

사용자가 동적 테스트를 명시적으로 거부한 경우("동적 테스트 안 해도 돼", "소스코드 분석만 해줘" 등)에만 동적 분석을 건너뛰고 Step 10(연계 분석)으로 진행한다. 이 경로에서 마스터 목록의 미판정 후보는 메인 에이전트가 `status=candidate`, `tag="동적 분석 생략"`으로 직접 설정하고 `evidence_summary`에 거부 사유를 기록한다 (`_contracts.md §5` 참조). 이 태그는 이 경로 전용이며 phase2-review가 설정하지 못한다.

### Step 9: 동적 분석 결과 리뷰 (phase2-review)

모든 동적 분석 에이전트가 완료되면, `scan-report-review mode=phase2-review`를 호출하여 Phase 2 결과 파일의 evidence를 해석하고 master-list.json의 status를 갱신한다.

```
Agent 도구로 phase2-review 에이전트를 생성한다. <NOAH_SAST_DIR>/<PHASE1_RESULTS_DIR>는 resolve된 실제 경로 문자열로 치환.

[MODE=phase2-review 전용 에이전트]

진입 즉시 아래 3개 파일을 순서대로 Read하세요. 그 외 파일(dispatcher SKILL.md, 다른 모드 파일)은 Read하지 마세요. 프로젝트 소스코드의 일반 탐색은 금지이며, `verified_defense` 기록용 방어 코드 Read 확인 시에만 허용됩니다.

1. <NOAH_SAST_DIR>/sub-skills/scan-report-review/phase2-review.md (MODE GUARD 및 전체 절차)
2. <NOAH_SAST_DIR>/sub-skills/scan-report-review/_principles.md (공통 판정 원칙)
3. <NOAH_SAST_DIR>/sub-skills/scan-report-review/_contracts.md (공통 계약: 판정×태그 매트릭스, 스키마)

위 3개 파일의 지시를 정확히 따라 mode=phase2-review 절차를 수행하세요. 다른 모드(phase1-review, report-review)의 절차를 수행하면 안 됩니다. 특히 report-review 모드의 "MD 본문 수정" 절차로 빠져 보고서 파일을 수정하면 안 됩니다 (phase2-review는 master-list.json만 갱신).

변수: NOAH_SAST_DIR=<NOAH_SAST_DIR>, PHASE1_RESULTS_DIR=<PHASE1_RESULTS_DIR>
대상: master-list.json의 후보 — Idempotent 동작(phase2-review.md §Idempotent 동작)에 따라 이미 status가 할당된 후보는 skip, 미판정 후보만 처리 (reopen=true는 예외)
출력: master-list.json의 status/tag/evidence_summary/verified_defense/rederivation_performed/source_phase2_file/source_phase2_hash 필드 갱신
```

**[필수] `mode=phase2-review`가 유일한 Phase 2 status writer이다.** 에이전트 반환 텍스트의 테이블은 체크리스트 출력용이며, 상태의 진실 원천은 master-list.json이다. 연계 분석 에이전트가 master-list.json에서 최종 상태를 직접 읽으므로, 이 갱신이 Step 10 진입 전에 완료되어야 한다.

**[필수] 메인 에이전트는 master-list.json의 status / tag / evidence_summary / verified_defense / rederivation_performed 필드를 직접 편집하지 않는다.** 드리프트나 실패가 의심되면 수동 판정이 아니라 아래 재시도 절차로 대응한다.

**phase2_review_assert.py로 Step 10 진입 가드 실행**:

```bash
python3 <NOAH_SAST_DIR>/tools/phase2_review_assert.py \
  <PHASE1_RESULTS_DIR>/master-list.json <PHASE1_RESULTS_DIR>
```

Exit code별 조치 (`sub-skills/scan-report-review/_contracts.md §2` Exit Code 통일 테이블):
- `0`: Step 10 진행
- `1`: status 미완결. **phase2-review 재시도 절차** 수행 (아래 참조)
- `3`: 비차단 경고 (rederivation 편향). 로그만 남기고 진행
- `4`: `phase1_eval_state.reopen=true` 후보 존재 — **품질 개선 힌트**. phase1-review 재호출은 선택적이며, Phase 2 우선 원칙에 따라 status는 이미 phase2-review가 확정했으므로 파이프라인은 차단하지 않고 다음 단계로 진행 가능

**phase2-review 재시도 절차 (exit 1)**: `mode=phase2-review` 최대 2회 재호출(idempotent — 미판정 후보만 처리). 2회 실패 시 남은 후보 ID와 실패 원인(토큰 한도·드리프트 등)을 보고하고 사용자 재개 요청까지 대기한다. 메인 에이전트가 status를 직접 할당하지 않는다.

**reopen 선택적 재호출 (exit 4)**: 파이프라인 차단 아님. 품질 개선을 원하면 `phase1-review` 재호출 (reopen=true 후보만 자동 재평가). 완료 후 스크립트가 `reopen=false` 리셋 + `retries` 증분한다.

**[필수] 재호출 중 master-list.json의 status 필드는 건드리지 않는다.** phase2-review만 status writer이며, 재호출된 phase1-review는 phase1_* 필드만 갱신한다.

**동적 테스트로 확인됨 증거가 새로 확보된 경우 섹션 갱신 절차**:

메인 에이전트는 **기존 sr_*.md 파일을 수동 sed/편집으로 고치지 않는다**. 대신:

1. `SANDBOX_DOMAINS` 확정(필요 시 사용자 확인)
2. 해당 후보가 속한 스캐너의 **scan-report Step 4 서브에이전트를 재호출**. 프롬프트에 `SANDBOX_DOMAINS`와 확인됨 증거(HTTP 응답, 관찰된 페이로드 등)를 전달
3. 서브에이전트가 확인됨 상태 + 실제 관찰 결과 + sandbox 도메인을 포함한 섹션을 새로 작성하여 반환
4. `assemble_report.py`로 보고서 재조립

### Step 10: 연계 분석

동적 분석 완료 후, "안전" 판정을 제외하고 후보가 2건 이상 남아 있는 경우 `<NOAH_SAST_DIR>/sub-skills/chain-analysis/SKILL.md`에 정의된 프로세스에 따라 **연계 분석 에이전트**를 실행한다. 2건 미만이면 이 단계를 건너뛴다.

에이전트 프롬프트에는 chain-analysis SKILL.md 경로, 후보 마스터 목록(`<PHASE1_RESULTS_DIR>/master-list.json` — 각 후보의 동적 분석 최종 상태 포함), Phase 1 결과 디렉토리(`<PHASE1_RESULTS_DIR>`), 프로젝트 컨텍스트, 이상 없음 요약을 포함한다.

**연계 분석 결과 활용:**
- 에이전트가 `<PHASE1_RESULTS_DIR>/chain-analysis.md` 파일에 결과를 저장하고, 반환 메시지에는 저장 완료 요약 + 체인/독립 후보 건수만 포함한다.
- **Step 12 (보고서)**: 메인 에이전트가 `<PHASE1_RESULTS_DIR>/chain-analysis.md`를 Read하여 파일 끝의 `<!-- NOAH-SAST CHAIN MANIFEST v1 -->` JSON 블록을 파싱한다. 파싱한 JSON 객체를 별도 파일(예: `/tmp/chain.json`)로 저장하고, `assemble_report.py`의 `--chain` 인자로 전달한다.

### Step 11: 결과 검증

동적 분석 및 연계 분석 완료 후, Step 12(보고서 작성)로 넘어가기 **전에** 다음을 검증한다.

**"후보" 상태는 소극적 선택지가 아니다.** 동적 테스트를 시도했으나 기술적으로 확인이 불가능한 경우에만 부여한다. 테스트를 시도하지 않은 채 "추가 검증 필요"로 남기는 것은 허용하지 않는다. 후보로 분류하려면 왜 동적 테스트가 불가능했는지 구체적인 사유(`[도구 한계]`/`[정보 부족]`/`[환경 제한]`)가 있어야 한다.

아래 형식의 체크리스트를 반드시 출력한다. 자율적 판단으로 대체하지 않는다.

**체크리스트는 후보 마스터 목록의 모든 항목을 포함해야 한다.** 테이블에서 항목을 생략하는 것은 허용하지 않는다. 테이블 행 수 = 후보 마스터 목록 항목 수여야 한다.

테이블 형식 (모든 후보 마스터 목록 항목 포함):
```
## 동적 분석 결과 체크리스트

| ID | 후보 제목 | 테스트 수행 | 결과 | 미수행 사유 |
|----|----------|------------|------|------------|
| [스캐너ID] | [후보 제목] | ✓ 또는 ✗ | [결과 또는 —] | [사유 또는 —] |
...
```

- 테스트 수행 ✓: 동적 테스트를 실제 실행한 경우. 미수행 사유 칸은 `—`.
- 테스트 수행 ✗: 테스트를 실행하지 못한 경우. 반드시 `[도구 한계]`/`[정보 부족]`/`[환경 제한]` 중 하나를 사유로 명시. Playwright 등 필요한 도구는 실행을 시도하지 않고 미설치로 추정하여 `[도구 한계]`로 표시하는 것은 허용하지 않는다. 실행을 시도했으나 실제로 실패(command not found 등)한 경우에만 허용한다.

**결과 컬럼 작성 기준:**
- **확인됨**: `확인됨 — [트리거 증거]` (예: `확인됨 — XSS alert 발화 확인`)
- **안전**: `안전 — [방어 계층 + 확인 방법]` (예: `안전 — 게이트웨이 라우팅 차단 확인 (nginx.conf:42)`) — `guidelines-phase2.md` 지침 7 "차단 응답 처리" 절차에 따라 의도적 방어가 입증된 경우에만 부여
- **후보 (차단)**: `후보 — [차단 계층]이 [응답] 반환, 방어 입증 불가` (예: `후보 — 백엔드 400 반환, 의도적 depth 제한 로직 확인 불가`)
- **후보 (환경)**: `후보 — [환경 한계 사유]` (예: `후보 — 내부 서비스 정상 운영으로 에러 조건 미충족`)

체크리스트의 미수행(✗) 항목은 사유 태그에 따라 아래 조치를 즉시 수행한다. "인지했다"에서 멈추지 않는다.

| 사유 태그 | 메인 에이전트 조치 |
|-----------|-----------------|
| `[도구 한계]` | 메인 에이전트가 직접 해당 테스트를 실행한다. 도구 설치 여부 확인 없이 바로 실행하며, 실행이 실패하면 그때 `[환경 제한]`으로 재분류한다. |
| `[정보 부족]` | 사용자에게 추가 정보 요청. 획득 불가 시 "후보"로 보고서에 포함. |
| `[환경 제한]` | "후보"로 보고서에 포함 (제한 사유 명시). |

> **`[환경 제한]` 유효 범위**: 테스터가 직접 해결할 수 없는 외부 제약에만 사용한다 (예: 관리자 권한 없음, OTP 필요, 프로덕션 전용 인프라). 테스트 데이터(댓글, 게시글, 파일 등)가 없어서 테스트가 불가능한 경우는 해당하지 않는다 — 데이터를 직접 생성한 뒤 테스트를 진행해야 한다.

체크리스트에 ✗ 항목이 없을 때(모두 ✓)에 한해 아래 최종 점검 후 Step 12로 진행한다:

0. **✓ 항목의 실행 여부를 검증한다.** 동적 테스트 수행 주체(개별 취약점 스캐너 에이전트 또는 메인 에이전트)의 반환/실행 결과에 각 항목의 **동적 테스트 실행 결과** 파트가 존재하는지 확인한다. 해당 파트가 없거나 비어 있으면 ✓가 아니라 ✗(`[도구 한계]`)로 재분류하고 메인 에이전트가 직접 재테스트한다.

1. **후보 마스터 목록의 모든 항목에 최종 상태가 부여되었는가?** Phase 2 에이전트 반환 테이블의 "결과" 열에서 상태를 판정한다: "확인됨"이 명시되면 confirmed, "안전"/"방어 확인"이면 safe, 그 외(테스트 미수행, 불확실)는 candidate.
   - "확인됨": 동적 테스트에서 실제 트리거 확인. **[필수] 동적 테스트 수행 주체의 결과에 해당 항목의 "동적 테스트 실행 결과" 파트(실제 실행한 명령 + 응답/출력)가 존재하는 경우에만 "확인됨"으로 인정한다. "확인됨"이라고 기술했더라도 실행 결과 파트가 없으면 메인 에이전트가 직접 동적 테스트를 수행한다. 직접 테스트 후에도 트리거를 확인할 수 없으면 "후보"로 재분류한다.** 또한, 확인됨 판정은 취약점 단위로 개별 적용한다. 동일 취약점 클래스라도 코드 경로가 다른 항목은 별도의 동적 테스트 증거가 있어야 한다. 한 경로의 확인 결과를 다른 경로에 전파하지 않는다.
   - "후보": 동적 테스트 미수행, 결과 불확실, 또는 차단되었으나 방어 의도 입증 불가
   - "안전": 동적 테스트에서 의도적 방어가 입증됨 (`guidelines-phase2.md` 지침 7 "차단 응답 처리" 절차 준수)
2. **"안전"으로 판정되지 않은 모든 항목이 보고서에 포함될 준비가 되었는가?**
3. **Phase 1 및 AI 자율 탐색에서 발견된 후보 중 누락된 것이 없는가?** — Phase 1 결과와 AI 자율 탐색 결과를 다시 대조한다.
4. **모든 후보에 실제 URL 경로가 확정되어 있는가?** — 경로가 누락된 항목이 있으면 메인 에이전트가 직접 호출부를 추적한다(Sink 함수명으로 Grep → import하는 컴포넌트 식별 → 라우트 정의를 Read로 읽어 경로 확정). 모든 후보의 경로가 확정된 후에만 Step 12로 진행한다.

### Step 12: 보고서 생성

> **전제 조건**: Step 11(결과 체크리스트)이 완료되었거나, 사용자가 동적 테스트를 명시적으로 거부한 경우에만 이 단계를 수행한다. 정적 분석만 완료된 상태에서 이 단계로 넘어가지 않는다.

Step 5~10에서 수집한 모든 결과를 **`scan-report` 스킬(`<NOAH_SAST_DIR>/sub-skills/scan-report/SKILL.md`)에 전달**하여 통합 보고서를 생성한다. **작업 디렉토리에 여러 프로젝트가 존재하더라도 보고서는 반드시 1개(`noah-sast-report.md` + `.html`)만 생성한다. 프로젝트별로 보고서를 분리하지 않는다.**

**sandbox 도메인 자동 적용 (보고서 POC URL용):**

Step 3에서 추출한 `SANDBOX_DOMAINS`가 있으면, 보고서 서브에이전트에 도메인 매핑을 전달하여 POC curl 명령어에 실제 sandbox 도메인을 사용한다. `SANDBOX_DOMAINS`가 비어 있거나 추출 불가한 서비스는 `<TARGET_HOST>` 등 플레이스홀더를 유지한다.

**전달하는 데이터:**
- 후보 마스터 목록: `<PHASE1_RESULTS_DIR>/master-list.json` (각 후보의 최종 상태: 확인됨/후보/안전)
- 스캐너별 Phase 1 소스코드 분석 결과: `<PHASE1_RESULTS_DIR>/<scanner-name>.md` 파일들
- AI 자율 탐색 결과: `<PHASE1_RESULTS_DIR>/ai-discovery.md` (후보 0건이면 생략 가능)
- 스캐너별 동적 분석 결과: 각 Phase 2 에이전트의 반환 텍스트(재현 방법 및 POC + 동적 테스트 실행 결과 파트)를 scan-report Step 4 서브에이전트 프롬프트에 해당 스캐너 데이터로 포함한다
- 연계 분석 결과 (전제조건 매트릭스, 연계 매트릭스, 공격 체인 또는 "체인 없음" 판정 사유, 독립 후보 정리, 위험도 재평가)
- **SANDBOX_DOMAINS**: 확인된 sandbox 도메인 매핑 (확인받은 경우)
- 이상 없음 스캐너의 점검 항목 요약
- 미적용 스캐너 목록 및 제외 사유

scan-report SKILL.md를 읽고, 그 스킬이 정의하는 보고서 작성 프로세스를 수행한다. **noah-sast는 보고서를 직접 작성하지 않는다.**

#### Step 12-1: report-review (MD 본문 품질 개선, 조건부)

master-list.json의 `status ∈ {confirmed, candidate}` 후보가 1건 이상일 때만 실행. 0건이면 스킵. 에이전트 프롬프트:

   ```
   [MODE=report-review 전용 에이전트]

   진입 즉시 아래 3개 파일을 순서대로 Read하세요. 그 외 파일(dispatcher SKILL.md, 다른 모드 파일)은 Read하지 마세요.

   1. <NOAH_SAST_DIR>/sub-skills/scan-report-review/report-review.md
   2. <NOAH_SAST_DIR>/sub-skills/scan-report-review/_principles.md
   3. <NOAH_SAST_DIR>/sub-skills/scan-report-review/_contracts.md

   위 3개 파일의 지시를 정확히 따라 mode=report-review 절차를 수행하세요. 다른 모드의 절차는 금지. 보고서 MD 본문만 수정하고 master-list.json·eval MD·Phase 2 manifest는 쓰지 마세요. `**상태**:` 필드 전환 금지.

   변수: NOAH_SAST_DIR=<NOAH_SAST_DIR>, PHASE1_RESULTS_DIR=<PHASE1_RESULTS_DIR>
   보고서 MD: <REPORT_MD_PATH>
   프로젝트 루트: <PROJECT_ROOT>
   ```

#### Step 12-2: 검증·변환·열기

`python3 <NOAH_SAST_DIR>/tools/report_finalize.py <NOAH_SAST_DIR> <PHASE1_RESULTS_DIR> <확인됨+후보 건수>` — `noah-sast-report.md`가 있는 디렉토리(=`assemble_report.py` 출력 위치)에서 실행한다. 내부 순서 html → validate → lint → links → open (validate가 MD·HTML 동기화를 검증하므로 html을 선행). 실패 대응: lint(exit 5)는 review 위반이면 report-review 재호출 1회 허용, links FAIL은 `missing_ids` MD 섹션을 `#### N. 제목`으로 변환 후 HTML 재생성.

## 유의사항 (메인 에이전트)

**실행 원칙**
- **[필수] 모든 동적 테스트는 `prompts/guidelines-phase2.md` 지침 11을 통과한 sandbox 도메인에서만 수행한다.** prod/cbt는 절대 금지, 분류 불명/staging은 명시적 확인 후에만 진행.
- Phase 1에서 후보가 발견되면 반드시 사용자에게 동적 테스트 진행 여부를 물어본다. 명시적 거부 시에만 건너뛴다.
- 각 스캐너의 분석 방법론은 해당 스캐너의 phase1.md(정적 분석 규칙) / phase2.md(동적 검증 cheat sheet)를 따른다. noah-sast는 중복 정의하지 않는다.
- 사용자에게 진행 상황을 주기적으로 알린다. 미적용 스캐너는 "해당 없음" 사유와 함께 미적용 목록에 기재한다.

**에이전트 프롬프트 규칙**
- Phase별 공통 지침(`prompts/guidelines-phase1.md` / `guidelines-phase2.md`)과 Phase별 에이전트 프롬프트(`phase1-group-agent.md` / `phase2-agent.md`) 경로를 프롬프트에 포함하여 에이전트가 Read로 읽도록 한다. 내용을 인라인으로 복사하지 않는다.
- 동적 분석 에이전트 프롬프트에는 `<PHASE1_RESULTS_DIR>/evaluation/<scanner>-eval.md` 경로를 포함한다. 메인 에이전트가 후보를 프롬프트에 재작성하지 않는다.
- 개별 에이전트 프롬프트에 "심각도 판단 포함하라" 지시를 추가하지 않는다 (상태는 확인됨/후보/안전 3종).

**Step 11 체크리스트 후 미수행 항목 보완**
- `[도구 한계]`: 메인 에이전트가 직접 해당 테스트 실행. 설치 확인 없이 바로 실행하며, 실패 시 `[환경 제한]`으로 재분류.
- `[정보 부족]`: 사용자에게 추가 정보 요청하거나 "후보"로 포함.
- `[환경 제한]`: "후보"로 보고서에 포함.
- "도구 권한 거부"나 사유 없는 미수행이 최종 상태로 남아있으면 안 된다.