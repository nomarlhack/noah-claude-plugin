# Phase 1 실행 흐름

Phase 1은 소스코드를 읽어 취약점 **후보**를 만드는 단계다. 동적 테스트 없이 정적 분석만으로 진행하며, 결과는 `master-list.json`으로 집약된다.

---

## 전체 흐름

```
semgrep 인덱싱
    │
    ▼
그룹 에이전트 (병렬, 스캐너당 결과 MD 작성)
    │
    ▼
phase1_build_master_list.py  ◄── 구조 검증 + 후보 집약
    │
    ▼
AI 자율 탐색 에이전트 (1개, 정적 분석 보완)
    │
    ▼
phase1_build_master_list.py  ◄── 재실행 (AI 결과 포함)
    │
    ▼
phase1-review 에이전트 (판정 품질 감사)
    │
    ▼
phase1_review_assert.py  ◄── 게이트 3종 검증
    │
    ▼
master-list.json (phase1_validated: true)
```

---

## Step별 상세

### 1. semgrep 인덱싱

`semgrep_index.py`가 모든 스캐너의 룰을 소스코드에 일괄 실행한다.

**입력**: `scanners/*/rules/` 디렉토리의 YAML 룰 파일  
**출력**: `<PATTERN_INDEX_DIR>/<scanner>.json` + `<scanner>.locindex.json`

locindex는 같은 `file:line`에 여러 룰이 매치된 경우 1개 위치로 병합하고, tier(taint > ast > generic)를 승격한다.

```
rule_id → tier 결정
  noah-java-xss-taint         → taint
  noah-xss-phase1-pattern     → ast
  noah-xss-sink-pattern       → ast   (-sink 접미사: 고정밀 capability 룰)
  noah-xss-phase1-generic     → generic

같은 file:line에 taint + ast 매치 → taint tier로 승격, rule_ids 배열에 둘 다 보존
```

---

### 2. 그룹 에이전트 (Phase 1 분석)

`select_scanners.py`가 편성한 그룹당 1개 에이전트를 단일 메시지로 병렬 디스패치한다.

각 에이전트의 작업:

```
① locindex_summary.py 실행
     → 노이즈(vendor/, .min.js, .yaml 등) 제거
     → 파일당 1줄 요약 (taint/ast/generic 건수)

② phase1.md 읽기
     → 스캐너별 Sink 의미론, Source 패턴, 판정 기준 숙지

③ taint 매치부터 순서대로 소스 파일 Read
     → Source → Sink 흐름 추적
     → 후보 / FALSE_POSITIVE / NO_PATH 판정

④ 결과 MD 작성
     → 후보가 있으면 ## ID: 섹션 + MANIFEST 블록
     → 이상 없음이면 MANIFEST declared_count: 0
```

**결과 파일**: `<PHASE1_RESULTS_DIR>/<scanner>.md`

---

### 3. phase1_build_master_list.py (1차 실행)

모든 그룹 에이전트 완료 후 실행한다.

검증 항목:
- MANIFEST `declared_count` == 실제 `## ID:` 헤더 수
- 필수 섹션 존재 및 최소 길이
- 동일 file:line 후보 중복 감지 (DUPLICATE SINK 경고)

**출력**: `master-list.json` (후보 목록 초안)

---

### 4. AI 자율 탐색 에이전트

정적 패턴으로 잡히지 않는 취약점을 보완한다. 3단계 탐색을 내부적으로 수행한다.

```
1단계: 자유 탐색 (인증 흐름, 비즈니스 로직, Race Condition 등)
    ↓
2단계: Phase 1 공백 영역 집중
       master-list.json을 다시 읽어 이상 없음 스캐너가 다루지 않은 영역 탐색
    ↓
3단계: 미탐색 파일/디렉토리 집중
```

**결과 파일**: `ai-discovery.md`  
후보가 없어도 정상 (Phase 1 스캐너가 충분히 커버한 경우)

---

### 5. phase1_build_master_list.py (2차 실행)

`ai-discovery.md`를 포함하여 전체 후보를 재집약한다. 이후 `master-list.json`이 Phase 2 ~ 보고서까지의 **단일 진실 원천**이 된다.

---

### 6. phase1-review 에이전트

에이전트가 만든 결과 MD의 판정 품질을 독립적으로 감사한다.

```
blind eval 메커니즘:
  phase1_review_blind_read.py 헬퍼가 각 후보의 소스 파일 해시를 기록
  → 리뷰 에이전트가 소스를 새로 Read하여 독립 판정
  → Phase 1 에이전트의 판정과 비교 → CONFIRM / OVERRIDE / DISCARD

출력:
  evaluation/<scanner>-eval.md  ← Phase 2 이후 참조본 (원본 MD 대체)
  master-list.json 업데이트:
    phase1_validated: true/false
    phase1_discarded_reason
    safe_category
```

---

### 7. phase1_review_assert.py (게이트)

phase1-review 완료 후 Step 8 진입 전에 실행한다. **3종 게이트**를 검사하며 하나라도 FAIL이면 Step 8로 진행할 수 없다.

---

## 결과 MD 파일이란

게이트가 검사하는 "MD"는 **Phase 1 그룹 에이전트가 스캐너별로 작성하는 분석 결과 파일**이다.

```
<PHASE1_RESULTS_DIR>/
  ssrf-scanner.md           ← ssrf-scanner 분석 결과
  xss-scanner.md            ← xss-scanner 분석 결과
  idor-scanner.md
  cookie-security-scanner.md
  ...
```

각 파일 안에는 후보 섹션, 게이트 주석, MANIFEST 블록이 들어있다:

```markdown
# ssrf-scanner Phase 1 분석 결과

이상 없음 — 분석 범위 내 SSRF 후보 없음.

<!-- COVERAGE matches=1264 accounted=1264 method="..." -->
<!-- FILE_PRESENCE files=248 accounted=248 method="..." -->

## 파일 단위 Disposition

| 파일명 | 분류 | 근거 |
|--------|------|------|
| kakao_link_checker.ts | FALSE_POSITIVE | 사용자 입력→sink 도달 경로 없음 |
| FormDialog.tsx        | FALSE_POSITIVE | React 클라이언트 fetch, 서버 발신 아님 |

<!-- NOAH-SAST MANIFEST v1 -->
```json
{ "declared_count": 0, "candidates": [] }
```
<!-- /NOAH-SAST MANIFEST -->
```

`phase1_review_assert.py`는 이 파일들을 읽어서 각 게이트 주석의 숫자를 locindex 실제값과 비교한다. phase1-review 이후 `evaluation/<scanner>-eval.md`(리뷰 평가본)가 생성되며, Phase 2와 보고서는 원본 MD 대신 이 eval MD를 참조한다.

---

## 게이트 3종

### 왜 3종으로 나뉘는가

에이전트는 매치가 많을수록 분석 비용이 올라간다. 그래서 자연스럽게 이런 방식으로 생략하려 한다:

```
방법 1: 숫자 자체를 줄여 말한다
  "매치가 1264건인데 349건만 설명하고 나머지는 언급 안 함"

방법 2: 위험한 매치를 그룹으로 묶어 넘어간다
  "exec() 17건 → 전부 RegExp.exec() 오매치야" (파일을 읽지 않고)

방법 3: 파일 수를 줄여 말한다
  "React 클라이언트 컴포넌트 클래스 → 일괄 제외" (실제 파일 수는 248개인데 100개만 처리했다고 선언)
```

세 게이트는 이 세 가지 생략 방법을 각각 막는다.

| 게이트 | 막는 것 | 게이트가 묻는 것 |
|--------|---------|----------------|
| COVERAGE | 매치 수를 줄여 말하는 것 | 네가 설명한 매치 수가 실제 총매치 수와 맞나? |
| OBLIGATION | 위험한 매치를 그룹으로 뭉개는 것 | 고정밀 매치를 1건씩 다 처리했나? |
| FILE-PRESENCE | 파일 수를 줄여 말하는 것 | 네가 처리했다는 파일 수가 실제 파일 수와 맞나? |

세 게이트 모두 동일한 구조다: **에이전트가 선언한 숫자 == locindex 실제 숫자**를 검증한다. 판단의 정확성은 검증하지 않는다 — "침묵 속에 건너뛰지 않았는가"를 보장하는 것이 목적이다.

| 게이트 | 주석 키워드 | 숫자 필드 | 스크립트가 검증하는 것 |
|--------|------------|----------|----------------------|
| COVERAGE | COVERAGE | matches, accounted | 에이전트가 설명한 매치 수 == locindex 실제 총매치 수 |
| OBLIGATION | OBLIGATION | capability_matches, dispositioned | 에이전트가 처리한 capability 매치 수 == 실제 수 |
| FILE-PRESENCE | FILE_PRESENCE | files, accounted | 에이전트가 처리했다는 파일 수 == locindex 실제 distinct 파일 수 |

---

### COVERAGE

**적용 조건**: 총 매치 200건 초과 스캐너 (고볼륨)

에이전트가 전체 매치를 설명했는지 검사한다.

**결과 MD에 작성할 주석**:
```
<!-- COVERAGE matches=1264 accounted=1264 method="taint 12건: 개별 확인 전부 FALSE_POSITIVE,
     ast 1100건: React fetch 클라이언트 클래스 (서버 발신 아님),
     generic 152건: 문서·설정 클래스" -->
```

| 필드 | 의미 |
|------|------|
| `matches` | locindex 실제 총 매치 수 — 스크립트가 직접 계산하므로 에이전트가 줄여 써도 실제 수로 비교 |
| `accounted` | 에이전트가 설명한 매치 수 — 클래스 일괄 제외도 설명으로 인정 |
| `method` | 어떻게 커버했는지 한 줄 요약 |

**FAIL 조건**: `accounted < 실제 총매치` (그리고 `[INCOMPLETE]` 표기도 없음)

taint 매치가 50건 초과이면 경고를 추가로 표시한다. taint는 dataflow로 확정된 고신뢰 매치이므로 클래스 뭉개기보다 전수 나열을 권고한다.

---

### OBLIGATION

**적용 조건**: `exclusion_policy: capability`가 선언된 스캐너 (현재 6개: xss, dom-xss, command-injection, code-injection, ssti, deserialization)

capability 스캐너의 고정밀 매치는 클래스 일괄 제외 불가 — 1건씩 개별 disposition 의무.

**capability란**: 스캐너 `phase1.md` frontmatter에 `exclusion_policy: capability`가 있으면 "이 스캐너의 고정밀 매치 = 취약점 성립 요건이 코드에 존재한다는 증거"라는 뜻이다. `dangerouslySetInnerHTML`, `exec()`, `eval()` 같은 패턴이 매치됐다면 취약점이 존재할 수 있는 능력 자체가 코드에 있는 것이다. 이런 매치를 "어차피 대부분 false positive" 클래스로 뭉개면 진짜 취약점이 묻힌다.

**두 가지 집계 모드**:

| 모드 | 조건 | 집계 대상 |
|------|------|----------|
| 기본 | `capability_via_sink_rule` 없음 | ast-tier 전체 |
| sink-rule | `capability_via_sink_rule: true` | `-sink` 접미사 고정밀 룰 매치만 |

xss-scanner처럼 ast 매치가 수백 건인 broad-pattern 스캐너는 `capability_via_sink_rule: true`를 설정해 `-sink` 룰 매치만 집계한다. 노이즈가 많은 ast 전체가 아니라 진짜 위험한 매치에만 강제를 건다.

**결과 MD에 작성할 주석**:
```
<!-- OBLIGATION ast_matches=17 dispositioned=17
     method="exec 계열 17건: system_checks.rb 9건=정적 인자 확인,
     network_checks.rb 5건=로컬 CLI 도구(T4), config_generator.rb 1건=array popen 안전,
     noise 2건=locindex 자동 제거" -->
```

| 필드 | 의미 |
|------|------|
| `ast_matches` | locindex 기준 실제 능력형 매치 수 — 스크립트가 직접 계산하므로 과소신고 우회 불가 |
| `dispositioned` | 에이전트가 1건씩 처리한 수 |

**FAIL 조건**:
- 주석 자체가 없음 (capability 매치가 있는데 OBLIGATION 마커 부재)
- `ast_matches < 실제 능력형 수` (과소신고)
- `dispositioned < ast_matches` 그리고 `[INCOMPLETE]` 없음 (처리 안 된 매치 존재)

OBLIGATION이 없는 스캐너(ssrf, sqli, open-redirect 등)는 클래스 단위 제외를 허용한다.

---

### FILE-PRESENCE

**적용 조건**: `DECISION_DEFENSE_SCANNERS` 집합에 속한 스캐너

ssrf, open-redirect, path-traversal, ssti, idor, business-logic, validation-logic, host-header, csrf, file-upload, xxe, command-injection, code-injection, deserialization, xpath-injection, ldap-injection, prototype-pollution, pdf-generation (18개)

이 스캐너들은 방어 코드나 판단 로직을 분석하는 스캐너다. 취약점이 taint 흐름으로 표현되지 않는 경우가 많고, "방어 결정 자체가 틀린" 결함(fail-open, TOCTOU, 누락 케이스)이 ast/generic 매치 안에 숨어 있다.

**결과 MD에 작성할 주석**:
```
<!-- FILE_PRESENCE files=248 accounted=248
     method="서버 결정 코드 23개 개별 Read, React 클라이언트 .tsx 51개 1줄 무관,
     문서 .mdx 55개 1줄 무관, SAST 도구 .py 8개 1줄 무관" -->
```

| 필드 | 의미 |
|------|------|
| `files` | locindex distinct 파일 수 — 스크립트가 직접 계산 |
| `accounted` | 에이전트가 처리했다고 선언한 파일 수 |

**FAIL 조건**: 주석 없음, 또는 `accounted < files` 그리고 `[INCOMPLETE]` 없음

**검증 범위와 한계**:

게이트가 검증하는 것은 **숫자**다. 파일명을 실제로 MD에 적었는지는 검사하지 않는다. 에이전트가 파일명 나열 없이 `accounted=248`만 선언해도 숫자가 맞으면 통과한다.

이전 구현(basename 텍스트 검색)에서 현재 구현(숫자 비교)으로 바뀐 이유: 파일명이 MD에 있는지만 보는 것은 "게이트가 막으려는 문제와 같은 모양(있으면 PASS)"이었다. COVERAGE, OBLIGATION과 동일하게 숫자 기반으로 통일했다.

따라서 `kakao_link_checker.ts`를 처리했다고 `accounted`에 포함시키고 오판정해도 게이트는 PASS한다. 게이트는 "침묵을 막는 것"이 목적이며 판단 정확성은 phase1-review 에이전트가 담당한다.

---

## 게이트 적용 스캐너 매핑

| 스캐너 | COVERAGE | OBLIGATION | FILE-PRESENCE |
|--------|----------|------------|---------------|
| xss-scanner | ✓ 고볼륨 | ✓ capability | — |
| dom-xss-scanner | ✓ 고볼륨 | ✓ capability | — |
| command-injection-scanner | — | ✓ capability | ✓ defense |
| code-injection-scanner | — | ✓ capability | ✓ defense |
| ssti-scanner | — | ✓ capability | ✓ defense |
| deserialization-scanner | — | ✓ capability | ✓ defense |
| ssrf-scanner | ✓ 고볼륨 | — | ✓ defense |
| idor-scanner | ✓ 고볼륨 | — | ✓ defense |
| file-upload-scanner | — | — | ✓ defense |
| open-redirect-scanner | — | — | ✓ defense |
| validation-logic-scanner | ✓ 고볼륨 | — | ✓ defense |
| system-prompt-leakage-scanner | ✓ 고볼륨 | — | — |
| unbounded-consumption-scanner | ✓ 고볼륨 | — | — |

---

## 게이트별 FAIL 시 조치

| 게이트 | exit code | 조치 |
|--------|-----------|------|
| COVERAGE | 7 | 해당 스캐너 phase1-review 재호출, COVERAGE 주석 보완 |
| OBLIGATION | 7 | 해당 스캐너 phase1-review 재호출, capability 매치 전수 disposition |
| FILE-PRESENCE | 7 | 해당 스캐너 phase1-review 재호출, accounted 수 보완 |
| SOURCE_HASH 불일치 | 1 | 원본 MD가 수정됨 — eval MD의 SOURCE_HASH 갱신 후 재실행 |
| 평가 미완료 | 1 | phase1-review 재호출 (최대 2회) |

---

## 알려진 한계

### 판단 정확성은 게이트 범위 밖

세 게이트 모두 "숫자가 맞는가"를 검증한다. 에이전트가 파일을 실제로 Read했는지, 판정 근거가 올바른지는 검증하지 않는다.

- `kakao_link_checker.ts`를 처리했다고 `accounted`에 포함시키고 `FALSE_POSITIVE`로 오판정해도 FILE-PRESENCE PASS
- OBLIGATION이 없는 스캐너(ssrf 등)에서 checker 파일을 "방어 코드" 클래스로 오분류해도 게이트 없음

이 한계는 phase1-review의 blind eval이 부분적으로 보완하나, phase1-review 자체도 동일한 편향을 가질 수 있다.

### OBLIGATION 미적용 스캐너의 방어 코드 오분류

ssrf 등 `capability` 정책이 없는 스캐너에서 `*_checker.ts`, `*_validator.ts` 같은 방어 코드 파일은 "방어 코드 = FALSE_POSITIVE" 클래스로 제외되기 쉽다. 실제로는 방어 구현 자체에 결함이 있을 수 있다 (fail-open, IPv6 미처리, DNS Rebinding 미고려 등). FILE-PRESENCE 게이트가 숫자 일치를 강제하지만, 판정이 잘못돼도 통과한다.
