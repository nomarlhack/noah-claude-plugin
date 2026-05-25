# MODE GUARD: 이 파일은 mode=phase1-review 전용

**[STOP]** 진입 에이전트 프롬프트에 `MODE=phase1-review`이 명시되지 않았다면 이 파일의 절차를 수행하지 말고 즉시 종료하라. 잘못 진입한 경우 아무 필드도 쓰지 말고 메인 에이전트에 "모드 불일치"를 보고한다.

**다른 모드라면 해당 파일을 대신 Read하라.**
- mode=phase2-review → `phase2-review.md`
- mode=report-review → `report-review.md`

**진입 전 필수 Read**:
1. `_principles.md` (공통 판정 원칙: Source 도달성, 부재 주장, 반환 형식)
2. `_contracts.md` (공통 계약: writer 권한, exit code, 스키마)
3. **`<NOAH_SAST_DIR>/prompts/decision-framework.md` ([필수] Phase 1 에이전트와 동일한 후보 판정 의사결정 프레임워크 — tier 분기 + 표준 라벨 + 객관 사실 체크리스트 + 트리거 4단계 + 통합/분리 규칙). 본 모드의 5개 축이 본 프레임워크를 단일 진실 원천으로 적용한다.**

**입력 허용 경로**:
- `<PHASE1_RESULTS_DIR>/<scanner>.md` (Phase 1 원본 — **이 모드만 Read 허용**)
- `<PHASE1_RESULTS_DIR>/ai-discovery.md`
- `<PHASE1_RESULTS_DIR>/master-list.json` (Read만)
- 프로젝트 소스코드 (부재 주장 / Source 도달성 검증용)

**출력**:
1. `<PHASE1_RESULTS_DIR>/evaluation/<scanner>-eval.md` (신규 작성)
2. `master-list.json`의 `phase1_validated`, `phase1_discarded_reason`, `phase1_eval_state`, `safe_category` 필드 갱신

**금지**:
- `tag`, `evidence_summary`, `verified_defense`, `rederivation_performed` 필드 쓰기 (writer는 phase2-review)
- `status` 필드 쓰기 — **예외**: 축 4 ✗ 폐기 시 `status: safe` 즉시 할당 (Phase 2 낭비 방지).
- Phase 1 원본 `.md` 파일 Edit·Write (Read만 허용, 원본 불변)
- 보고서 MD 파일 수정 (report-review의 영역)

---

# mode=phase1-review

Phase 1이 생산한 후보 목록과 prose 분석의 **정적 분석 품질**을 독립 재판정한다. Phase 2 이전에 수행되어 부정확한 후보를 조기에 정제한다.

## 호출 시점

Phase 1 정적 분석 + AI 자율 탐색 완료 직후, Phase 2 진입 전.

## 관점

Phase 1이 **Sink 패턴 매칭** 중심이었다면, 이 모드는 **Source 역추적 중심**으로 접근한다. 절차: `_principles.md §1`.

---

## blind eval 메커니즘

1. Phase 1 MD를 `tools/phase1_review_blind_read.py`로 로드. 헬퍼가 다음 섹션을 `<MASKED until independent judgment>`로 대체한 뷰를 반환:
   - `### Decision`
   - `### Confidence`
   - `### 판정 요약`
2. 평가자는 **마스킹된 뷰만** 보고 아래 4개 필수 축을 독립 적용.
3. 마스킹 해제 → Phase 1 결론과 대조 → `CONFIRM` / `OVERRIDE` / `DISCARD` 중 하나 기록.

---

## 필수 적용 5개 축 (decision-framework.md §6 매핑)

각 후보마다 아래 5개 축을 모두 적용한다. 각 축의 판정 기준은 `decision-framework.md`를 단일 진실 원천으로 사용한다 — 본 문서에 모호 기준을 별도 정의하지 않는다.

### 축 1 — 코드 스니펫 정확성 (framework §2-A 사실(a))

Phase 1이 인용한 코드가 실제 파일·라인에 존재하는가.
- 라인 번호 오차 ±5줄까지 허용 (리팩토링으로 인한 이동).
- 내용이 다르면 eval MD에 실제 코드로 교체 기록.

### 축 2 — Source→Sink 흐름 (framework §2-A 사실(a) + §3 라벨)

Phase 1이 기술한 각 단계를 실제 코드에서 추적.
- 호출 관계가 끊기거나 중간에 검증 로직이 있으면 기록.
- 메서드명, 클래스명, 파라미터명이 실제와 다르면 수정 권고.
- 라벨(`DIRECT`/`INDIRECT`/`SECOND_ORDER`/`IDENTIFIER` 등)이 흐름과 일치하는가 확인.

### 축 3 — 부재 주장 검증 (framework §2-A 사실(b))

Phase 1이 "~가 없다", "~하지 않는다"라고 주장하는 모든 곳을 검증.
- **의무 절차 5단계** — `_principles.md §2 부재 주장 검증` 적용.
- decision-framework §2-A (b)의 객관 사실(타입 캐스트/화이트리스트/sanitizer/바인딩)이 실제로 부재하는지 코드 read로 확인.
- 결과를 eval MD의 `phase1_quality_notes`에 기록.

### 축 4 — Source 도달성 (framework §1 tier 자동 분기)

`_principles.md §1 Source 도달성 판정` + `decision-framework.md §1` 적용.

**tier 자동 분기 (decision-framework.md §1):**
- `tier: taint` + sink 의미론 정합 → ✓ 유지 자동, 3단계 역추적 생략. `phase1_quality_notes`에 "taint tier — dataflow 확정 (rule: \<id\>)" 기록.
- `tier: taint` + sink 의미론 불일치 → DISCARD (`safe_category: false_positive`).
- `tier: ast`/`generic` → 전체 역추적 수행, §2-A 객관 사실 (a)·(b) 확인.

> **presence 아키타입 예외** (`decision-framework.md §3`, `hardcoded-secrets-scanner` / `log-injection-scanner`):
> 이 스캐너의 매치는 "값/패턴 자체가 취약점"이므로 Source 도달성(O2) 역추적을 적용하지 않는다.
> `tier: generic`이라도 역추적 결과가 "하드코딩 리터럴"이면 **DISCARD가 아닌 CONFIRM**이다 — 리터럴이 취약점의 증거이기 때문. O4(sink 의미론 정합 — 실제 비밀값 형태인지, 실제 로그 sink인지)만 확인 후 CONFIRM.

**✗ 폐기 시 즉시 액션** (Phase 2 낭비 방지):
- `status: safe`, `tag: null`
- `phase1_validated: true`
- `phase1_discarded_reason`에 폐기 근거 + 코드 경로 기록 (예: "인자 X가 static final 상수로 대입, <file>:<line>")
- `safe_category` enum 필수 (통상 `no_external_path` 또는 `false_positive`)

**? 불명확 시**: `phase1_validated: true` 유지 (CONFIRM 취급).

### 축 5 — 최신 플랫폼 방어 (framework §3 라벨 PLATFORM_DEFENSE)

Source 도달성이 ✓ 유지라도, 대상 브라우저·런타임·HTTP 표준이 명시적으로 동등 효과 방어를 제공하면 DISCARD → `platform_default_defense` (decision-framework.md §3 라벨 `PLATFORM_DEFENSE`).

**인정 근거** (아래 중 하나 이상 명시 가능할 때 DISCARD, 아니면 CONFIRM 유지):

- IETF/HTTP RFC 표준에 의한 기본 차단 (예: 인증 요청의 공유 캐시 차단 RFC 7234)
- 주요 브라우저(Chrome/Firefox/Safari) 최근 2개 메이저 버전의 기본값이 동등 방어
- 공식적으로 폐기·제거된 헤더/API (해당 기능이 현대 브라우저에서 무시됨)
- 표준 명세에 의한 조용한 실패 (예: 누락 속성으로 동작이 차단됨)

**복수 성립 시 우선순위**: `no_external_path` / `not_applicable` > `defense_verified` / `platform_default_defense`.

---

## 선택 적용 축 (효율)

후보가 이미 참조하는 파일을 Read한 김에 겸사 적용한다. 단독 Read는 비효율.

- **복수 요소 커버리지**: 후보가 인용한 설정값/코드에 복수의 요소가 있거나 동일 결함이 복수 파일·라인에서 발견될 때, 제목·본문·POC가 모든 요소를 반영하는가 확인.
- **동일 file:line 다층 관점**: 서로 다른 스캐너가 같은 file:line을 지적하는 후보가 2건 이상이면 관점 차이를 확인하고 통합 가능성 판단 (한 후보의 권장 조치가 다른 후보를 해소하는가 의사 테스트).
- **아키텍처 근거 중복**: 후보가 다른 후보의 경로 증명용으로만 기술된 독립 항목이면 `architectural_rationale_only`로 DISCARD (조치는 참조 대상 후보가 담당).

---

## 판정 결과

| 판정 | 의미 | master-list.json 갱신 |
|------|------|---------------------|
| `CONFIRM` | Phase 1 판정 타당 | `phase1_validated: true` |
| `OVERRIDE` | Phase 1 판정에 수정 필요 (스니펫·흐름·부재 주장 오류) | `phase1_validated: true` + eval MD에 수정 권고 |
| `DISCARD` | Source 도달성 불가 등 구조적 이유로 폐기 | `status: safe` + `tag: null` (safe는 tag 없음), `phase1_validated: true`, `phase1_discarded_reason` 기록, `safe_category` enum 필수 |

---

## eval MD 형식

`<PHASE1_RESULTS_DIR>/evaluation/<scanner>-eval.md`에 아래 형식으로 작성. 상단 `<!-- SOURCE_HASH: sha256:... -->` 주석은 Phase 1 원본 MD의 해시로, assert가 원본과 대조하여 불일치 시 eval 고아 상태로 간주해 `phase1_validated`를 false 처리한다.

```markdown
<!-- SOURCE_HASH: sha256:<Phase 1 MD 해시> -->

# <scanner-name> Phase 1 평가본

## <ID>: <후보 제목>

### Phase 1 원본 판정
[Phase 1 MD에서 복사, 변경 없음]

### 평가자 독립 판정 (blind eval 후)
[4개 축 적용 결과 요약]

### Override 여부
CONFIRM | OVERRIDE | DISCARD

### 수정 권고 (Phase 2에 전달)
[Phase 2가 반영해야 할 Source·Sink·테스트 경로 수정 사항]

### phase1_quality_notes
[축 3 taint 분석 요약 + 축 4 Source 도달성 근거 + 축 1·2 정확성 판정]
```

---

## 파일 간 일관성 검사

eval MD 작성 완료 후 마지막 단계:

- 동일 `file:line`을 지적하는 모든 스캐너의 eval MD를 교차 확인.
- 상충된 판정(A 스캐너는 CONFIRM, B 스캐너는 DISCARD) 발견 시 `phase1_eval_state.conflicts`에 기록 (감사 로그용, 파이프라인 차단 없음).

---

## 재호출 경로

트리거: `mode=phase2-review`가 Phase 1↔Phase 2 불일치를 발견하고 `phase1_eval_state.reopen=true`를 사전 설정한 경우. 이 파일이 `reopen == true`인 후보를 선택적으로 재평가한다 (품질 메타데이터 갱신 목적, status 결정은 phase2-review가 이미 확정).

### 재평가 절차

1. **retries 상한 체크**: `phase1_eval_state.retries >= 2`인 후보는 재평가 스킵 + `phase1_validated=true` 강제 세팅(무한 루프 방지). 이미 `conflicts`에 `retry_limit_reached`가 있으면 재기록하지 않음, 없으면 `{round: retries, description: "retry_limit_reached"}` 1회만 append.
2. 나머지 대상 후보에 4개 축 재적용.
3. 완료 후:
   - `reopen = false` 리셋 (conflicts는 **절대 reset 금지 — append-only**)
   - `retries += 1`
   - `phase1_validated = true` 재기록 (DISCARD 제외)
   - DISCARD 판정 시: 현재 `status`가 이미 `safe`면 skip, 아니면 `status: safe`로 재확정

---

## Step 진행

1. master-list.json Read, `phase1_validated != true` 또는 `phase1_eval_state.reopen == true`인 후보 수집.
2. 각 후보에 대해 blind eval → 4개 축 적용 → 판정.
3. 축 4에서 ✗ 폐기 판정 시 즉시 `status: safe` 할당 (Phase 2 낭비 방지).
4. `evaluation/<scanner>-eval.md` 작성.
5. 파일 간 일관성 검사.
6. master-list.json 갱신 (재호출이면 `reopen=false` 리셋 + `retries` 증분).
7. 판정 분포(CONFIRM/OVERRIDE/DISCARD) 및 일관성 검사 결과 요약 반환.

---

## 반환 형식

```
## Phase 1 평가 결과

### 판정 분포
| 판정 | 건수 |
|------|------|
| CONFIRM | N |
| OVERRIDE | N |
| DISCARD | N |

### DISCARD 상세
| ID | safe_category | phase1_discarded_reason |
|----|---------------|-----------------------|
| ... | ... | ... |

### OVERRIDE 상세
| ID | 수정 권고 요약 |
|----|----------------|
| ... | ... |

### 일관성 검사
| 이상 유형 | ID 목록 |
|-----------|---------|
| 동일 file:line 판정 충돌 | ... |
```

---

## 자가 검증 (반환 전 필수)

- 모든 후보에 `phase1_validated` 갱신되었는가?
- DISCARD 후보에 `safe_category` + `phase1_discarded_reason` 기록되었는가? (누락 시 exit 7)
- eval MD 상단에 `<!-- SOURCE_HASH: ... -->` 주석이 있는가?
- reopen 재호출 시 `retries` 증분 + `reopen=false` 리셋 수행했는가?
- Phase 1 원본 MD를 Edit·Write하지 않았는가?
