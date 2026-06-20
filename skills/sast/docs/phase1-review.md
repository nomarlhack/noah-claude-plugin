# Phase 1 리뷰 (phase1-review)

Phase 1 그룹 에이전트가 만든 후보 목록을 **독립 에이전트가 다시 판정**하는 단계다. Phase 2(동적 테스트) 진입 전에 부정확한 후보를 정제해 동적 테스트 낭비를 줄이는 것이 목적이다.

---

## 왜 리뷰가 필요한가

Phase 1 에이전트는 **Sink 패턴 매칭** 중심으로 분석한다. 패턴에 걸리면 일단 후보로 올리고, Source 역추적은 깊이 보지 않는 경향이 있다.

Phase 1 리뷰는 **Source 역추적 중심**으로 접근한다. Phase 1이 "이 코드가 sink다"라고 말할 때 "그 sink에 사용자 입력이 실제로 닿는가"를 독립적으로 추적한다.

```
Phase 1 에이전트: Sink 패턴 발견 → 후보 등록
                                    ↓
Phase 1 리뷰:    Source 역추적 → "입력이 여기까지 오는가?" 검증
                                    ↓
                 CONFIRM / OVERRIDE / DISCARD
```

---

## 호출 위치

```
Phase 1 그룹 에이전트 완료
    ↓
phase1_build_master_list.py (후보 집약)
    ↓
AI 자율 탐색 에이전트
    ↓
phase1_build_master_list.py (재실행)
    ↓
► phase1-review 에이전트  ← 여기
    ↓
phase1_review_assert.py (게이트 검증)
    ↓
Phase 2 (동적 테스트)
```

---

## blind eval 메커니즘

리뷰 에이전트가 Phase 1의 결론을 먼저 읽으면 "Phase 1이 이렇게 판단했으니 맞겠지"라는 편향이 생긴다. 이를 막기 위해 **blind eval**을 사용한다.

```
Phase 1 MD 원본
    ↓
phase1_review_blind_read.py 헬퍼
    ↓
### Decision, ### Confidence, ### 판정 요약 섹션을
"<MASKED until independent judgment>"로 대체
    ↓
리뷰 에이전트는 마스킹된 뷰만 보고 독립 판정
    ↓
마스킹 해제 → Phase 1 결론과 대조 → CONFIRM / OVERRIDE / DISCARD
```

이렇게 하면 리뷰 에이전트가 Phase 1의 결론 없이 코드를 직접 읽고 독립적으로 판단하게 된다.

---

## 판정 결과 3종

| 판정 | 의미 | 결과 |
|------|------|------|
| CONFIRM | Phase 1 판정이 타당함 | `phase1_validated: true` |
| OVERRIDE | Phase 1 판정에 오류가 있으나 후보는 유지 | `phase1_validated: true` + eval MD에 수정 권고 기록 |
| DISCARD | Source 도달성 불가 등 구조적 이유로 폐기 | `status: safe`, `safe_category`, `phase1_discarded_reason` 기록 |

DISCARD는 Phase 2를 낭비하지 않도록 즉시 `status: safe`를 설정한다.

---

## 5개 판정 축

각 후보마다 아래 5개 축을 적용한다.

### 축 1 — 코드 스니펫 정확성

Phase 1이 인용한 코드가 실제 파일·라인에 존재하는가.

- 라인 번호 오차 ±5줄까지 허용 (리팩토링으로 인한 이동)
- 내용이 다르면 eval MD에 실제 코드로 교체 기록

### 축 2 — Source→Sink 흐름

Phase 1이 기술한 흐름을 실제 코드에서 추적한다.

- 호출 관계가 끊기거나 중간에 검증 로직이 있으면 기록
- 메서드명, 클래스명, 파라미터명이 실제와 다르면 수정 권고

### 축 3 — 부재 주장 검증

Phase 1이 "~가 없다", "~하지 않는다"라고 주장하는 모든 곳을 코드 Read로 직접 확인한다.

```
Phase 1: "sanitizer가 없다"
    ↓
리뷰: 실제로 sanitize 함수가 없는지 코드에서 확인
      → 있으면 OVERRIDE (오류 수정)
      → 없으면 CONFIRM
```

### 축 4 — Source 도달성

사용자 입력이 실제로 sink까지 도달할 수 있는가. **tier에 따라 분기**한다.

| tier | 처리 방식 |
|------|----------|
| taint | dataflow가 확정됨 → 역추적 생략, sink 의미론만 확인 |
| ast / generic | Source→Sink 전체 역추적 수행 |

**taint인데 sink 의미론이 맞지 않으면** DISCARD(`safe_category: false_positive`).

**도달성이 없다고 판단되면** 즉시 DISCARD:
- `status: safe`
- `safe_category`: `no_external_path` / `false_positive` / `not_applicable` 중 선택
- `phase1_discarded_reason`에 폐기 근거와 코드 경로 기록

### 축 5 — 최신 플랫폼 방어

Source 도달성이 있더라도 브라우저·런타임·HTTP 표준이 이미 방어하고 있으면 DISCARD(`platform_default_defense`).

인정 근거 예시:
- IETF RFC 표준에 의한 기본 차단
- 주요 브라우저 최근 2개 메이저 버전의 기본값이 동등 방어
- 공식적으로 폐기·제거된 API

---

## 출력: eval MD

리뷰 에이전트는 Phase 1 원본 MD를 수정하지 않는다. 대신 `evaluation/<scanner>-eval.md`를 새로 작성한다.

```
<PHASE1_RESULTS_DIR>/
  ssrf-scanner.md            ← Phase 1 원본 (수정 금지)
  evaluation/
    ssrf-scanner-eval.md     ← 리뷰 평가본 (Phase 2 이후 참조 기준)
```

eval MD 구조:

```
<!-- SOURCE_HASH: sha256:<Phase 1 MD 해시> -->

# ssrf-scanner Phase 1 평가본

## SSRF-1: <후보 제목>

### Phase 1 원본 판정
[Phase 1 MD에서 복사, 변경 없음]

### 평가자 독립 판정 (blind eval 후)
[5개 축 적용 결과 요약]

### Override 여부
CONFIRM | OVERRIDE | DISCARD

### 수정 권고 (Phase 2에 전달)
[Phase 2가 반영해야 할 수정 사항]

### phase1_quality_notes
[축별 근거 요약]
```

**SOURCE_HASH**: Phase 1 원본 MD의 SHA-256 해시. `phase1_review_assert.py`가 이 해시와 현재 원본 파일의 해시를 비교한다. 원본이 수정되면 해시가 달라지고 eval MD가 "고아 상태"로 간주되어 `phase1_validated`가 false 처리된다.

---

## master-list.json 갱신 필드

리뷰 에이전트가 쓸 수 있는 필드:

| 필드 | 의미 |
|------|------|
| `phase1_validated` | 리뷰 완료 여부 — 판정 후 `true`로 설정 |
| `phase1_discarded_reason` | DISCARD 시 폐기 근거 |
| `safe_category` | DISCARD 시 폐기 분류 |
| `phase1_eval_state` | 재호출 정보 (`reopen`, `retries`, `conflicts`) |

**쓸 수 없는 필드** (phase2-review 전용):
- `status`, `tag`, `evidence_summary`, `verified_defense`, `rederivation_performed`

---

## 게이트 (phase1_review_assert.py)

리뷰 완료 후 `phase1_review_assert.py`가 검증한다. Phase 2 진입을 막는 조건:

| exit code | 의미 | 조치 |
|-----------|------|------|
| 0 | 모든 후보 평가 완료, 게이트 통과 | Phase 2 진행 |
| 1 | 평가 미완료 후보 존재 | phase1-review 재호출 (최대 2회) |
| 3 | 비차단 경고 (rederivation 편향 등) | 로그만 남기고 진행 |
| 7 | 감사군 위반 (COVERAGE/OBLIGATION/FILE-PRESENCE) | 위반 스캐너 phase1-review 재호출 |

SOURCE_HASH 불일치(원본 MD 수정)가 감지되면 exit 1로 차단한다.

---

## 재호출 경로

phase2-review가 Phase 1 ↔ Phase 2 간 불일치를 발견하면 `phase1_eval_state.reopen = true`를 설정한다. 다음 phase1-review 호출 시 이 후보만 선택적으로 재평가한다.

재호출 상한: `retries >= 2`인 후보는 스킵하고 `phase1_validated: true` 강제 설정(무한 루프 방지).

---

## Phase 2 이후 참조 기준

Phase 2 에이전트, 연계 분석, 보고서는 **eval MD를 참조 기준**으로 사용한다. Phase 1 원본 MD를 직접 참조하는 것은 금지된다(`_contracts.md §6` C1 lint 강제).

```
Phase 2 에이전트 프롬프트:
  Phase 1 결과: evaluation/ssrf-scanner-eval.md  ← eval MD
              (ssrf-scanner.md 직접 참조 금지)
```

---

## 관련 파일

| 파일 | 역할 |
|------|------|
| `sub-skills/scan-report-review/phase1-review.md` | 리뷰 에이전트 지시 (5개 축, blind eval 절차) |
| `sub-skills/scan-report-review/_principles.md` | 공통 판정 원칙 (Source 도달성, 부재 주장) |
| `sub-skills/scan-report-review/_contracts.md` | 공통 계약 (writer 권한, exit code, 스키마) |
| `tools/phase1_review_blind_read.py` | blind eval 헬퍼 (판정 섹션 마스킹) |
| `tools/phase1_review_assert.py` | 리뷰 완료 게이트 검증 |
| `docs/phase1-execution-flow.md` | Phase 1 전체 실행 흐름 |
