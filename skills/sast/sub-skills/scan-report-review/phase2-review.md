# MODE GUARD: 이 파일은 mode=phase2-review 전용

**[STOP]** 진입 에이전트 프롬프트에 `MODE=phase2-review`가 명시되지 않았다면 이 파일의 절차를 수행하지 말고 즉시 종료하라. 특히 **소스코드를 직접 탐색하는 "보고서 대조 검증" 절차는 report-review 모드의 영역**이며 이 모드에서 절대 수행 금지. 잘못 진입한 경우 아무 필드도 쓰지 말고 메인 에이전트에 "모드 불일치"를 보고한다.

**다른 모드라면 해당 파일을 대신 Read하라.**
- mode=phase1-review → `phase1-review.md`
- mode=report-review → `report-review.md`

**진입 전 필수 Read**:
1. `_principles.md` (공통 판정 원칙)
2. `_contracts.md` (공통 계약: writer 권한, exit code, 스키마, 판정×태그 매트릭스)

**입력 허용 경로**:
- `<PHASE1_RESULTS_DIR>/<scanner>-phase2.md` (Phase 2 동적 테스트 결과)
  - **AI 후보**(`scanner == "ai-discovery"`): 먼저 `ai-discovery-phase2.md`에서 해당 ID 검색 → 없으면 전체 `*-phase2.md` manifest를 ID로 역탐색하여 매칭되는 파일 사용 (scanner 카테고리 의미 매핑 불필요). 두 경로 모두 부재 시 `candidate + tag: 도구 한계`.
- `<PHASE1_RESULTS_DIR>/evaluation/<scanner>-eval.md` (Phase 1 평가본)
- `<PHASE1_RESULTS_DIR>/master-list.json` (Read + 일부 필드 Write)
- 프로젝트 소스코드 — **오직 `verified_defense` 기록을 위한 방어 코드 Read 확인 시에만 허용**. 그 외의 일반 코드 탐색 금지 (이는 report-review의 영역).

**출력**: `master-list.json`의 다음 필드만 쓴다.
- `status`, `tag`, `evidence_summary`, `verified_defense`, `rederivation_performed`, `source_phase2_file`, `source_phase2_hash`
- `phase1_eval_state.reopen` / `conflicts` (Phase 1↔Phase 2 불일치 감사 기록 시)

**금지**:
- `phase1_validated`, `phase1_discarded_reason`, `phase1_eval_state.retries`, `safe_category` 단독 쓰기 (writer는 phase1-review. 단, `status: safe` 할당 시 `safe_category: defense_verified` 동반 기록은 허용.
- Phase 1 원본 `.md` 직접 Read (eval MD만 참조 — `_contracts.md §6`)
- 보고서 MD 파일 수정 (report-review의 영역)
- 프로젝트 소스코드의 일반 탐색 (방어 코드 재확인 외)

---

# mode=phase2-review

Phase 2 동적 분석이 생산한 evidence를 해석하여 각 후보의 최종 `status`를 확정한다.

## 호출 시점

Phase 2 동적 분석 완료 직후, Step 10(연계 분석) 진입 전.

## 커버리지 규약

대상: `phase1_discarded_reason == null` **또는** `phase1_eval_state.reopen == true` (reopen이 우선 — DISCARD도 재평가 가능). skip된 후보는 status·evidence 변경 금지.

---

## 증거 해석 원칙

- **confirmed**: 공격 성공 지표가 응답/관찰에 명시됨. "성공한 것 같다" 같은 수식어 금지.
- **safe**: `verified_defense`에 Read로 확인한 `{file, lines, content_hash}` 기록 필수. Phase 2 hint를 그대로 복사 금지 — 반드시 독립 Read.
- **candidate**: "애매하면 candidate" 금지. 사유 `tag` + 해당 태그 필수 필드 충족 (상세: `_contracts.md §5`).

---

## rederivation_performed 필드

- `true`: phase2-review가 Phase 2 hint와 **독립적으로** 방어 코드를 Read하여 재확인한 경우
- `false`: Phase 2 hint를 그대로 승격한 경우 (편향 의심 신호)

`false` 비율이 safe 판정 전체의 30%를 초과하면 `phase2_review_assert.py`가 exit 3 (rederivation_warn)을 발생시킨다 (비차단 경고).

---

## §10-A Phase 2 우선 원칙

Phase 1은 **코드만** 보기 때문에 인프라(WAF, 프록시 정규화, 프레임워크 런타임 방어, 게이트웨이 재작성 등)를 관측할 수 없다. Phase 2는 실제 요청/응답을 관찰한 **실증 데이터**이며 Phase 1 이후 실행되어 그 주장을 검증한다.

따라서 Phase 1 정적 주장과 Phase 2 동적 증거가 다를 때 **항상 Phase 2 증거로 status를 확정한다**. Phase 1 주장은 참고 정보일 뿐.

| Phase 2 증거 | status 확정 (Phase 1 주장 무관) |
|-------------|-------------------------------|
| 공격 성공 지표 관측 (alert·데이터 반환·상태 변경 등) | `confirmed` |
| 방어 계층 작동 관측 (차단 응답·에러·정규화 등) | `safe` + `safe_category: defense_verified` + `verified_defense` |
| 증거 불명확 (타이밍 동일·응답 모호·관측 불가) | `candidate` + 해당 `tag` (도구 한계 / 정보 부족 / 환경 제한 / 차단) |
| Phase 2 미수행 (사용자 거부·환경 제한) | `candidate` + `tag: 환경 제한` 또는 `정보 부족` |
| Phase 2 파일 자체 부재 (에이전트 실행 실패·파일 생성 실패) | `candidate` + `tag: 도구 한계`. 일반 후보·AI 후보 공통 기본 처리 |

### Phase 1 판정 불일치 기록 (감사 로그)

Phase 1 판정과 Phase 2 확정 status가 다르면 `phase1_eval_state.conflicts` 배열에 기록한다:

```json
{"round": N, "description": "Phase 1 <주장> vs Phase 2 <관측>"}
```

품질 개선이 필요하면 `phase1_eval_state.reopen=true`를 선택적으로 set (status 결정과 무관, 비차단).

---

## Idempotent 동작

이미 `status` 할당된 후보는 스킵 (예외: `reopen == true` 또는 `source_phase2_hash` 불일치).

---

## safe 판정 시 writer 규약

`status: safe` 할당 시 4개 필드를 모두 채운다: `safe_category: "defense_verified"`, `verified_defense={file, lines, content_hash}`, `rederivation_performed`(독립 Read 여부), `source_phase2_file`/`source_phase2_hash`. `validate_safe_consistency`가 `defense_verified`↔`verified_defense` 정합성 검증 (불일치 시 exit 1).

**DISCARD 경로 면제**: `phase1_discarded_reason != null`인 safe 후보는 상호 검증 면제, `safe_category`만 기록 필수.

---

## 재평가 트리거

**진입 시 해시 비교**: 각 후보의 현재 Phase 2 파일 sha256을 master-list의 `source_phase2_hash`와 비교.
- `source_phase2_hash == null` (최초 호출) → 정상 경로, Idempotent 스킵 적용 안 함
- 해시가 기록된 값과 **다르면** 재평가 대상에 포함 (Phase 2 재실행·파일 수정 반영)
- 일치하면 idempotent 스킵

그 외 필드 제약은 `_contracts.md §3` 단일 원천.

---

## Step 진행

1. master-list.json Read, `_contracts.md §6` C1 lint 경로 준수 확인.
2. 커버리지 규약 + 해시 비교로 대상 후보 집합 결정.
3. 각 후보에 대해 Phase 2 결과 파일 Read하여 manifest 추출.
4. §10-A Phase 2 우선 원칙 적용 → status/tag 할당.
   - **LLM endpoint 미확보 placeholder 인식**: scanner가 LLM 그룹 4개(`prompt-injection-scanner`, `system-prompt-leakage-scanner`, `insecure-output-handling-scanner`, `unbounded-consumption-scanner`) 중 하나이고, Phase 2 manifest의 `results[*].evidence.observations`에 `"endpoint_unverified"` 문자열이 포함되거나 manifest가 사실상 placeholder(`results` 비어 있거나 evidence가 사유 문자열 한 줄)인 경우, 해당 스캐너의 모든 LLM 후보에 `status: candidate` + `tag: "동적 검증 불가(LLM endpoint 미확보)"`를 부여한다. `evidence_summary`에는 placeholder가 기록한 사유를 그대로 옮긴다. 본 케이스는 `verified_defense` 기록 금지(`safe`가 아님), `safe_category`는 `null` 유지.
5. safe 판정 시 방어 코드 Read → `verified_defense` 기록.
6. Phase 1↔Phase 2 불일치 발견 시 `conflicts`에 감사 로그 기록 + 필요 시 `reopen=true` 선택적 set.
7. **reopen reset 규칙**:
   - 모순이 해소되거나 Phase 1과 일관된 status로 확정 → `reopen=false` reset
   - 모순은 여전하나 `source_phase2_hash`가 이전과 동일 (Phase 2 증거에 새 정보 없음) → `reopen=false` reset + `conflicts`에 `{round: N, description: "no_new_evidence"}` append (영구 루프 방지)
   - 모순 + Phase 2 evidence가 새로 갱신됨 → `reopen=true` 유지 (phase1-review 재호출 대기)
8. master-list.json 갱신.
9. 판정 분포 및 이상 요약 반환.

---

## 반환 형식

```
## Phase 2 평가 결과

### 커버리지
| 종류 | 건수 |
|------|------|
| 처리 대상 | N |
| DISCARD skip (reopen=false) | N |

### 판정 분포
| status | 건수 |
|--------|------|
| confirmed | N |
| candidate | N |
| safe | N |

### candidate 태그 분포
| tag | 건수 |
|-----|------|
| 도구 한계 | N |
| 정보 부족 | N |
| 환경 제한 | N |
| 차단 | N |

### safe_category 분포
| safe_category | 건수 |
|---------------|------|
| defense_verified | N |
| (그 외는 phase1-review이 부여) | — |

### Phase 1 ↔ Phase 2 불일치 로그
- conflicts 기록: N건 (ID 목록)
- reopen 설정: N건 (ID 목록)

### rederivation_performed 통계
- true: N건
- false: N건 (비율 X% — 30% 초과 시 exit 3 경고 예정)
```

---

## 자가 검증 (반환 전 필수)

- 커버리지 규약 준수: DISCARD + reopen=false 후보는 손대지 않았는가?
- 모든 confirmed에 `commands`, `responses`, `observations` 필드가 있는가? (`_contracts.md §5`)
- 모든 safe에 `verified_defense` 객체가 `{file, lines, content_hash}` 형식으로 채워졌는가?
- 모든 candidate에 `tag` + 해당 태그 필수 필드가 있는가?
- `null` placeholder를 넣지 않았는가? (해당 없는 필드는 생략)
- `safe_category` 누락된 safe 후보가 없는가? (누락 시 exit 7)
- Phase 1 ↔ Phase 2 불일치 후보에 `phase1_eval_state.conflicts` 기록했는가?
- Phase 1 원본 MD를 직접 Read하지 않고 eval MD만 참조했는가?
