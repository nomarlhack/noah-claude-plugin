# 단일 진실 원천 (Single Source of Truth)

Noah SAST 파이프라인에서 각 데이터가 **어디에 저장되고 누가 쓰는지**를 정의한다. 단일 진실 원천을 위반하면 서로 다른 파일에 같은 데이터가 각각 쓰이고 불일치 시 어느 것이 맞는지 판별 불가해진다. 본 문서는 읽기 가이드이며 기계적 강제는 `sub-skills/scan-report-review/_contracts.md` §1 Writer 권한 Matrix가 담당한다.

## 원칙

- **한 필드 = 한 writer**. 동일 필드를 두 주체가 쓰면 순서에 따라 결과가 달라진다.
- **writer 외 모드는 read-only**. 판정 필드를 reader가 편집하면 파이프라인 하류의 해석이 깨진다.
- **append-only 감사 로그는 reset 금지**. `phase1_eval_state.conflicts`는 여러 모드가 쓰되 삭제·덮어쓰기 금지.
- **위반 검출은 assert 스크립트로**. `phase1_review_assert.py`, `phase2_review_assert.py`가 게이트에서 강제한다.

---

## 5개 원천

### 1. 후보 메타데이터 — `master-list.json`

Phase 1 스캐너와 AI 자율 탐색이 발견한 모든 후보의 집합.

- **Writer**: `phase1_build_master_list.py` (Phase 1 후처리 스크립트)
- **Readers**: 하류 전 단계 (phase1-review, phase2-review, 연계 분석, 보고서 조립)
- **소스 입력**: `<scanner-name>.md` 파일들의 manifest v1 블록 + `ai-discovery.md`
- **스키마**: `_contracts.md` §3
- **핵심 필드** (메타데이터): `id`, `title`, `scanner`, `file`, `line`, `url_path`, `source`, `sink`, `phase1_path`
- **id 규약**: `<id_prefix>-N` — `id_prefix`는 각 스캐너의 `phase1.md` frontmatter에서 선언. 에이전트가 임의로 정하지 않는다. 불일치 시 빌드 스크립트가 `ID_PREFIX_MISMATCH` ERROR로 차단. AI 자율 탐색은 고정 prefix `AI` 사용.
- **재생성 조건**: `--merge` 플래그로 기존 phase2-review 필드를 보존하며 메타데이터만 재파싱

### 2. Phase 1 판정 — `master-list.json`의 `phase1_*` 필드

- **Writer**: `phase1-review` 모드 (blind eval + 5축 독립 판정으로 CONFIRM/OVERRIDE/DISCARD 부여)
- **Readers**: `phase2-review`, `report-review`, 연계 분석
- **필드**: `phase1_validated` (bool), `phase1_discarded_reason` (string|null), `phase1_eval_state.retries`
- **DISCARD 결과**: `phase1_discarded_reason` 기록 + `status: safe` + `safe_category` 확정 (Phase 2 낭비 방지)
- **위반 차단**: `phase1_review_assert.py` exit 1 (phase1_validated 누락) / exit 5 (Phase 1 원본 직접 참조)

### 3. 최종 status — `master-list.json`의 `status`/`tag`/`evidence_summary`/`verified_defense`/`safe_category`

- **Writer**: `phase2-review` 모드 (DISCARD 보호 가드 내에서만). Phase 2 에이전트가 수집한 evidence를 해석하여 최종 status 할당.
- **Readers**: 연계 분석, `report-review`, 보고서 조립
- **status enum**: `confirmed` / `candidate` / `safe`
- **tag enum** (candidate 전용): `도구 한계` / `정보 부족` / `환경 제한` / `차단` / `동적 분석 생략` (마지막은 사용자가 동적 테스트를 명시적으로 거부한 경로에서 메인 에이전트 전용)
- **safe_category enum**: `no_external_path` / `defense_verified` / `not_applicable` / `false_positive`
- **예외**: `phase1-review`가 DISCARD 시 `safe_category`를 기본값으로 쓸 수 있음 (writer 권한 matrix 예외 허용)
- **위반 차단**: `phase2_review_assert.py` exit 1 (status 미완결) / exit 7 (safe_category 누락)

### 4. Phase 2 증거 — `<scanner>-phase2.md`의 manifest v2

- **Writer**: Phase 2 에이전트 (`prompts/phase2-agent.md`). status 필드 기록 금지 — 오직 evidence만.
- **Readers**: `phase2-review` (해석 → status 할당), **보고서 작성 서브에이전트 + `report-review`** (POC 리터럴 원천 — 아래)
- **스키마**: `_contracts.md` §4
- **evidence 필드**: `commands` (실행 명령), `responses` (HTTP 상태 + body 발췌), `observations` (관찰 사실), 옵션으로 `blocking_layer_hint`, `defense_code_hints`
- **POC 리터럴의 단일 원천**: 동적 실행된 항목(`evidence.commands` 존재)의 보고서 "재현 방법 및 POC"는 `commands`/`responses`를 **verbatim 복사**한다 — 재작성·플레이스홀더 치환 금지. 작성 서브에이전트에 `<scanner>-phase2.md` 경로가 전달되고, `report-review`가 잔존 플레이스홀더를 실값으로 교정한다.
- **재평가 트리거**: `source_phase2_hash` 변경 시 `phase2-review` 재평가 필요

### 5. 보고서 본문 — `noah-sast-report.md` / `.html`

- **Writer 1차**: `assemble_report.py` (조립 — skeleton + 스캐너 섹션 + 연계 시나리오 + safe 섹션)
- **Writer 2차**: `report-review` 모드 (설명 품질 개선 — 스니펫, 경로, POC, 원인 분석, 권장 조치 보강)
- **불변 제약**: `report-review`는 `**ID**`, `**유형**`, `**상태**`, `**미확인 사유**` 필드 및 `#### N. 제목` 헤딩 수정 금지. 판정 필드 전파는 1~3번 원천에서만.
- **위반 차단**: `lint_reader_layer.py` (독자 레이어 용어) + `validate_report.py` (건수 일치) + `validate_links.py` (앵커 무결성)

---

## Writer 권한 교차 규칙

### 재호출 중 status 불변

`phase1-review` 재호출(예: `phase1_eval_state.reopen=true` 처리)은 `phase1_*` 필드만 갱신한다. **status / tag / evidence_summary 필드는 건드리지 않는다** (writer는 `phase2-review` 전속).

### append-only 감사 로그

`phase1_eval_state.conflicts`는 `phase1-review`(파일 간 판정 충돌)와 `phase2-review`(Phase 1↔Phase 2 불일치) 양쪽이 append만 수행. reset 금지 — 재호출 루프에서 과거 판정 이력 손실 방지.

### Phase 1 원본 MD 불변

`<PHASE1_RESULTS_DIR>/<scanner>.md`는 어떤 모드도 Edit·Write 불가. `phase1-review`만 Read 허용. 모든 하류 참조는 `evaluation/<scanner>-eval.md`를 거친다 (`_contracts.md` §6 C1 lint).

---

## 위반 검출 지점

| 스크립트 | 검출 대상 |
|---------|---------|
| `phase1_review_assert.py` | `phase1_validated` 누락, eval MD 고아/누락, Phase 1 원본 직접 참조, **session-override 룰 매치 미등록**(고신뢰 IDOR 누락, exit 7) |
| `phase2_review_assert.py` | status 미완결, tag·safe_category enum 위반, Phase 2 manifest에 금지 필드(`status`) 포함, 마스터 목록 mtime 역전 |
| `lint_reader_layer.py` | 보고서 본문의 내부 규약 용어(`§N`, mode명, `DISCARD`) 헤딩 노출 |
| `validate_report.py` | 보고서 건수와 마스터 목록 건수 불일치, **동적 실행 항목 POC의 잔존 플레이스홀더**(exit 6 경고). **FAIL 시 보고서를 영구 삭제하지 않고 `.invalid-<ts>.bak`로 rename**(fail-closed 유지 + 소실 방지) |

각 스크립트의 exit code 의미는 `_contracts.md` §2 Exit Code 통일 테이블 참조.

---

## 관련 문서

| 문서 | 내용 |
|------|------|
| `sub-skills/scan-report-review/_contracts.md` | Writer 권한 Matrix, Exit code, 스키마의 기계적 정의 |
| `sub-skills/scan-report-review/_principles.md` | Source 도달성 판정, 부재 주장 검증 원칙 |
| `docs/review-modes.md` | phase1-review / phase2-review / report-review 3모드 역할 |
| `docs/pipeline.md` | 전체 파이프라인 흐름과 스크립트 실행 순서 |
