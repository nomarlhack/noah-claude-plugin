# scan-report-review 공통 계약 레퍼런스

3모드의 **기계적 계약** 단일 진실 원천 — Writer 권한, Exit code, master-list.json 스키마, 파일 참조 규칙. 각 모드 파일이 진입 직후 Read.

---

## 1. Writer 권한 Matrix

| 필드 | Writer 모드 | Reader 모드 |
|------|------------|------------|
| `status`, `tag`, `evidence_summary`, `verified_defense`, `rederivation_performed`, `source_phase2_file`, `source_phase2_hash` | `phase2-review` (DISCARD 보호 가드 내에서만) | `report-review`, 연계 분석 |
| `phase1_validated`, `phase1_discarded_reason` | `phase1-review` | `phase2-review`, `report-review`, 연계 분석 |
| `phase1_eval_state.retries` (증분) | `phase1-review` | — |
| `phase1_eval_state.conflicts` (**append-only 감사 로그**) | `phase2-review` (Phase 1↔Phase 2 불일치 기록) 및 `phase1-review` (파일 간 판정 충돌 기록). **어떤 모드도 reset 금지** | `report-review`, 연계 분석 |
| `phase1_eval_state.reopen` (품질 개선 힌트, 비차단) | `phase2-review` (set + Phase 2 재평가 완료 후 자체 reset) 및 `phase1-review` (처리 후 reset) | `report-review`, 연계 분석 |
| `safe_category` | `phase1-review` (기본), `phase2-review` (단 `defense_verified` 케이스에 한함) | `report-review`, 연계 분석 |
| 보고서 MD 본문 (설명·스니펫·POC·원인 분석·권장 조치 한정, 판정 필드 불변) | `report-review` | — |
| Phase 1 원본 MD (`<scanner>.md`) | **없음 (불변, 어떤 모드도 Edit·Write 불가)** | `phase1-review`만 Read 허용 |
| eval MD (`evaluation/<scanner>-eval.md`) | `phase1-review` | `phase2-review`, `report-review`, 보고서 조립 |

---

## 2. Exit Code 통일 테이블

두 assert 스크립트(`phase1_review_assert.py`, `phase2_review_assert.py`)가 **동일 exit code 네임스페이스**를 공유한다.

| Exit code | 의미 | Blocking | 후속 조치 |
|-----------|------|---------|----------|
| `0` | pass | — | 다음 단계 진행 |
| `1` | incomplete / invalid state | Yes | 해당 단계 재호출 (phase1-review 또는 phase2-review) |
| `2` | (사용 안 함 — Phase 2 우선 원칙으로 인간 개입 경로 폐기) | — | — |
| `3` | non-blocking warning (rederivation 편향 등) | No | 기록·모니터링만, 다음 단계 진행 가능 |
| `4` | reopen_pending (품질 개선 힌트) | No | `phase1_eval_state.reopen=true` 후보 존재. phase1-review 선택적 재호출 (status는 이미 phase2-review가 확정) |
| `5` | lint 위반 | Yes | Phase 1 원본 직접 참조 금지(§6) 위반. `evaluation/<scanner>-eval.md`로 참조 전환 |
| `6` | missing_placeholder | Yes | 스켈레톤에 `<!-- SAFE_SECTION_HERE -->` 등 필수 플레이스홀더 누락 |
| `7` | safe_bucket_unclassified | Yes | safe 후보에 `safe_category` enum 값 누락. phase2-review/phase1-review이 기록해야 함 |

---

## 3. master-list.json 스키마

### 기본 후보 필드

```json
{
  "id": "XSS-2",
  "title": "...",
  "scanner": "...",
  "file": "...",
  "line": 42,
  "url_path": "...",
  "source": "...",
  "sink": "...",
  "status": "confirmed" | "candidate" | "safe",
  "tag": null | "도구 한계" | "정보 부족" | "환경 제한" | "차단" | "동적 분석 생략" | "동적 검증 불가(LLM endpoint 미확보)" | "endpoint 확인됨, 동적 검증 생략" | "정적 endpoint 식별만, 동적 검증 생략",
  "evidence_summary": "판정 근거 요약 (≤2KB)",
  "verified_defense": null | {"file": "...", "lines": "40-52", "content_hash": "sha256:..."},
  "rederivation_performed": true | false,
  "source_phase2_file": "/tmp/phase1_results_.../xss-scanner-phase2.md",
  "source_phase2_hash": "sha256:...",
  "phase1_validated": true | false,
  "phase1_discarded_reason": null | "Source 도달성 폐기 근거 ...",
  "phase1_eval_state": {
    "reopen": false,
    "retries": 0,
    "conflicts": []
  },
  "safe_category": null | "no_external_path" | "defense_verified" | "not_applicable" | "false_positive" | "platform_default_defense" | "architectural_rationale_only"
}
```

### 필드별 값 제약

Writer는 §1 테이블 참조.

| 필드 | 제약 |
|------|------|
| `status` | enum 3개 중 하나 |
| `tag` | candidate 전용, 그 외엔 `null` |
| `evidence_summary` | ≤ 2KB |
| `verified_defense` | safe + `defense_verified`일 때 `{file, lines, content_hash}` 필수. 본문은 해시만 기록 |
| `rederivation_performed` | safe일 때 Phase 1 hint와 독립적으로 방어 코드를 Read 확인했는지 |
| `phase1_validated` | bool |
| `phase1_discarded_reason` | `_principles.md §1` ✗ 폐기 시 근거, 그 외 `null` |
| `phase1_eval_state.retries` | 재호출 카운터. **상한 2** — 도달 시 해당 후보는 재평가 스킵하고 현재 `phase1_validated`·`status` 유지 (review ↔ phase1-review 무한 루프 방지). `conflicts`에 `{round: N, description: "retry_limit_reached"}` 자동 append |
| `safe_category` | `status=safe`일 때 null 금지. enum 위반 시 exit 7 |

### safe_category enum 의미

| 값 | 정의 | 판정 모드 | 대표 근거 |
|----|------|----------|---------|
| `no_external_path` | 공격자가 해당 코드로 HTTP 요청을 보낼 수 없음 | phase1-review | dev-only 프록시, 서버 번들 비노출, 내부 전용 라우트 |
| `defense_verified` | 공격 페이로드를 실제 전송했으나 명시적 방어 코드가 차단 | phase2-review | nginx 차단, 프레임워크 이스케이프, 게이트웨이 재작성 |
| `not_applicable` | 공격 경로는 존재하나 취약점의 핵심 요건이 부재 | phase1-review 재호출 / phase2-review | 민감정보 0건, 공개 자원이라 보호 대상 아님 |
| `false_positive` | Phase 1이 지적한 코드가 실제로는 취약점 sink가 아님 | phase1-review | 설정 지시자 오인, 방어가 다른 메커니즘으로 존재 |
| `platform_default_defense` | 대상 브라우저·런타임·HTTP 표준이 명시적으로 동등 효과 방어를 제공 (아래 인정 근거 중 하나 이상) | phase1-review | IETF RFC 표준 기본 차단, 주요 브라우저 최근 2개 메이저 버전 기본값, 공식 폐기된 헤더/API, 표준 명세에 의한 조용한 실패 |
| `architectural_rationale_only` | 다른 후보의 경로 증명용으로 기술된 독립 항목 (자체 조치 대상 아님) | phase1-review | 상위 계층 결함의 영향 경로 증거, chain 근거 분리본 |

---

## 4. Phase 2 Manifest v2 스키마

Phase 2 결과 파일(`<scanner>-phase2.md`) 끝에 포함되는 JSON 블록.

```
<!-- NOAH-SAST PHASE2 MANIFEST v2 -->
```json
{
  "scanner": "<scanner-name>",
  "schema_version": 2,
  "results": [
    {
      "id": "<master-list candidate id>",
      "evidence": {
        "commands": ["curl ..."],
        "responses": {"http_status": 200, "body_excerpt": "..."},
        "observations": ["..."],
        "defense_code_hints": null | {"file": "...", "lines": "...", "note": "..."},
        "blocking_layer_hint": null | "nginx" | "backend" | "gateway" | "infrastructure" | ...
      }
    }
  ]
}
```
`<!-- /NOAH-SAST PHASE2 MANIFEST -->`

### 제약

- **각 result에 `status` 필드를 넣지 않는다.** status는 `mode=phase2-review`가 할당한다 (writer 권한 §1).
- `evidence` 내부 필드는 해당 없으면 필드 자체를 **생략** (null placeholder 금지).
- `blocking_layer_hint` / `defense_code_hints`는 차단 의심 시에만 포함 (hint일 뿐이며 확정 아님).
- 후보당 evidence JSON 크기 ≤ 4KB, `body_excerpt` ≤ 512 바이트, `observations` ≤ 10개.

---

## 5. 판정×태그별 필수 필드 매트릭스 (phase2-review 전용)

| 판정 | 태그 | 필수 필드 | 금지 |
|------|------|-----------|------|
| confirmed | — | commands, responses, observations | null placeholder |
| safe | — | commands, responses, verified_defense `{file, lines, content_hash}` | Phase 2 에이전트의 사전 확정 |
| candidate | 도구 한계 | commands (실패 로그), observations (도구 오류 메시지) | 빈 responses placeholder |
| candidate | 정보 부족 | observations (요청한 정보 목록) | — |
| candidate | 환경 제한 | commands, responses, observations (제한 유형 명시) | — |
| candidate | 차단 | commands, responses, blocking_layer_hint | verified_defense 기록 금지 (safe 경로) |
| candidate | 동적 분석 생략 | evidence_summary (사용자 거부 사유) | phase2-review writer 금지 — 사용자가 동적 테스트를 명시적으로 거부한 경로에서 메인 에이전트만 설정 |
| candidate | 동적 검증 불가(LLM endpoint 미확보) | evidence_summary (`endpoint_unverified — <상세 사유>`) | LLM 그룹 4개 스캐너 한정. SKILL.md Step 8-3 그룹 사전 단계가 endpoint를 확보하지 못한 경우 메인 에이전트가 placeholder phase2 결과 파일을 생성하고, `phase2-review`가 이를 인식해 본 tag를 부여한다. verified_defense 기록 금지(안전 판정 아님). |
| candidate | endpoint 확인됨, 동적 검증 생략 | evidence_summary + Phase 2 manifest의 `observations`에 endpoint 명세 요약 (route/채널/multiturn_mode/system_overridable) | LLM 그룹 4개 스캐너 한정. SKILL.md Step 8-3 매트릭스 (Y, N) — sandbox URL은 제공됐으나 동적 공격 테스트는 거부된 경로. probe-agent가 `connectivity-only` 모드로 endpoint를 확보했으나 공격 페이로드 시도는 수행되지 않음. verified_defense 기록 금지. |
| candidate | 정적 endpoint 식별만, 동적 검증 생략 | evidence_summary + Phase 2 manifest의 `observations`에 정적 endpoint 단서 (route 후보/채널 후보/인증 미들웨어 유무) | LLM 그룹 4개 스캐너 한정. SKILL.md Step 8-3 매트릭스 (N, N) — sandbox URL/세션 미제공 + 동적 공격 거부 경로. probe-agent가 `static-only` 모드로 코드 정적 단서만 추출. `verified: false`, `static_only: true`로 산출물이 표기됨. verified_defense 기록 금지. |

**복합 태그**: 두 태그가 동시에 해당하면 각 태그의 필수 필드를 **union**하여 요구한다.

---

## 6. Phase 1 원본 직접 참조 금지 (C1 lint)

Phase 2 에이전트 프롬프트 및 연계 분석 에이전트 프롬프트, 보고서 조립 로직에서 `<PHASE1_RESULTS_DIR>/<scanner>.md` 또는 `<PHASE1_RESULTS_DIR>/ai-discovery.md` 직접 참조는 **금지**한다. 반드시 `<PHASE1_RESULTS_DIR>/evaluation/<scanner>-eval.md` 또는 `evaluation/ai-discovery-eval.md`를 참조한다.

- Phase 1 원본 `<scanner>.md` / `ai-discovery.md`는 **어떤 모드도 Edit·Write 불가**. Read는 오직 `mode=phase1-review`만 허용된다.
- eval MD 부재 시 원본 MD를 fallback으로 허용하되, 결과에 `[FALLBACK: eval MD 부재]` 태그.
- assert 스크립트(`phase1_review_assert.py`, `phase2_review_assert.py`)가 lint 형태로 검사. 위반 시 exit 5.

---

## 7. DISCARD 보호 가드

`mode=phase2-review`는 `phase1_discarded_reason != null` AND `status == "safe"`인 후보의 status·evidence 필드를 **변경하지 않는다**. Phase 2 evidence는 `phase1_quality_notes`에 "DISCARD 상태라 미반영"으로만 기록.

**예외**: `phase1_eval_state.reopen == true`면 `phase2-review`의 커버리지 규약에 따라 DISCARD 철회 가능 (Phase 2 증거로 재확정).

---

## 8. 하위 호환 fallback

- `phase1_validated` 필드 부재 시 `false`로 간주.
- `phase1_eval_state` 부재 시 빈 객체로 초기화: `{reopen: false, retries: 0, conflicts: []}`.
- `safe_category` 부재 + `status != safe`: `null` 허용.
- `safe_category` 부재 + `status == safe`: **exit 7 차단**. 복구: `phase1_eval_state.reopen=true`를 해당 후보에 set 후 `phase1-review` 재호출 (품질 메타데이터 경로).

---

## 9. 독자 레이어 노출 금지 용어

보고서 제목·소제목·대시보드에는 다음 내부 규약 용어를 **절대 노출하지 않는다**:

- `§N` (내부 섹션 번호)
- mode명 (`phase1-review`, `phase2-review`, `report-review`)
- 내부 라벨 (`DISCARD`, `OVERRIDE`, `CONFIRM`, `Source 도달성 폐기`, `실질 영향 반증`)
- 스크립트명 (`phase2_review_assert.py` 등)

근거 서술 본문에서 필요 시에만 풀이와 함께 쓴다. 헤딩·카테고리 라벨로는 쓰지 않는다.
