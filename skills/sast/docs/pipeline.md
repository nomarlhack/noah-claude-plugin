# 파이프라인 개요

Noah SAST 실행 단계를 한눈에 보여주는 문서. 각 Step의 상세 절차는 `SKILL.md`를 참조한다. 재개 경로는 `docs/resume.md`, 리뷰 3모드는 `docs/review-modes.md`.

## 전체 흐름

```mermaid
flowchart TD
    S1["Step 1<br/>실행 경로 확정"] --> S2["Step 2<br/>패턴 인덱싱"]
    S2 --> S3["Step 3<br/>프로젝트 스택 파악"]
    S3 --> S4["Step 4<br/>스캐너 선별"]
    S4 --> S5["Step 5<br/>정적 분석"]
    S5 --> S6["Step 6<br/>AI 자율 분석"]
    S6 --> ML["phase1_build_master_list.py"]
    ML --> S7["Step 7<br/>정적·AI 리뷰<br/>(phase1-review)"]
    S7 --> S81["Step 8-1<br/>동적 테스트 정보 요청"]
    S81 -->|정보 제공| S82["Step 8-2<br/>도구 권한 확인"]
    S81 -->|거부| Skip["Phase 2 스킵"]
    S82 --> S83["Step 8-3<br/>Phase 2 실행<br/>(Tier A/B/C 병렬)"]
    S83 --> S9["Step 9<br/>동적 분석 리뷰<br/>(phase2-review)"]
    S9 --> S10["Step 10<br/>연계 분석"]
    Skip --> S10
    S10 --> S11["Step 11<br/>결과 검증"]
    S11 --> S12["Step 12<br/>보고서 생성"]
    S12 --> RR{"후보<br/>1건+?"}
    RR -->|Yes| RRV["Step 12-1<br/>report-review"]
    RR -->|No| FIN["Step 12-2<br/>report_finalize.py"]
    RRV --> FIN
```

## 산출물 계보

```mermaid
flowchart LR
    I["패턴 인덱스<br/>PATTERN_INDEX_DIR/*.json"] --> P1["Phase 1 결과<br/>PHASE1_RESULTS_DIR/<br/>*-scanner.md + ai-discovery.md"]
    P1 --> MLJ["master-list.json"]
    MLJ --> EV["evaluation/<br/>*-eval.md"]
    P1 --> P2["Phase 2 결과<br/>*-phase2.md"]
    P2 --> MLJ2["master-list.json<br/>(status/tag/evidence)"]
    EV --> MLJ2
    MLJ2 --> CH["chain-analysis.md"]
    MLJ2 --> RPT["noah-sast-report.md"]
    CH --> RPT
    RPT --> HTMLF["noah-sast-report.html"]
```

## Tier 구조 (Step 8-3 Phase 2)

동적 분석은 인증 컨텍스트에 따라 Tier로 분류. Tier 간 병렬, Tier 내 순차.

| Tier | 특성 | 예시 스캐너 |
|------|------|-----------|
| A | 인증 불요 (헤더/설정) | security-headers, http-smuggling, tls |
| B | 공유 세션 사용 (주요 테스트) | xss, sqli, ssrf, idor, csrf 등 대부분 |
| C | 독립 인증 컨텍스트 | oauth, saml, jwt |

## 스크립트 실행 순서

**메인 파이프라인 (순차)**

| 단계 | 스크립트 | 역할 |
|------|---------|------|
| Step 2 | `semgrep_index.py` | 패턴 인덱싱 (semgrep 룰 + grep-less 스캐너 빈 인덱스, exit 0 + stdout 키워드로 결과 전달) |
| Step 4 | `select_scanners.py` | 스캐너 선별 + 그룹 편성 + Tier 출력 |
| Phase 1 후처리 | `phase1_build_master_list.py` | master-list.json 생성 |
| Step 7 게이트 | `phase1_review_assert.py` | phase1-review 완료 확인 |
| Step 9 게이트 | `phase2_review_assert.py` | phase2-review 완료 확인 |
| Step 12 ① | `sub-skills/scan-report/assemble_report.py` | 보고서 조립 |
| Step 12 ② | `report_finalize.py` | html → validate → lint → links → open |

**에이전트 내부 헬퍼 (파이프라인 밖)**

| 스크립트 | 호출 주체 |
|---------|---------|
| `phase1_review_blind_read.py` | phase1-review 에이전트 (blind eval) |
| `phase2_actuator_check.py` | Spring Boot hardening 스캐너 (URL 안전성) |

**재개·개발용**

| 스크립트 | 시점 |
|---------|------|
| `phase1_resume.py` | 중단 후 재개 요청 시 |
| `lint_reader_layer.py` | 보고서 독자 레이어 용어 검증 (report_finalize.py 내부 호출) |

## 단일 진실 원천

| 대상 | 원천 | Writer |
|------|------|--------|
| 후보 메타데이터 | `master-list.json` | `phase1_build_master_list.py` (Phase 1 파싱) |
| Phase 1 판정 | `master-list.json`의 `phase1_*` 필드 | `phase1-review` |
| 최종 status | `master-list.json`의 `status/tag/evidence_summary` | `phase2-review` |
| Phase 2 증거 | `*-phase2.md`의 manifest v2 | Phase 2 에이전트 |
| 보고서 본문 | `noah-sast-report.md` | `assemble_report.py`, `report-review` |

상세 설명은 `docs/single-source-of-truth.md`, 기계적 계약(Writer 권한, 스키마, enum)은 `sub-skills/scan-report-review/_contracts.md` 참조.

## 관련 문서

| 문서 | 내용 |
|------|------|
| `SKILL.md` | Step별 실행 절차 (메인 에이전트용) |
| `docs/resume.md` | 중단 후 재개 판별 규칙 |
| `docs/review-modes.md` | phase1-review / phase2-review / report-review 3모드 |
| `docs/single-source-of-truth.md` | 각 데이터의 writer/reader 상세 |
| `docs/lint-reader-layer.md` | 독자 레이어 용어 lint 규칙 |
| `docs/automation-plan.md` | 자동화된 스크립트의 역할 |
| `sub-skills/scan-report-review/_contracts.md` | Writer 권한 / Exit code / Schema |
| `sub-skills/scan-report-review/_principles.md` | Source 도달성 / 부재 주장 검증 원칙 |
