---
name: scan-report-review
description: "noah-sast 보고서의 후보/확인됨/이상 없음 판정을 소스코드와 대조해 검증하고 필요 시 수정하는 서브스킬. 3모드: phase1-review / phase2-review / report-review."
---

# Scan Report Review — Dispatcher

**이 파일은 dispatcher이다.** 에이전트는 이 파일을 읽지 않고 **호출된 mode에 해당하는 파일을 직접 Read**해야 한다. 메인 오케스트레이터(`skills/sast/SKILL.md`)가 모드별 파일 경로를 에이전트 프롬프트에 직접 지정한다.

## 모드별 진입점

| 모드 | 호출 시점 | 진입 파일 | 역할 |
|------|----------|----------|------|
| `phase1-review` | Phase 1 정적 분석 + AI 자율 탐색 완료 직후 | `phase1-review.md` | Phase 1 결과 품질 검증, Phase 2 낭비 방지 |
| `phase2-review` | Phase 2 동적 분석 완료 직후 | `phase2-review.md` | Phase 2 증거 기반 status 할당 |
| `report-review` | 보고서 MD 조립 직후, HTML 변환 전 | `report-review.md` | 보고서 기술 정확성 검증 |

## 공통 레퍼런스

모든 모드가 진입 직후 Read해야 한다.

- `_principles.md` — Source 도달성 판정, 부재 주장 검증, 반환 형식 규칙
- `_contracts.md` — Writer 권한 matrix, exit code, master-list.json/manifest 스키마, DISCARD 보호, 독자 레이어 용어 금지

## 호출 방식

에이전트 프롬프트는 모드별 파일을 직접 지정한다:

```
[MODE=<X> 전용 에이전트]

진입 즉시 아래 3개 파일을 순서대로 Read하세요:
1. <NOAH_SAST_DIR>/sub-skills/scan-report-review/<X>.md
2. <NOAH_SAST_DIR>/sub-skills/scan-report-review/_principles.md
3. <NOAH_SAST_DIR>/sub-skills/scan-report-review/_contracts.md

위 파일의 지시를 정확히 따라 mode=<X> 절차를 수행하세요. 다른 모드의 절차를 수행하면 안 됩니다.
```

## 드리프트 방지

- 각 모드 파일 첫 줄 `MODE GUARD`: 다른 모드 행동 금지, 진입 시 `_principles.md`/`_contracts.md` Read 강제.
- Writer 권한은 `_contracts.md §1`에 단일 정의. 모드 파일은 자기 권한만 기술.
- assert 스크립트(`phase1_review_assert.py`, `phase2_review_assert.py`)가 산출물 필드 완결성을 검증한다 (모드가 수행해야 할 필드 갱신이 누락되면 exit 1~7로 차단).

