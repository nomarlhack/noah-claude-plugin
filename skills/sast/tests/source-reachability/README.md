# Source Reachability 수동 회귀 픽스처

`guidelines-phase1.md` 지침 8 및 `scan-report-review/_principles.md` §1 Source 도달성 판정
(phase1-review/report-review가 모두 적용)이 정상 동작하는지 수동으로 검증하기 위한 픽스처.

패턴 인덱싱(semgrep)은 sink/source 패턴의 존재 여부만 본다. Source 도달성은 semantic 판정이므로
여기서 자동화하지 않고 LLM 에이전트 기반 회귀로 돌린다.

## 픽스처

| 경로 | 내용 | 기대 결과 |
|------|------|----------|
| `fixtures/false-positive/ConstantSink.java` | `out.print`의 인자가 상수/UUID/리터럴 | Phase 1에서 후보 등록 안 됨 |
| `fixtures/true-positive/UserInputSink.java` | `getParameter` → `out.print` | 후보 등록됨 |
| `fixtures/mixed/MixedCaller.java` | 같은 Sink 함수의 두 호출부 중 하나만 Source 도달 | `handleUser` 경로만 후보 유지, `handleStatic` 폐기 |

## 회귀 절차

### 1. Phase 1 진입 차단 검증

픽스처 디렉토리를 작업 디렉토리로 지정하고 xss-scanner Phase 1 에이전트를 실행한다
(`phase1-group-agent.md` + `guidelines-phase1.md` + `xss-scanner/phase1.md`).

- `ConstantSink.java`의 어떤 `out.print` 호출도 후보로 등록되면 안 된다.
- `UserInputSink.java`의 `out.print(q)`는 후보로 등록되어야 한다.
- `MixedCaller.java`는 `handleUser` 호출 경로의 `write(out, q)`만 후보로 잡혀야 한다.

### 2. Review 재분류 검증

Phase 1이 `ConstantSink.java` 후보를 잘못 등록했다고 가정한 보고서를 수동으로 작성한 뒤
`scan-report-review` 스킬을 실행한다.

- `_principles.md §1 Source 도달성 판정`에서 `Source 도달성 실패`로 판정되어야 한다.
- Step 5에서 후보 → 이상 없음 재분류가 일어나야 한다.
- Step 6 수정 내역 표에 `Source 도달성 실패` 행이 등장해야 한다.

### 3. 용어 드리프트 확인

```
grep -rn "Source 도달성\|컴파일 타임 상수\|내부 생성값" skills/sast/prompts skills/sast/sub-skills/scan-report-review
```

`guidelines-phase1.md`, `scan-report-review/_principles.md`, `SKILL.md` 세 파일에서 공통 용어가 모두 등장해야 한다.
