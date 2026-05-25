# noah-8719

> Claude Code 보안 분석 플러그인. 49개 취약점 스캐너 + AI 자율 탐색으로 정적 분석 + 동적 테스트 + 보고서 생성.

## 설치

```bash
git clone https://github.com/nomarlhack/noah-claude-plugin.git noah-8719
claude --plugin-dir ./noah-8719
```

#### 요구사항

| 항목 | 조건 |
|------|------|
| Claude Code | 최신 버전 |
| Git | 클론 시 필요 |
| Python 3 | 보고서 생성/검증 기능에 필요 |

#### 업데이트

```bash
cd noah-8719 && git pull
```

## 사용법

Claude Code에서 다음 중 하나를 입력합니다:

```
/noah-8719:sast
```

> `sast`, `소스코드 취약점 스캔` 등으로도 트리거됩니다.

## 개요

Noah SAST는 Claude Code의 **스킬(Skill)** 위에서 동작하는 소스코드 취약점 분석 프레임워크입니다. 49개 전용 스캐너와 AI 자율 탐색을 결합해 **정적 분석 → 동적 검증 → 보고서 생성**까지 한 번에 수행합니다.

전체 파이프라인은 네 묶음으로 이어집니다.

1. **준비** (Step 1–4) — 무엇을·어디를 스캔할지 정하고 코드베이스를 한 번만 인덱싱합니다.
2. **Phase 1 · 정적 분석** (Step 5–7) — 스캐너와 AI가 코드를 읽어 취약점 후보를 찾고 1차로 거릅니다.
3. **Phase 2 · 동적 검증** (Step 8–11) — 실제 페이로드를 보내 후보가 진짜 악용 가능한지 확인합니다.
4. **보고서** (Step 12) — 확정된 결과를 사람이 읽을 문서로 조립합니다.

이 구조를 떠받치는 세 가지 설계 원칙만 알면 나머지는 자연스럽게 읽힙니다.

- **단일 진실 원천** — 모든 상태는 `master-list.json` 한 파일에만 기록되고, 각 필드는 정해진 한 주체만 쓸 수 있습니다(Writer 권한 matrix). 단계가 늘어나도 상태가 흩어지지 않습니다.
- **오탐·미탐 저항** — 후보의 최종 판정은 탐색을 수행한 에이전트가 아니라 **독립된 리뷰 에이전트**가 코드와 증거만 보고 내립니다(blind eval). 정적 주장과 동적 증거가 충돌하면 **항상 동적 증거를 따릅니다**(Phase 2 우선). 자세한 규칙은 아래 **Safe-by-Proof**와 **판정 결과 모델** 절에서 다룹니다.
- **최소 개입** — 파이프라인은 사용자 입력이 꼭 필요한 지점(동적 테스트 동의 등) 외에는 멈추지 않고 자동으로 수렴합니다. Phase 1↔Phase 2 불일치도 차단 대신 감사 로그(`conflicts`)로만 남깁니다.

## 실행 흐름

아래 다이어그램은 전체 흐름을 한눈에 보여줍니다. 각 단계의 상세 설명은 바로 다음 절에 있습니다.

```mermaid
flowchart TD
    User["사용자: /noah-8719:sast"] --> S1["Step 1: 실행 경로 확정"]
    S1 --> S2["Step 2: 패턴 인덱싱"]
    S2 --> S3["Step 3: 프로젝트 스택 파악"]
    S3 --> S4["Step 4: 스캐너 선별\n(다국어 의존성 + AI 검토)"]
    S4 --> S5["Step 5: 정적 분석\n(그룹 병렬 → 파일 저장)"]
    S5 --> BML2["phase1_build_master_list.py\n결과 검증 + master-list.json"]
    BML2 --> S6["Step 6: AI 자율 분석\n(내부 3단계)"]
    S6 --> MLUpdate2["master-list.json 갱신\n(Phase 1 + AI 후보 통합)"]
    MLUpdate2 --> S7["Step 7: 정적·AI 리뷰\n(phase1-review, blind eval)"]
    S7 -->|DISCARD| ML_Safe["status: safe\n(Phase 2 낭비 방지)"]
    S7 -->|CONFIRM / OVERRIDE| Check{후보 발견?}
    ML_Safe --> Check
    Check -->|0건| S12["Step 12: 보고서 생성\n+ safe 분류 자동 섹션"]
    Check -->|1건+| S81["Step 8-1: 동적 테스트 정보 요청\n(URL_PROVIDED + ATTACK_CONSENT 분리)"]
    S81 --> S82["Step 8-2: 도구 권한 확인"]
    S82 --> AttackCheck{ATTACK_CONSENT\n동적 공격 동의?}

    AttackCheck -->|Yes| LLMCheckY{LLM 그룹 활성?}
    LLMCheckY -->|Yes| S83Full["Step 8-3: LLM endpoint probe\nprobe_mode = full\n(정적 + 동적 + system override)"]
    LLMCheckY -->|No| S84Plain["Step 8-4: Phase 2 실행\n비-LLM 스캐너만 본 검증"]
    S83Full --> S84Mixed["Step 8-4: Phase 2 실행 (Tier A/B/C 병렬)\n- LLM 스캐너: probe 성공 → 본 검증 / 실패 → placeholder\n- 비-LLM 스캐너: 정상 본 검증 (LLM probe 결과 무관)"]

    AttackCheck -->|No| LLMCheckN{LLM 그룹 활성?}
    LLMCheckN -->|Yes| S83Lite["Step 8-3: LLM endpoint probe\nprobe_mode = connectivity-only or static-only\n(URL_PROVIDED 여부로 자동 선택)"]
    LLMCheckN -->|No| S12
    S83Lite --> S12

    S84Plain --> S9["Step 9: 동적 분석 리뷰\n(phase2-review)"]
    S84Mixed --> S9
    S9 -->|불일치 감사 로그| Conflicts["phase1_eval_state.conflicts\n(append-only)"]
    Conflicts --> ChainCheck
    S9 --> ChainCheck{"안전 제외\n후보 2건+?"}
    ChainCheck -->|Yes| S10["Step 10: 연계 분석"]
    ChainCheck -->|No| S11
    S10 --> S11["Step 11: 결과 검증"]
    S11 --> S12
    S12 --> ReviewCheck{"후보 1건+?"}
    ReviewCheck -->|Yes| Review["Step 12-1: report-review\n보고서 본문 품질 개선"]
    ReviewCheck -->|No| Finalize
    Review --> Finalize["Step 12-2: report_finalize.py\n(html → validate → lint → links → open)"]

    style User fill:#e94560,stroke:#e94560,color:#fff
    style S6 fill:#e94560,stroke:#e94560,color:#fff
    style MLUpdate2 fill:#0f3460,stroke:#e94560,color:#eee
    style S7 fill:#0f3460,stroke:#e94560,color:#eee
    style S9 fill:#0f3460,stroke:#e94560,color:#eee
    style Review fill:#0f3460,stroke:#e94560,color:#eee
    style Conflicts fill:#0f3460,stroke:#e94560,color:#eee
    style ML_Safe fill:#533483,stroke:#533483,color:#fff
    style S10 fill:#533483,stroke:#533483,color:#fff
    style Finalize fill:#e94560,stroke:#e94560,color:#fff
    style Check fill:#533483,stroke:#533483,color:#fff
    style ChainCheck fill:#533483,stroke:#533483,color:#fff
    style ReviewCheck fill:#533483,stroke:#533483,color:#fff
    style AttackCheck fill:#533483,stroke:#533483,color:#fff
    style LLMCheckY fill:#533483,stroke:#533483,color:#fff
    style LLMCheckN fill:#533483,stroke:#533483,color:#fff
```

## 단계별 상세 설명

위 다이어그램의 각 단계가 실제로 무엇을 하는지 순서대로 설명합니다.

### 준비 단계 (Step 1–4)

**Step 1 · 실행 경로 확정**
스캔 대상 경로와 결과를 저장할 임시 디렉토리를 정합니다. 이전 스캔이 중단된 상태라면 이 단계에서 이어서 진행할지(resume)를 판단합니다.

**Step 2 · 패턴 인덱싱**
스캔을 시작하기 전에 코드베이스 전체를 **한 번만** 훑어, 각 스캐너의 semgrep 룰이 매치되는 위치를 미리 색인합니다(`semgrep_index.py`). 개별 스캐너가 같은 코드를 반복해서 뒤지는 낭비를 막습니다. 비-UTF8(EUC-KR 등) 파일도 UTF-8로 변환해 한국어 레거시 코드의 누락을 방지하며, 룰이 없는 의미 분석형 스캐너(business-logic 등)는 빈 색인으로 처리됩니다.

**Step 3 · 프로젝트 스택 파악**
언어·프레임워크·인증 방식·DB 종류·프록시 구성 등 모든 스캐너가 공통으로 필요로 하는 프로젝트 정보를 먼저 수집합니다.

**Step 4 · 스캐너 선별**
49개 스캐너 중 이 프로젝트에 해당하는 것만 고릅니다. 매니페스트(`package.json`, `requirements.txt`, `pom.xml`, `Gemfile` 등)에서 의존성을 파싱해 자동 선별하고(`select_scanners.py`), AI가 한 번 더 검토해 놓친 스캐너를 복원합니다. **"포함이 기본, 제외에는 근거가 필요"** 원칙으로 동작합니다.

### Phase 1 · 정적 분석 (Step 5–7)

**Step 5 · 정적 분석**
선별된 스캐너를 의미적 연관성에 따라 그룹으로 묶어 **병렬 실행**합니다. 각 스캐너는 Step 2의 색인을 출발점으로 위험 지점(sink)과 입력 출처(source)를 추적해 취약점 후보를 찾고, 결과를 파일로 저장합니다. 이후 `phase1_build_master_list.py`가 결과를 검증해 `master-list.json`을 만듭니다.

**Step 6 · AI 자율 분석**
정해진 패턴에 얽매이지 않고 AI가 코드를 직접 읽으며, 스캐너가 구조적으로 놓치기 쉬운 취약점(비즈니스 로직 결함, 인가 흐름, Race Condition 등)을 자율적으로 탐색합니다. 발견한 후보는 `master-list.json`에 통합됩니다.

**Step 7 · phase1-review (정적·AI 결과 리뷰)**
**독립된 리뷰 에이전트**가 Step 5–6이 적어 둔 "후보 사유"를 보지 않은 채 코드와 증거만으로 다시 판정합니다(blind eval). 명백한 오탐은 여기서 `safe`로 떨궈 동적 테스트 낭비를 막고, 살아남은 후보만 Phase 2로 넘깁니다. 구체적인 판별 논리는 아래 **Safe-by-Proof** 절에서 다룹니다.

### Phase 2 · 동적 검증 (Step 8–11)

> 후보가 한 건도 없으면 Phase 2를 건너뛰고 바로 보고서(Step 12)로 갑니다.

**Step 8 · 동적 분석**
실제로 실행 중인 대상에 페이로드를 보내 후보를 검증하는 단계로, 네 부분으로 나뉩니다.
- **8-1 정보 요청** — 테스트 대상 URL과 *공격 동의(ATTACK_CONSENT)* 를 사용자에게 일괄로 묻고 응답을 기다립니다. URL 제공 여부와 공격 동의는 별개로 관리됩니다.
- **8-2 도구 권한 확인** — curl·Playwright 등 동적 테스트 도구의 사용 권한을 미리 확인합니다.
- **8-3 그룹 사전 단계** — LLM 취약점 스캐너 그룹이 활성일 때만, LLM endpoint를 식별·확정하는 probe를 먼저 실행합니다(동의·URL 조합에 따라 full / connectivity-only / static-only 모드 자동 선택).
- **8-4 Phase 2 실행** — 인증 컨텍스트에 따라 스캐너를 Tier A/B/C로 나눠 병렬로 동적 테스트를 수행합니다.

**Step 9 · phase2-review (동적 결과 리뷰)**
동적 테스트가 수집한 증거를 해석해 각 후보의 최종 상태(`confirmed`/`candidate`/`safe`)를 확정합니다. 정적 주장과 동적 증거가 충돌하면 동적 증거를 따르며, 불일치는 `conflicts` 감사 로그에 누적 기록만 합니다.

**Step 10 · 연계 분석**
안전하게 제외하기 애매한 후보가 2건 이상이면, 개별로는 낮은 위험이라도 **연결하면 실제 공격이 되는 체인**을 구성해 영향을 재평가합니다.

**Step 11 · 결과 검증**
최종 상태와 증거의 정합성을 점검해 보고서 생성 직전 마지막으로 검증합니다.

### 마무리 · 보고서 (Step 12)

**Step 12 · 보고서 생성**
확정된 결과를 보고서로 조립합니다. `safe`로 분류된 항목도 버리지 않고 **왜 안전한지**(safe 분류 6종)와 함께 별도 섹션으로 남깁니다.
- **12-1 report-review** — 후보가 있으면 보고서 본문의 설명·스니펫·PoC를 다듬어 품질을 높입니다(판정 자체는 바꾸지 않음).
- **12-2 검증·변환·열기** — `report_finalize.py`가 HTML 변환 → 스키마 검증 → 내부 용어 린트 → 링크 점검 → 열기를 한 번에 처리합니다.

## Phase 1 후보 분류 방법 (Safe-by-Proof)

이 절은 **Phase 1이** 매치 한 건을 후보 또는 안전으로 **어떻게 분류하는지**를 설명합니다(분류 결과가 최종적으로 어떤 라벨로 확정되고 누가 정하는지는 다음 절 **판정 결과 모델**에서 다룹니다). 분류는 한 번의 판정이 아니라 여섯 개의 층을 차례로 통과하는 깔때기 구조이며, 각 층은 서로 다른 종류의 오분류를 잡아냅니다. 특히 정탐을 안전으로 잘못 떨구는 미탐(놓침)을 막는 데 초점이 있습니다.

이 구조를 관통하는 원칙은 세 가지입니다.

> 1. **입증책임 역전** — 모든 매치를 일단 "취약"으로 간주하고, "안전"으로 분류하려면 증거를 제시하게 합니다. 의심스럽거나, 증명할 수 없거나, 아직 확인하지 못한 경우는 모두 후보로 남깁니다.
> 2. **삭제 대신 순위 매기기** — "안전"으로 분류해도 목록에서 지우지 않습니다. 가장 낮은 신뢰 등급으로 내려둘 뿐이며, 검토 인벤토리와 동적 진단의 입력으로 계속 남습니다.
> 3. **비대칭 (놓침을 더 무겁게)** — 후보로 남기는 비용은 낮게, 안전으로 단정하는 비용은 높게 설계했습니다. 오탐은 뒤 단계에서 걸러낼 수 있어 회복 가능하지만, 정탐을 놓치면 되돌릴 수 없기 때문입니다.

### 여섯 층 깔때기

```
semgrep 매치(tier+rule_ids) → [1]tier 분기 → [2]의무 판정 → [3]볼륨 전수처리
   → [4]master-list → [5]블라인드 재판정 → [6]기계 게이트 → Phase 2 동적 확정
```

### 각 판별 방법

**[1] tier 자동 분기** (`decision-framework.md §1`)
semgrep이 매치를 찾아낸 방식에 따라 신뢰도를 세 등급으로 나눕니다. 같은 토큰이라도 어떻게 탐지됐는지에 따라 신뢰도가 달라지기 때문입니다.
- `taint` — 데이터 흐름 분석이 사용자 입력(source)에서 위험 지점(sink)까지 도달하는 경로와, 그 사이에 정화 처리(sanitizer)가 없다는 사실까지 모두 확인한 경우입니다. 신뢰도가 가장 높아 자동으로 후보가 되며, 에이전트가 다시 판단하지 않습니다(판정이 흔들리는 것을 막습니다).
- `ast` — 언어 파서가 실제 구문을 매치한 경우로, 주석이나 문자열 안의 오매치는 걸러집니다. 위치는 정확하지만 입력의 출처와 정화 여부는 아직 모르므로 추가 검토가 필요합니다.
- `generic` — 정규식으로 글자만 맞춰본 경우입니다. 주석·문자열·비슷한 이름까지 매치되어 노이즈가 많고, 신뢰도가 가장 낮습니다.

**[2] 의무 모델 O1~O4** (`§2-D`)
어떤 매치를 "안전"으로 분류하려면 아래 네 가지 의무를 **모두 증거로 충족**해야 합니다. 하나라도 충족하지 못하면 후보로 남깁니다.
| 의무 | 안전으로 인정받는 조건 | 충족 못 하면 후보 |
|---|---|---|
| O1 입력 비제어 | 입력이 상수·내부 생성·이미 검증된 값임을 입증 | 외부 입력 경로에 닿아 있음 |
| O2 도달 가능성 | sink가 진입점에서 도달 불가능함을 입증 | 람다·리플렉션·2차 흐름 등 분석 엔진이 추적하지 못하는 구간은 "도달 불가"가 아니라 "확인 못 함" |
| O3 정화 처리 | 유효한 정화 처리가 모든 경로를 덮는다는 것을 입증 | 일부만 막거나, 우회 가능하거나, 적용 안 된 경로가 있음 |
| O4 위험성 | 그 위치가 실제 위험 지점이 아님을 입증 | 위험한 동작이 실제로 존재함 |

**[3] 볼륨 전수 처리** (`§6-A-2` 커버리지 + `§2-D` 의무)
매치가 수천에서 수만 건에 이르더라도 한 건도 빠짐없이 설명해야 합니다. 노이즈는 같은 성격끼리 묶어 근거와 함께 한꺼번에 제외하되, `eval`·`system`·`innerHTML`처럼 그 자체로 위험한 토큰은 묶어서 버릴 수 없고 하나하나 판정합니다. 안전한 것과 위험한 것이 한 묶음에 섞여 있으면, 그 묶음을 통째로 제외해서는 안 됩니다.

**[4] 관례 일탈(deviance) 신호** (`§2-D 원칙4`)
코드베이스가 스스로 지키는 다수의 관례가 곧 그 코드의 명세입니다. 대부분의 위치는 방어를 갖췄는데 일부만 빠졌다면, 그 일부는 신뢰도 높은 후보입니다(대표 사례가 `IDOR_ASYMMETRIC`). 다수가 안전하다는 사실이 그 예외의 안전을 증명해 주지는 않기 때문입니다.

**[5] 블라인드 재검토** (`phase1-review`)
독립된 에이전트가 Phase 1이 적어 둔 "후보 사유"를 보지 않은 채, 코드와 증거만으로 다시 판정합니다(유지·번복·폐기). 앞의 [2][3]에서 분류 자체가 틀린 경우를 잡아내는 단계입니다.

**[6] 기계 게이트** (`tools/phase1_review_assert.py`, 위반 시 종료 코드 7로 차단)
`locindex`를 기준값으로 삼아, 우회하거나 축소 신고할 수 없도록 "빠짐없음"을 강제합니다. 세 가지를 검사합니다.
- **커버리지 감사** — 고볼륨 스캐너가 모든 매치를 설명했는지 확인합니다.
- **의무 감사** — capability 스캐너가 위험 토큰을 한 건도 빠짐없이 판정했는지 확인합니다(아래 표).
- **taint-safe 감지** — 가장 신뢰도 높은 taint 매치를 안전으로 분류했다면, 정당한 사유와 증거가 있는지 확인합니다.

> **두 종류의 보장이 함께 작동합니다.** [1][3][6]은 기계가 강제하는 "빠짐없음(완전성)"을 책임지고, [2][4][5]는 사람과 모델이 판단하는 "분류의 정확성"을 책임집니다. 완전성만으로는 부족합니다. 실제로 PHP의 `eval` 295건을 "전부 클라이언트 JS"라고 설명해 게이트는 통과했지만, 분류가 틀려 원격 코드 실행을 놓친 적이 있고, 이를 블라인드 재검토가 잡아냈습니다. 그래서 두 보장을 직렬로 쌓습니다.

### 스캐너별 적용 방법

49개 스캐너는 모두 위의 여섯 층을 공통으로 거칩니다([3] 커버리지 감사는 매치가 200건을 넘을 때 적용됩니다). 아래는 스캐너마다 달라지는 부분입니다.

**A. 능력형 — 기계 게이트가 전수 판정을 강제 (6개)**
매치 자체가 위험한 동작의 존재를 뜻하는 스캐너입니다. 위험 토큰을 묶어서 버릴 수 없고, 게이트가 한 건도 빠짐없이 판정하도록 강제합니다.

| 스캐너 | taint 룰 | sink 룰 | 게이트 방식 |
|---|---|---|---|
| command-injection | 4 | 5 (php/ruby/python/java/kotlin) | sink 룰 매치를 집계 |
| xss | 4 | 2 (js/ts) | sink 룰 매치를 집계 |
| ssti | 3 | 3 (java/kotlin/ruby) | sink 룰 매치를 집계 |
| dom-xss | 1 | 2 (js/ts) | sink 룰 매치를 집계 |
| code-injection | 3 | — | ast 등급 전체를 집계 (eval·assert) |
| deserialization | 3 | — | ast 등급 전체를 집계 (unserialize·readObject) |

> code-injection과 deserialization은 ast 등급 자체가 곧 위험 토큰(eval 등)이라 ast 전체를 집계합니다. 반면 xss·ssti·command-injection·dom-xss는 넓은 패턴이 만드는 ast에 노이즈가 수천 건 섞이므로(예: `Template(` 생성자, 출력 컨텍스트, `@RequestParam`), 고정밀 `-sink` 룰로 위험 토큰만 따로 집계합니다. 실측으로 ssti는 넓은 ast 1131건 가운데 sink가 1건, command-injection은 897건 가운데 0건이었습니다.

**B. 부재형 — 있어야 할 검증이 빠졌는지 탐지**
위험 지점(sink)이 따로 없어 토큰 기반 게이트를 쓸 수 없고, "있어야 할 검증이 누락됐는가"를 찾습니다.

| 스캐너 | 판별 방법 |
|---|---|
| idor | taint 룰(java/kotlin, 외부 입력 어노테이션 7종을 source로 인식) + **`idor_inventory.py` 두 모드**(taint 원장 + 컨트롤러 전수 스캔) + 게이트 범위 적정성 확인 + 관례 일탈 신호 |
| csrf | `protect_from_forgery` 적용과 그 예외(`skip`) 추적 |
| business-logic / validation-logic | locindex 없이 코드 의미를 분석(상태 전이, 대량 할당, 검증 비대칭) |

**C. 주입형 — taint 위주로, 위험한 형태만 후보**
위험 토큰이 위험한 형태(문자열 보간·연결, 사용자가 정한 host)로 쓰일 때만 후보로 올립니다. 파라미터 바인딩이나 상수 host처럼 안전한 형태는 증거를 붙여 제외합니다.

| 스캐너 | taint 룰 수 |
|---|---|
| sqli | 6 (최다) |
| ssrf · path-traversal | 5 · 5 |
| open-redirect · xxe | 3 · 3 |
| crlf-injection · ldap-injection · xpath-injection | 2 |
| nosqli · file-upload | 1 · 0 |

**D. 공통 층과 패턴 룰로만 검토 (나머지 약 30개)**
taint나 sink 룰 없이 패턴(ast)·generic 룰과 공통 층으로 검토합니다. 상당수가 설정 점검형이며, "플랫폼이나 인프라가 알아서 막아 줄 것"이라고 단정하지 않고, 확인되지 않으면 후보로 남깁니다(`PLATFORM_DEFENSE`).
`tls` · `security-headers` · `cookie-security` · `springboot-hardening` · `http-smuggling` · `sourcemap` · `subdomain-takeover` · `host-header` · `http-method-tampering` · `csv-injection` · `jwt` · `oauth` · `saml` · `redos` · `prototype-pollution` · `graphql` · `websocket` · `xslt-injection` · `soapaction-spoofing` · `android-deeplink` · `zipslip` · `pdf-generation` · `prompt-injection` · `system-prompt-leakage` · `insecure-output-handling` · `unbounded-consumption` · `css-injection`

## 판정 결과 모델 (status·태그·안전분류)

> Phase 1·Phase 2 양쪽에 걸친 **결과 라벨 체계**입니다. 앞 절(Safe-by-Proof)이 Phase 1의 분류 *과정*을 다뤘다면, 이 절은 그 결과가 최종적으로 **어떤 라벨로 확정되고 누가 정하는지**를 정의합니다.

후보의 최종 상태는 `master-list.json`의 `status` 필드로 결정되며, **`scan-report-review` 서브스킬이 단일 writer**입니다. Phase 1·Phase 2 에이전트는 증거만 수집하고 상태를 직접 할당하지 않습니다.

### 1) status 3종

| status | 의미 | 결정 시점 |
|--------|------|----------|
| `confirmed` | 동적 테스트 또는 결정적 증거로 취약점이 실증됨 | phase2-review |
| `candidate` | 동적 검증이 미완·차단·생략된 상태(상태 미확정) | phase1-review / phase2-review |
| `safe` | 명시적 방어 또는 영향도 부재로 후보 폐기 | phase1-review / phase2-review |

### 2) safe 분류 (`safe_category` 6종)

`status=safe`이면 반드시 분류 명시 — 단순 "안전"이 아닌 **왜 안전한지**를 표현합니다.

| 값 | 정의 | 대표 근거 |
|----|------|---------|
| `no_external_path` | 공격자가 해당 코드로 HTTP 요청을 보낼 수 없음 | dev-only 프록시, 서버 번들 비노출, 내부 전용 라우트 |
| `defense_verified` | 공격 페이로드를 실제 전송했으나 방어 코드가 차단 | nginx 차단, 프레임워크 이스케이프, 게이트웨이 재작성 |
| `not_applicable` | 공격 경로는 존재하나 취약점의 핵심 요건이 부재 | 민감정보 0건, 공개 자원이라 보호 대상 아님 |
| `false_positive` | Phase 1이 지적한 코드가 실제로는 취약점 sink가 아님 | 설정 지시자 오인, 다른 메커니즘으로 방어 존재 |
| `platform_default_defense` | 대상 브라우저·런타임·HTTP 표준이 동등 효과 방어 제공 | IETF RFC 표준 기본 차단, 주요 브라우저 최근 2개 메이저 기본값 |
| `architectural_rationale_only` | 다른 후보의 경로 증명용 독립 항목 (자체 조치 대상 아님) | chain 분석의 영향 경로 증거 |

### 3) candidate 태그 (`tag` enum)

`status=candidate`는 반드시 사유 태그를 동반합니다. 두 태그 조건이 동시 해당하면 아래 **우선순위**에 따라 한 개만 부여하고, 부여되지 못한 사유는 `evidence_summary`에 함께 기술합니다.

| 우선순위 | tag | 의미 | 적용 그룹 |
|---------|-----|------|---------|
| 1 | `LLM endpoint 미확보` | LLM probe 실패로 endpoints 빈 산출물 | LLM 그룹 한정 |
| 2 | `LLM endpoint 정적 식별` | (N, N) static-only 모드 — 동적 호출 없음 | LLM 그룹 한정 |
| 3 | `LLM endpoint 확인됨` | (Y, N) connectivity-only — 공격 페이로드 미시도 | LLM 그룹 한정 |
| 4 | `동적 분석 생략` | 사용자가 동적 테스트 명시적 거부 | 비-LLM 그룹 |
| 5 | `차단` | WAF/게이트웨이 등이 모든 변형 차단 | 공통 |
| 6 | `환경 제한` | sandbox 환경 제한으로 일부 페이로드 수행 불가 | 공통 |
| 7 | `도구 한계` | curl/Playwright 등 도구 실패로 검증 부분 실패 | 공통 |
| 8 | `정보 부족` | 외부 콜백 URL 등 필요 정보 없어 검증 미완 | 공통 |

### 4) 판정 워크플로 (3단계)

```
Phase 1 (스캐너 정적 탐색)
   ↓ 후보 도출
phase1-review (blind eval)
   ↓ ✓ 유지 (CONFIRM/OVERRIDE) → Phase 2 진입
   ↓ ✗ 폐기 (DISCARD)          → status=safe + safe_category (조기 종료, Phase 2 낭비 방지)
Phase 2 (동적 검증)
   ↓ 증거 수집 (status 부여 X)
phase2-review (증거 해석)
   ↓ confirmed / candidate+tag / safe+safe_category 확정
```

### 5) 핵심 판정 원칙

- **Source 도달성 의미 기반 판정** — *"이 값을 외부 행위자가 의도적으로 다르게 만들 방법이 코드 외부에 존재하는가?"* 한 줄 질문으로 평가. 패턴 목록·enum 의존 금지. 입증 불가는 불명확 케이스로 **보수적으로 유지**.
- **부재 주장 검증** — "검증 없음"을 주장하려면 sink ±30줄 + 호출자 체인 + 프레임워크 내장 방어 + 전역 필터까지 Read로 실제 확인. 함수명이 아닌 효과 기준.
- **Phase 2 우선 원칙** — Phase 1 정적 주장과 Phase 2 동적 증거가 모순되면 항상 Phase 2 증거로 status 확정. 불일치는 `phase1_eval_state.conflicts`에 append-only 감사 로그로만 기록.
- **blind eval** — phase1-review/phase2-review는 Phase 1 결과의 "후보 사유"를 보지 않고 코드와 evidence만으로 독립 판정 (편향 차단). 판정이 Phase 1과 일치하면 CONFIRM, 다르면 OVERRIDE·DISCARD.
- **단일 writer 권한** — `confirmed`/`candidate`/`safe` 부여는 phase2-review만, `phase1_validated`/`phase1_discarded_reason`은 phase1-review만, `tag="동적 분석 생략"`은 사용자 거부 경로의 메인 에이전트만. 권한 위반은 assert 스크립트가 차단.

상세 규칙은 `skills/sast/sub-skills/scan-report-review/_principles.md`(판정 원칙)와 `_contracts.md`(writer 권한·스키마·매트릭스) 참조.

## 스캐너 목록

| # | 스캐너 | 취약점 유형 | 그룹 |
|---|--------|-----------|------|
| 1 | xss-scanner | Cross-Site Scripting (Reflected/Stored) | url-navigation |
| 2 | dom-xss-scanner | DOM-based XSS | url-navigation |
| 3 | open-redirect-scanner | Open Redirect | url-navigation |
| 4 | crlf-injection-scanner | CRLF Injection / HTTP Response Splitting | response-header |
| 5 | host-header-scanner | Host Header Attack / IP Spoofing | response-header |
| 6 | http-method-tampering-scanner | HTTP Method Tampering | response-header |
| 7 | sqli-scanner | SQL Injection | db-query |
| 8 | nosqli-scanner | NoSQL Injection | db-query |
| 9 | command-injection-scanner | OS Command Injection | process-execution |
| 10 | code-injection-scanner | Code Injection (eval/assert) | process-execution |
| 11 | ssti-scanner | Server-Side Template Injection | process-execution |
| 12 | ssrf-scanner | Server-Side Request Forgery | server-request |
| 13 | pdf-generation-scanner | PDF Generation SSRF/LFI | server-request |
| 14 | path-traversal-scanner | Path Traversal / LFI | file-system |
| 15 | file-upload-scanner | Unrestricted File Upload | file-system |
| 16 | zipslip-scanner | Zip Slip (Archive Path Traversal) | file-system |
| 17 | xxe-scanner | XML External Entity | xml-serialization |
| 18 | xslt-injection-scanner | XSLT Injection | xml-serialization |
| 19 | deserialization-scanner | Insecure Deserialization | xml-serialization |
| 20 | jwt-scanner | JWT Tampering | auth-protocol |
| 21 | oauth-scanner | OAuth Authentication Bypass | auth-protocol |
| 22 | saml-scanner | SAML Authentication Bypass | auth-protocol |
| 23 | csrf-scanner | Cross-Site Request Forgery | auth-protocol |
| 24 | idor-scanner | Insecure Direct Object Reference | auth-protocol |
| 25 | redos-scanner | Regular Expression DoS | client-rendering |
| 26 | css-injection-scanner | CSS Injection | client-rendering |
| 27 | prototype-pollution-scanner | Prototype Pollution | client-rendering |
| 28 | http-smuggling-scanner | HTTP Request Smuggling | infra-config |
| 29 | sourcemap-scanner | Source Map Exposure | infra-config |
| 30 | subdomain-takeover-scanner | Subdomain Takeover | infra-config |
| 31 | csv-injection-scanner | CSV / Formula Injection | data-export |
| 32 | graphql-scanner | GraphQL Vulnerabilities | protocol-check |
| 33 | websocket-scanner | WebSocket Vulnerabilities | protocol-check |
| 34 | soapaction-spoofing-scanner | SOAPAction Spoofing | protocol-check |
| 35 | ldap-injection-scanner | LDAP Injection | protocol-check |
| 36 | xpath-injection-scanner | XPath Injection | protocol-check |
| 37 | security-headers-scanner | Security Headers (CSP, CORS, HSTS 등) | infra-config |
| 38 | business-logic-scanner | Business Logic Vulnerabilities | business-logic |
| 39 | springboot-hardening-scanner | Spring Boot Hardening (설정 보안) | infra-config |
| 40 | cookie-security-scanner | Cookie Security (Secure, HttpOnly, Persistent 등) | auth-protocol |
| 41 | tls-scanner | TLS/SSL Misconfiguration | infra-config |
| 42 | validation-logic-scanner | Validation Logic Mismatch | business-logic |
| 43 | prompt-injection-scanner | LLM Prompt Injection (Direct/Indirect) | llm |
| 44 | system-prompt-leakage-scanner | LLM System Prompt Leakage | llm |
| 45 | insecure-output-handling-scanner | LLM Insecure Output Handling | llm |
| 46 | unbounded-consumption-scanner | LLM Unbounded Consumption | llm |
| 47 | android-deeplink-scanner | Android Deeplink / WebView | mobile |

## 디렉토리 구조

```
noah-8719/
├── .claude-plugin/
│   └── plugin.json                # 플러그인 매니페스트
├── hooks/
│   └── hooks.json                 # 보안 후크
├── skills/
│   └── sast/
│       ├── SKILL.md               # 오케스트레이터 (실행 프로세스 상세)
│       ├── scanners/              # 49개 취약점 스캐너 (각 phase1.md + phase2.md)
│       ├── prompts/               # 서브 에이전트 지시 문서 (LLM 그룹 사전 단계 포함)
│       ├── tools/                 # Python 유틸리티 스크립트 (LLM 채널 어댑터 포함)
│       ├── sub-skills/            # 내부 서브스킬
│       │   ├── scan-report/       # 보고서 생성
│       │   ├── scan-report-review/# 보고서 정확성 검증
│       │   └── chain-analysis/    # 공격 체인 연계 분석
│       └── tests/
├── install.sh
├── uninstall.sh
├── VERSION
├── LICENSE
└── README.md
```

## 상세 문서

| 문서 | 경로 | 내용 |
|------|------|------|
| 오케스트레이터 | `skills/sast/SKILL.md` | 전체 실행 프로세스 (Step 1~12), 스캐너 그룹 편성, 동적 분석 Tier, 결과 검증 |
| Phase 1 공통 지침 | `skills/sast/prompts/guidelines-phase1.md` | Sink-first + Source-first 분석, 래퍼 추적, 의미 기반 판정, Source 도달성 |
| Phase 2 공통 지침 | `skills/sast/prompts/guidelines-phase2.md` | 동적 테스트 절차, 에러 핸들링, 차단 응답 처리, 도메인 안전 규칙 |
| AI 자율 탐색 | `skills/sast/prompts/ai-discovery-agent.md` | 3단계 자율 탐색, 7개 제외 필터, Phase 1 충돌 해소 |
| LLM 그룹 사전 단계 | `skills/sast/prompts/llm-endpoint-probe-agent.md` | LLM endpoint 식별·확정 (probe_mode: full / connectivity-only / static-only). LLM 4개 스캐너 Phase 2의 단일 입력 계약 생성 |
| LLM 채널 어댑터 | `skills/sast/tools/llm_channel_probe.py` | HTTP / ws-raw / ws-stomp / SSE 단일 어댑터. probe-agent와 Phase 2가 공유하는 헬퍼 (의존성: `websocket-client`, `requests`) |
| 보고서 생성 | `skills/sast/sub-skills/scan-report/SKILL.md` | 스켈레톤 → 병렬 작성 → 조립 → HTML 변환 → 검증. safe 분류(6종) 섹션 자동 생성 |
| 평가·리뷰 (dispatcher) | `skills/sast/sub-skills/scan-report-review/SKILL.md` | 3모드 진입점 안내. 모드별 파일을 직접 Read하도록 오케스트레이션 |
| └ 공통 판정 원칙 | `skills/sast/sub-skills/scan-report-review/_principles.md` | Source 도달성, 부재 주장, 반환 형식 규칙 |
| └ 공통 계약 | `skills/sast/sub-skills/scan-report-review/_contracts.md` | Writer 권한 matrix, exit code, master-list.json 스키마, DISCARD 보호 |
| └ Phase 1 품질 평가 | `skills/sast/sub-skills/scan-report-review/phase1-review.md` | blind eval, 5축 독립 판정(축 5: 현실 영향 가중치), DISCARD 시 Phase 2 낭비 방지 |
| └ Phase 2 증거 해석 | `skills/sast/sub-skills/scan-report-review/phase2-review.md` | Phase 2 우선 원칙, status 확정, `conflicts` 감사 로그 |
| └ 보고서 본문 품질 개선 | `skills/sast/sub-skills/scan-report-review/report-review.md` | 조립된 MD 본문 설명 보강 — 스니펫·POC 교정, 중복 통합, 원인 분석·권장 조치 보강 (판정 필드 불변) ([3모드 상세 가이드](skills/sast/docs/review-modes.md)) |
| 연계 분석 | `skills/sast/sub-skills/chain-analysis/SKILL.md` | R1~R5 체인 구성 규칙, 전제조건/연계 매트릭스 |
| 개별 스캐너 | `skills/sast/scanners/{name}/phase1.md` | Sink 의미론, 안전 패턴, 판정 의사결정, 자주 놓치는 패턴 |
