# Phase 1 소스코드 분석 에이전트 공통 지침

Phase 1(소스코드 분석)을 에이전트로 실행할 때 따르는 공통 지침이다.

> `[필수]`는 과거 위반 이력이 있어 추가 강조된 항목이다. 태그가 없는 항목도 모두 준수 의무가 있다.

## 지침 0: 결정 프레임워크 필수 참조

**[필수] 진입 즉시 `<NOAH_SAST_DIR>/prompts/decision-framework.md`를 Read하라.** 매치 1건마다의 "후보 vs 안전" 판정은 본 가이드라인의 절차(역추적/부재 검증)와 함께 **decision-framework.md의 7단계**(tier 분기 → sink 정합 → 객관 사실 체크리스트 → 라벨 → 트리거 4단계 → 통합/분리)를 적용한다. 이것이 LLM 변동성을 줄이는 단일 진실 원천이다. 각 스캐너 phase1.md는 sink/source 의미론만 정의하고, 분류 로직은 decision-framework.md를 따른다.

## 지침 1: 보고서 파일 생성 금지

**보고서 파일(.md, .html)을 절대 생성하지 않는다. 분석 결과는 `<PHASE1_RESULTS_DIR>/<scanner-name>.md` 경로에만 작성한다 (지침 3 참조).**

## 지침 2: 개별 스캐너 phase1.md의 유의사항 준수

**[필수] 해당 스캐너의 phase1.md를 반드시 읽고, 그 안의 유의사항(판정 기준 등)을 그대로 따른다.**

## 지침 3: 모든 후보 빠짐없이 파일에 작성

**Phase 1에서 발견된 모든 후보를 빠짐없이 구조화된 형식으로 결과 파일에 작성한다. 중요도가 낮다고 판단하여 생략하지 않는다.**

**각 스캐너의 분석 결과를 Write 도구로 `<PHASE1_RESULTS_DIR>/<scanner-name>.md`에 저장한다.** 반환 메시지에는 분석 전문을 포함하지 않는다.

### 3-A: 후보 작성 형식

각 후보는 `## <ID>: <제목>` 헤더로 시작하며, 아래 5개 필수 섹션을 포함한다. **[필수] `## ` (h2) 레벨은 후보 전용이다. 체크리스트 항목, "제외" 판정 항목 등 후보가 아닌 분석 내용은 `### ` (h3) 이하 레벨만 사용한다.**

| 섹션 | 최소 길이 | 내용 |
|------|----------|------|
| `### Code` | 20자 | 파일 경로:라인 번호 + 취약 코드 스니펫 |
| `### Source→Sink Flow` | 50자 | 데이터 흐름 경로 (Source에서 Sink까지). **Source는 사용자 제어 가능한 실제 입력 채널이어야 한다 — 역추적이 내부 상수에서 멈추면 후보가 아님(지침 8).** |
| `### Validation Logic` | 80자 | 확인한 검증/방어 로직 (없으면 부재 근거) |
| `### Trigger Conditions` | 80자 | **decision-framework.md §4 트리거 4단계(T1~T3) 중 1개 명시** + `실제 경로:` (라우트 파일 근거 포함). T4는 후보 아님(제외). |
| `### Decision` | 40자 | "후보" + **decision-framework.md §3 표준 라벨 1개 이상** (예: `DIRECT`, `SECOND_ORDER`, `DEFENSE_BYPASS`, `IDENTIFIER` 등) + 근거. 안전 판정 시 `NO_PATH`/`FALSE_POSITIVE`/`PLATFORM_DEFENSE` 라벨로 `safe_category` 매핑. |
| `### locindex tier` | 1줄 | locindex의 `tier` 값(`taint`/`ast`/`generic`) + `rule_ids` 인용. tier=taint면 §6-D-3 단축 절차 적용 근거. |

**ID 규칙:** 해당 스캐너의 `phase1.md` frontmatter `id_prefix` 값을 그대로 사용한다 (예: xss-scanner의 `id_prefix: XSS` → `XSS-1`, open-redirect-scanner의 `id_prefix: OREDIR` → `OREDIR-1`). 스캐너명에서 임의 추론 금지 — frontmatter 값이 단일 진실 공급원. 후보 번호는 스캐너 내 순번이다 (XSS-1, XSS-2, ...).

### 3-B: Manifest 블록 (파일 끝 필수)

**[필수] 모든 결과 파일의 끝에 manifest 블록을 포함한다.** `phase1_build_master_list.py`가 이 블록으로 구조 검증을 수행한다.

형식:
- 첫 줄: `<!-- NOAH-SAST MANIFEST v1 -->`
- JSON 코드 블록 (` ```json ` ... ` ``` `)
- 마지막 줄: `<!-- /NOAH-SAST MANIFEST -->`

manifest JSON 필드:
- `declared_count`: 파일 내 후보 수 (정수). `## <ID>:` 헤더 수와 반드시 일치.
- `candidates`: 후보 배열. 각 요소: `id`, `title`, `file`(경로), `line`(정수), `url_path`, `source`, `sink`, `test_prereq`(없으면 null).

**[필수] `url_path` 반드시 채울 것**: `url_path`는 `phase1_build_master_list.py`가 인증경계(`auth_boundary`)를 자동 파생하는 유일한 입력이다. 비워두면 보고서 취약점 요약 테이블의 인증경계 열이 공백으로 렌더링된다. 컨트롤러 매핑(`@RequestMapping`, `@GetMapping` 등)에서 확정한 HTTP 경로를 `METHOD /path/template` 형식으로 기재한다 (예: `GET /jude/link/{linkId}/preview`, `POST /chatbot/writeFeed`). URL 경로를 확인할 수 없을 때만 `null`을 허용한다.

**후보 ID 규약**: 각 스캐너의 `phase1.md` frontmatter에 선언된 `id_prefix` 값을 사용하여 `<id_prefix>-1, <id_prefix>-2, ...` 형식으로 순서대로 부여한다. 예: `id_prefix: XSS`이면 `XSS-1, XSS-2, ...`. 스스로 prefix를 추론하지 않는다. 불일치 시 `phase1_build_master_list.py`가 ERROR로 차단.

**카테고리 헤더 규약**: 스캐너 정의 문서(`phase1.md`)에서 취약점 유형을 구분할 때 `### V-1`, `### D-1` 같은 **숫자+하이픈 형식을 사용하지 않는다**. 카테고리 이름(UPPER_SNAKE_CASE)을 그대로 헤더로 쓴다. 숫자+하이픈 형식은 후보 ID 전용으로 예약되어 있어 혼동을 일으킨다.

**이상 없음인 경우에도 파일을 생성**하고, 이상 없음 항목 1줄 요약 + `{"declared_count": 0, "candidates": []}` manifest를 포함한다.

### 3-C: 반환 형식

**파일 저장 후, 반환 메시지에는 스캐너별 후보 건수 요약만 포함한다.** 아래는 반환 예시이다:

```
xss-scanner: 후보 2건
dom-xss-scanner: 이상 없음
open-redirect-scanner: 후보 1건
```

## 지침 4: 심각도 평가 금지

**취약점에 심각도(High, Medium, Low, Critical 등)를 부여하지 않는다. 상태는 "후보" 또는 "안전"으로만 구분한다.**

## 지침 5: 이상 없음 스캐너도 파일 생성 필수

**[필수] 해당 스캐너에서 후보가 없고 이상 없음 판정인 경우에도 결과 파일을 생성한다.** "이상 없음 항목" 1줄 요약 + `declared_count: 0` manifest를 포함한다.

## 지침 6: Phase 1 분석 대상 확정 — Sink-first + Source-first 병행

Phase 1 분석은 세 단계로 구성된다. 모두 수행해야 한다.

### 6-A: Sink-first 분석 (필수 하한선)

**[필수] 패턴 인덱스 파일에서 추출한 파일 목록은 반드시 전수 분석한다. 이것은 분석 범위의 하한선(최소 대상)이다.**

프롬프트에 제공된 패턴 인덱스 파일 경로를 Read 도구로 읽어 패턴별 파일경로:라인번호 목록을 추출하고, 이를 필수 분석 대상으로 확정한다.

**인덱스 JSON 키의 의미** — 키는 semgrep 룰 ID이며, 룰 종류(pattern/taint)에 따라 매치의 신뢰도와 후속 검증 단계가 다르다 (구체적 차이는 §6-D-3 참조):

| 키 형태 | 출처 | 매치의 의미 |
|---|---|---|
| `noah-<lang>-...-pattern` (예: `noah-kotlin-sqli-annotation`) | `semgrep_index.py` pattern 룰 (AST 매칭) | sink 호출 위치만 매치하되 언어 파서가 적용되어 주석/문자열 내부 false match는 제외됨. source/sanitizer는 미확인. |
| `noah-<lang>-...-taint` (예: `noah-kotlin-spring-sqli-taint`) | `semgrep_index.py` taint 룰 (dataflow 분석) | 사용자 입력 source → sink + sanitizer 부재가 룰엔진의 dataflow 분석으로 확정됨. high-signal 후보. |

#### 6-A-1: tier 우선순위 검토 (locindex 사이드카가 있을 때)

`semgrep_index.py`는 패턴 인덱스(`<scanner>.json`)와 함께 **위치 중심 사이드카 `<scanner>.locindex.json`**을 생성한다. locindex는 같은 file:line의 다중 룰 매치를 1개 위치로 병합하고 최고 tier로 승격하되 `rule_ids` 배열로 모든 매치 룰을 보존한다.

**[필수] locindex는 Read 도구로 직접 읽지 않는다.** 파일이 수만 줄에 달해 Read 2,000줄 제한으로 JSON 파싱이 실패하기 때문이다. 대신 `phase1-group-agent.md §3`에 명시된 대로 `locindex_summary.py`를 Bash로 실행하여 파일별 요약을 얻는다:

```bash
python3 <NOAH_SAST_DIR>/tools/locindex_summary.py <PATTERN_INDEX_DIR>/<scanner>.locindex.json
```

출력은 매칭 파일 목록(파일별 1줄)으로, `_scanner.has_taint` / `tier_counts` / `[SINK]` 표시를 포함한다. **검토 순서:**

1. **`[SINK]` 표시 파일** — sink 룰(innerHTML-sink 등) 직접 매치. 우선 Read하여 실제 sink 코드와 source 추적.
2. **`best_tier=taint` 파일** — dataflow source 도달성 + sanitizer 부재 확정. §6-D-3 단축 절차 적용.
3. **`best_tier=ast` 파일** — 언어 파서로 위치는 정밀하나 source/sanitizer 미확인. 파일당 1회 Read로 패턴 의미 확인.
4. **`best_tier=generic` 파일** — regex 매치, 최저 신뢰. 클래스 판정 후 대량 제외 가능.

**`has_taint == false` 시 (generic/ast만 있는 스캐너):** ast·generic이 유일 신호이므로 전수 분석한다. 후순위·상한 적용 금지.

**`has_taint == true` 시:** taint·ast 파일을 먼저 처리한 뒤 generic 파일을 검토한다. 컨텍스트 예산 소진 시 남은 generic 파일을 `[INCOMPLETE: generic-tier N개 파일 미검토 — <scanner>]`로 표기한다.

locindex가 없으면 평평한 패턴 인덱스 JSON을 Read하여 전수 분석한다.

#### 6-A-2: 커버리지 감사 (고볼륨 스캐너 필수)

매치가 많은 스캐너는 에이전트가 컨텍스트 한계로 **일부만 보고 나머지를 조용히 누락**하는 위험이 있다(실측: sqli generic 9858건을 "sample"하고 0 후보로 종결 — §6-A-1의 "전수 분석" 지시가 강제되지 않음). "전수 분석"이 물리적으로 불가능한 볼륨에서도 **누락이 보이게** 만들기 위해, 총 매치 **200건 초과** 스캐너의 결과 MD에는 **커버리지 감사**를 반드시 포함한다. 핵심 원칙은 **"모든 매치를 설명한다(account for all)"** — 개별 검토하든 클래스로 묶어 제외하든, 설명 안 된 매치가 **0**이어야 한다. "일부 봤더니 괜찮더라"는 금지.

결과 MD에 다음 주석을 1줄 포함한다(기계 검증용, `phase1_review_assert.py`가 파싱):

```
<!-- COVERAGE matches=<총매치수> accounted=<설명한수> method="<좁히기 방법 요약>" -->
```

- `matches`: locindex `_scanner.tier_counts` 합(총 매치 수).
- `accounted`: 개별 검토 + 클래스 단위 제외로 **설명한** 매치 수. `matches`와 같아야 한다(잔여 0).
- `method`: 어떻게 좁혔는지 한 줄 (예: `"DB driver import grep=0 → 전 매치 JS 템플릿 리터럴 클래스"`, `"Source-first 재grep으로 진짜 sink 52건 식별, 나머지 587건은 source·무관 함수 클래스"`).

그리고 본문에 **클래스별 제외 근거**를 적는다(나머지 매치가 왜 일괄 제외 가능한지 — 클래스명 + 근거 + 대표 예 1~2건). 클래스 단위 제외가 narrowing의 핵심이다: 9858건을 일일이 안 봐도 "전부 X 클래스이고 X는 sink 의미 불성립"이면 9858건 전부 설명된 것이다.

**taint 매치가 많은 경우(50건 초과)**: taint는 dataflow로 확정된 고신뢰 매치라 드롭하면 곧 미탐이다. 전수를 ledger로 나열해 `accounted`에 포함한다. IDOR은 `tools/idor_inventory.py`가 ledger를 기계 생성하므로 그 출력을 결과에 포함하면 충족된다. 다른 스캐너도 동일 원칙(taint 매치는 클래스 일괄 제외로 뭉뚱그리지 말고 전수 나열).

설명 못 한 잔여가 불가피하면 버리지 말고 `accounted`를 실제 설명한 수로 정직히 적고 본문에 `[INCOMPLETE: <scanner> 미검토 N건]`을 표기한다(메인 에이전트가 후속 처리). 감사가 막는 것은 "잔여의 존재"가 아니라 "잔여가 보이지 않는 것"이다.

#### FILE-PRESENCE: 파일 단위 disposition (결정/방어 스캐너 필수)

**적용 대상**: ssrf·open-redirect·path-traversal·ssti·idor·business-logic·validation-logic·host-header·csrf·file-upload·xxe·command-injection·code-injection·deserialization·xpath-injection·ldap-injection·prototype-pollution·pdf-generation (이하 **결정/방어 스캐너**).

이 스캐너들의 취약점은 **taint로 표현되지 않는 경우가 흔하다**. 두 가지 일반 사유:
- **sink가 분석 범위 밖**(다른 레포·다른 서비스)이라 범위 내 source→sink 경로가 끊긴다.
- 결함이 "오염 데이터가 sink에 도달"이 아니라 **"방어 결정 자체가 틀림"**(불완전 검사·검사시점과 사용시점 불일치·예외 경로의 허용 기본값)이라 dataflow로 모델링되지 않는다.

그래서 §6-A-2가 비용상 일괄 제외를 허용하는 **ast/generic 칸**에 진짜 취약점이 숨고, 파일명이 결과 MD에 등장조차 않은 채 클래스 캐치올에 흡수돼 미탐된다.

**규칙**: 이 스캐너들은 **인덱스가 매치한 파일을 클래스로 뭉개지 못한다.** 인덱스가 매치한 *모든 distinct 파일*은 결과 MD에 **파일명을 적고 개별 disposition**(후보 / 안전 / 무관 + 근거 1줄)해야 한다. 어떤 파일이 중요한지의 판단은 분석자 몫이며, 경로·확장자로 *미리 거르지 않는다* — 노이즈로 보이는 파일도 파일명을 적고 "무관 + 사유 1줄"로 빠르게 처리하면 된다(막는 것은 판단이 아니라 *침묵*이다).

결과 MD에 다음 주석을 1줄 포함한다(기계 검증용, `phase1_review_assert.py`가 파싱):

```
<!-- FILE_PRESENCE files=<총파일수> accounted=<명시한파일수> method="<처리 방식 한 줄>" -->
```

- `files`: locindex distinct 파일 수 (스크립트가 직접 계산 — 에이전트 선언과 불일치 시 스크립트 값 우선).
- `accounted`: 개별 명시한 파일 수. `files`와 같아야 한다(잔여 0). 불가피하면 `[INCOMPLETE]` 표기.
- `method`: 어떻게 처리했는지 한 줄 (예: `"서버 결정 23개 개별 Read, 클라이언트 .tsx 51개 1줄 무관, 문서 .mdx 55개 1줄 무관"`).

- 비용은 **매치 수가 아니라 파일 수**다(매치가 수천이어도 distinct 파일은 보통 그보다 훨씬 적다). 명백한 노이즈는 1줄로 빠르게 dispose하므로 깊이는 분석자가 배분한다.
- 외부 입력에 대해 allow/deny/transform **결정을 내리는 코드**(검증기·게이트·sanitizer)는 "검증이 존재함 = 안전"으로 종결하지 말고, 그 결정이 **옳은지**를 확인한다 — 일반 점검 축: ① 검사한 값과 최종 사용/전송한 값이 동일한 변수인가(불일치 시 TOCTOU), ② 예외·기본·단락 경로의 결과가 허용(allow)인가(fail-open), ③ 차단·허용 목록이 리터럴 열거형이면 입력 공간 대비 누락 원소가 있는가. 이 축들은 망라 목록이 아니라 출발점이며, 결정 코드면 유형 불문 적용한다.
- `phase1_review_assert.py`가 locindex의 distinct 파일 집합 ∩ MD 미명시를 기계 검증한다(FILE-PRESENCE 위반 시 exit 7). 파일명(basename)이 MD에 등장만 해도(후보·안전·무관 어느 판정이든) 충족 — 막는 것은 "이름조차 안 적고 묶어서 사라지는 것"이다.

### 6-B: Source-first 분석 (추가 탐색)

Sink-first 분석 완료 후, Source-first 탐색을 수행한다.

1. 해당 스캐너의 취약점 유형에 해당하는 사용자 입력 Source 패턴을 프로젝트에서 Grep한다.
2. 각 Source에서 값이 전달되는 함수 호출을 추적하여, 패턴 인덱스에 없는 Sink로 흘러가는 경로가 있는지 확인한다.
3. 새로 발견된 후보는 Sink-first 결과와 함께 반환한다.
4. 추가 후보가 없으면 "Source-first 추가 탐색: 추가 후보 없음"으로 명시한다.

**[필수] 모든 판정은 패턴 목록이 아닌 의미(semantic) 기반으로 한다.** phase1.md의 `Sink 의미론` / `Source-first 추가 패턴` / `안전 패턴 (FP Guard)` / `자주 놓치는 패턴` / `후보 판정 의사결정` 표는 모두 대표 예시이며 전체 목록이 아니다. 판정 기준은 의미적 효과이다:

- **Sink**: "이 함수에 공격자 입력이 도달하면 취약점이 발생하는가?"
- **Source**: "이 채널을 외부 행위자가 직접 또는 간접 제어할 수 있는가?" — 카탈로그에 없는 동등 채널(새 프레임워크의 입력 데코레이터, 새 프로토콜 메시지, 외부 쓰기 가능한 저장소 등)도 Source로 인정한다.
- **안전 패턴**: "이 메커니즘이 공격자 입력의 위험성을 효과적으로 제거하는가?" — 카탈로그에 없는 동등 효과 메커니즘도 안전으로 인정한다 (예: Svelte/Solid/Astro 자동 escape, 별도 컨테이너 격리, 외부 AV 스캔).
- **자주 놓치는 패턴**: "이 코드 형태가 의미상 같은 취약 흐름을 만들어내는가?" — 카탈로그에 없는 변형(난독화, 별칭, 새 빌드 도구 출력 등)도 동일 의미면 후보로 등록한다.
- **의사결정 표**: 표에 없는 조건 조합이라도 동일 원칙으로 판정한다. "표에 없음"을 이유로 보류하거나 기본값으로 후보를 폐기하지 않는다.

**남용 방지**: "효과적으로 제거" 판단은 §9-B(부분 검증은 "검증 없음"이 아니다)와 §10(트리거 조건의 현실성 평가)으로 재검증한다. 의미적 동등성의 근거(어떤 공격 벡터를 어떻게 차단하는지)를 후보/제외 판정 문구에 명시한다.

**[필수] 경로 추적 시 검증 로직도 함께 확인한다.** Source→Sink 경로를 추적할 때, 중간에 존재하는 검증/방어 로직(validate, sanitize, encode, 프레임워크 내장 방어, DTO의 validate() 등)을 반드시 확인한다. Source가 사용자 직접 입력이 아닌 경우(DB 저장값, 관리자/파트너 등록 데이터 등), 해당 데이터의 등록 경로까지 추적하여 등록 시점의 검증 로직도 확인한다. 확인한 검증 로직은 후보 판정 결과에 포함한다.

### 6-C: 호출부(Call-site) 추적 — 실제 URL 경로 확정

> **이 지침은 모든 스캐너 phase1.md에 자동 적용된다.** 개별 phase1.md 상단에 더 이상 인라인으로 기재하지 않는다.

**[필수] 모든 후보에 대해 라우트 정의 파일을 Read로 읽어 실제 URL 경로를 확정한다. 컴포넌트/파일 이름에서 경로를 유추하는 것은 확정이 아니다.**

절차:
1. Sink의 호출부를 Grep → 최종 페이지 컴포넌트/컨트롤러 식별
2. 라우트 정의(routes/index.tsx, @RequestMapping 등)를 Read로 읽어 경로 문자열 확인
3. 후보 반환 시 근거 포함: `실제 경로: /home/apply (src/routes/index.tsx:42)`

### 6-D: 5단계 분석 골격 (모든 스캐너 공통)

각 스캐너 phase1.md는 아래 5단계 골격을 따른다는 것을 가정한다. phase1.md는 이 골격의 산문을 반복하지 않고, 스캐너 고유 의미만 정의한다.

1. **Source 식별** — phase1.md의 "Source-first 추가 패턴" 섹션 + 일반 사용자 입력 채널(파라미터, 헤더, 바디, DB 저장값 등) (목록은 대표 예시 — §6-B 의미-기반 원칙 적용)
2. **Sink 식별** — 패턴 인덱스(6-A) + phase1.md의 "Sink 의미론" 섹션
3. **경로 추적** — Source→Sink, 검증/방어 로직 확인. phase1.md의 "안전 패턴" 섹션 참조 (목록은 대표 예시 — §6-B 의미-기반 원칙 적용). 검증 없이 직관으로 후보를 버리지 않는다. **Sink의 실제 인자를 변수 체인으로 역추적하여 최초 대입 지점을 확인하고, 대입 지점이 사용자 제어 가능한 Source(파라미터/헤더/바디/DB 저장값 등)에 도달하는지 확정한다(Source 도달성). 대입 지점이 컴파일 타임 상수·하드코딩 리터럴·내부 생성값(UUID, 서버 시간, 고정 내부 ID 등)에서 멈추면 후보가 아니다 — 지침 8 참조.**

   **semgrep taint 룰(`noah-<lang>-...-taint`) 매치에 한한 단축 절차** — dataflow 분석이 Source 도달성과 sanitizer 부재를 이미 확정했으므로, 아래 두 작업은 생략한다:
   - **Sink 인자의 변수 체인 역추적**: 룰의 `pattern-sources` 정의(컨트롤러 입력 어노테이션 등)가 매치한 변수에서 sink까지의 흐름이 보장되므로 재추적 불필요.
   - **Sink 함수 ±30줄 sanitizer Read (§9-A)**: 룰의 `pattern-sanitizers` 어디에도 매치되지 않은 흐름이 보고된 것이므로 재확인 불필요.

   그 대신 결과 파일의 섹션 작성 시 룰 근거를 인용한다:
   - `### Source→Sink Flow`: 룰의 source 항목명을 명시 (예: `@RequestParam name`(Spring 컨트롤러 입력) → `JdbcTemplate.query` (UserController.kt:21) — semgrep taint 룰 `noah-kotlin-spring-sqli-taint`가 dataflow 확정).
   - `### Validation Logic`: "semgrep taint 룰 `<rule-id>`의 pattern-sanitizers 목록 어디에도 매치되지 않음 — sanitizer 부재. 코드에 `.toInt()`/`PreparedStatement.setString`/named parameter map이 없음을 dataflow가 확인" 식으로 근거를 명시.

   **단축이 적용되지 않는 단계** — taint 매치라 하더라도 아래는 동일하게 수행한다:
   - §6-C(호출부 추적 — URL 경로 확정): semgrep은 컨트롤러 메서드는 알지만 URL 매핑 문자열은 모름. 라우트 정의 Read 필수.
   - §6-E(래퍼 함수 재귀 추적): semgrep taint는 함수 내부 dataflow에 강하지만 cross-function/cross-file 추적은 약함. sink가 헬퍼/유틸리티에 있으면 호출부 Grep 보강.
   - §9-B(부분 검증 의미 분석): 룰의 sanitizer 목록에 없지만 코드에 다른 형태의 검증(부분 화이트리스트, 타입 캐스팅, 정규식 매칭 등)이 있는 경우, 그 의미를 기술. 룰이 잡지 못한 안전 메커니즘을 놓치지 않기 위함.
   - §10(트리거 조건의 현실성): 룰엔진은 코드 도달성만 확인. 실제 라우트 노출 여부·인증 게이트·인프라 차단은 에이전트가 평가.

   **`pattern` 룰(`noah-<lang>-...-pattern`) 매치**: 위 단축 절차 미적용. 변수 체인 역추적과 sanitizer ±30줄 Read를 전부 수행한다.
4. **모호 케이스 처리** — phase1.md의 "후보 판정 의사결정" 섹션 (표에 없는 조건 조합은 §6-B 의미-기반 원칙으로 판정)
5. **후보 정리** — phase1.md의 "후보 판정 제한" 한 줄 기준

**프로젝트 스택 파악은 메인 에이전트가 SKILL.md Step 3에서 수행하여 그룹 에이전트 프롬프트로 전달한다. 개별 phase1.md는 스캐너 고유 라이브러리/설정 점검만 담당하며, 일반 스택 파악 단계를 반복하지 않는다.**

### 6-E: 래퍼 함수 재귀 추적 (Sink 간접 호출 탐지)

패턴 룰은 직접적인 Sink 호출만 잡는다. 래핑 함수, 별칭, 유틸리티 함수를 통한 간접 호출은 패턴 인덱스에 나타나지 않는다.

**절차 (Sink-first 분석 후 수행):**

1. **래퍼 식별**: 패턴 인덱스에서 발견된 각 Sink에 대해, Sink를 포함하는 함수의 이름을 추출한다.
   ```
   예: innerHTML을 사용하는 함수 → function setContent(el, html) { el.innerHTML = html; }
   → "setContent"가 래퍼 함수
   ```

2. **호출부 역추적**: 추출한 래퍼 함수명을 프로젝트에서 Grep하여 호출부를 찾는다. 이 호출부에서 사용자 입력이 인자로 전달되는지 확인한다.

3. **재귀 확장**: 래퍼 함수가 다시 다른 함수에서 호출되는 경우, 최대 3단계까지 재귀적으로 추적한다. 3단계 이상은 비용 대비 효과가 낮으므로 중단한다.

4. **별칭 탐지**: 래퍼 함수가 변수에 재할당되거나 export 별칭이 있는 경우(`const render = setContent`, `export { setContent as render }`) 해당 별칭도 Grep 대상에 포함한다.

**적용 범위**: Sink-first 분석(6-A)에서 발견된 Sink가 **유틸리티/헬퍼 파일**에 위치한 경우에만 수행한다. Sink가 컨트롤러/핸들러/컴포넌트에 직접 있으면 래퍼 추적이 불필요하다.

**결과 반환**: 래퍼 추적으로 새로 발견된 후보는 `[래퍼 추적]` 라벨을 붙여 기존 후보와 구분한다.

---

## 지침 7: 이미 읽은 파일 재읽기 금지

**[필수] 여러 스캐너를 순서대로 실행하는 경우, 이전 스캐너 분석에서 이미 Read한 파일은 다시 읽지 않는다.** 컨텍스트에 이미 내용이 있으므로 재읽기는 토큰 낭비이다.

---

## 지침 8: 후보 판정 제외 기준

다음에 해당하면 후보로 등록하지 않는다.

- 서버 침해, API 응답 변조, MITM 등 외부 전제 조건이 필요한 경우
- 서버에서 동일한 검증이 이미 수행되는 것이 확인된 경우
- 전이 의존성에만 존재하고 소스코드에서 직접 사용하지 않는 경우
- 빌드 스크립트, 테스트 코드, 개발 도구에만 해당하는 경우
- Sink의 실제 인자가 컴파일 타임 상수, 하드코딩 리터럴, 또는 내부적으로만 생성되는 값(UUID, 서버 시간, 내부 ID 등)이며, 변수 역추적 시 사용자 제어 Source에 도달하지 않는 경우 (Source 도달성 실패)

단, 서버 검증 여부를 확인할 수 없는 경우에는 후보로 유지한다.

---

## 지침 9: 부재 주장의 정확성

"검증이 없다", "sanitize하지 않는다", "필터링 없이" 등 **방어 로직의 부재를 주장할 때는 반드시 아래를 확인**한다. 부재 주장은 오탐의 가장 흔한 원인이다.

### 9-A: Sink 주변 컨텍스트 확인

Sink 함수의 전후 ±30줄을 읽는다. **함수명이 아니라 호출의 효과를 기준으로** 입력값을 변형·검증·거부·타입 강제·인코딩·컨텍스트 분리하는 모든 코드를 식별한다. 이름이 `sanitize`/`validate`/`escape` 류가 아니어도 같은 효과를 내는 호출(프레임워크 내장 변환, DTO validator, 정규식 매칭 후 분기, 타입 캐스팅, 파싱 후 enum 매핑, 화이트리스트 비교, ORM 파라미터 바인딩 등)이면 방어로 본다. 함수명 패턴 매칭만으로 "검증 없음"을 결론 내지 말고, 효과 기반 의미 판단을 요구한다. 같은 파일/같은 클래스/호출자 체인의 상위 레이어까지 확인 범위에 포함한다.

**예외**: 매치가 semgrep taint 룰(`noah-<lang>-...-taint`)에서 온 경우 §6-D-3의 단축 절차가 적용되어 ±30줄 Read를 생략한다. 단 §9-B(부분 검증)는 여전히 적용 — 룰의 sanitizer 목록에 들어가지 않은 다른 형태의 부분 검증이 코드에 있을 수 있으므로, 후보 본문 작성 시 그 의미를 함께 기술한다.

**[영향축 대칭] sink의 실제 효과도 함께 확인한다.** sink를 읽을 때 방어(게이트) 유무만 보지 말고, **그 sink가 실제로 무엇을 하는지**도 best-effort로 확인하여 영향(impact)을 거기에 근거해 적는다(과장·과소 둘 다 방지, decision-framework §2-D 원칙 4):
- **조회·공개형(read)**: 반환되는 데이터 구조(응답으로 직렬화되는 구조)에서 실제로 노출되는 필드. 엔드포인트 의미로 PII를 단정하지 말고 구조에 있는 필드로 한정한다.
- **변경·부수효과형(write/side-effect)**: sink가 일으키는 상태 변화나 부수 효과 — 어떤 자원/외부 상태를 어떻게 바꾸거나 작동시키는지.

정적으로 효과를 확인할 수 없으면(반환이 제네릭/Map/projection/vendor 패스스루 등) **"효과 미확인"으로 표기**한다 — 이는 후보 보류 사유가 아니며, 코드 근거 없는 추정은 "추론"으로 라벨한다.

### 9-B: 부분 검증은 "검증 없음"이 아니다

검증 로직이 존재하지만 불완전한 경우 (예: URL 스킴만 화이트리스트, 길이만 제한, 타입만 체크), **"검증 없음"이 아니라 구체적으로 무엇이 검증되고 무엇이 안 되는지**를 기술한다.

나쁜 예: "URL 검증 없이 window.location.href에 할당"
좋은 예: "validateAppLinkScheme()에서 스킴만 화이트리스트 검증. 호스트/경로 검증 없음. https 스킴이 허용되면 임의 도메인으로 리다이렉트 가능"

---

## 지침 10: 트리거 조건의 현실성 평가

후보를 등록할 때, **취약점이 트리거되는 조건이 현실적으로 발생하는지**를 평가하여 기술한다.

예시:
- `remoteAddr ?: xForwardedIp` 패턴에서 `remoteAddr`가 null이 되려면 `getNativeRequest()`가 null을 반환해야 하는데, 일반적인 서블릿 환경에서는 극히 드문 케이스다 → 이를 후보 설명에 명시
- `X-Forwarded-For`를 우선 사용하는 코드에서, 앞단 프록시가 헤더를 덮어쓰는지 여부는 인프라 구성에 의존한다 → 이를 전제조건으로 명시

후보에서 제외하라는 것이 아니라, **독자가 실제 위험도를 판단할 수 있도록 조건의 현실성을 함께 기술**하라는 것이다.

---

## 지침 11: 복수 요소의 전수 반영

**[필수] 하나의 후보가 아래 중 하나에 해당하면, 문제 요소를 모두 후보 제목·소스코드 분석·POC에 반영한다. 대표 항목 하나로 축약하거나 "등"으로 요약하지 않는다.**

- 설정/코드가 복수의 값을 열거하는 경우 (리스트, 배열, 콤마 구분 문자열, 와일드카드)
- 동일 결함이 복수의 파일·라인에서 반복 발견되는 경우

판정 기준(어떤 요소가 문제인지)은 해당 스캐너의 phase1.md를 따른다. 본 지침은 "누락 금지" 원칙만 강제한다.

---

## 지침 12: 카테고리 경계 후보의 독립 등록

하나의 sink가 여러 스캐너의 의미론에 동시에 부합할 수 있다. 어느 한 스캐너에서 후보로 등록했다고 해서 다른 스캐너의 의미 영역에서 누락해도 된다는 뜻은 아니다.

- 동일 코드 지점이 자기 스캐너의 sink 의미론에 정합하면 독립 후보로 등록한다. 다른 스캐너에서 잡힌 후보 ID는 본문에 cross-reference로 짧게 남긴다.
- "다른 스캐너가 이미 잡았으니 우리는 제외"는 후보 판정 사유가 아니다. 누락되면 보고서에서 해당 카테고리가 좁게 보이거나 사라질 수 있다.
- 후보의 본질이 동일 file:line + 동일 권장 조치라면 마스터 목록 빌드 단계의 DUPLICATE SINK 통합 절차를 따른다 — 등록 단계에서 미리 생략하지 않는다.

---

## 공통 유의사항

- **작업 디렉토리에 여러 프로젝트가 존재하더라도, 분석 결과를 프로젝트별로 분리하지 않는다.** 모든 프로젝트의 후보를 하나의 결과 파일 흐름으로 통합한다. 단, 각 후보의 위치(파일 경로)에 프로젝트 디렉토리명을 그대로 유지하여 프로젝트 출처를 식별할 수 있게 한다.
- **"확인됨"은 동적 테스트를 통해서만 부여할 수 있다.** 소스코드 분석만으로는 "확인됨"이 아니라 "후보"이다.

## 인증 경계 교차검증 (v11)

각 후보를 작성하기 전, `<PHASE1_RESULTS_DIR>/auth-boundary.json`의 `routes[]`와 후보 진입 경계를 반드시 매칭한다. SKILL.md Step 3-1에 정의된 M5 매칭 알고리즘 사용 (METHOD 정확 일치 + path 변수 `{...}`·`**`→`*` 정규화 + trailing `/` 제거).

- 매칭 성공: 매칭된 route의 `gateway_id`·`client_ids`·`failure_modes`·`credential_chain`을 본문에 자연어로 인라인 (예: "이 진입은 `oahu-gateway` 게이트웨이의 Bearer 인증을 거쳐 도달하며, `credential_mismatch` 실패 모드가 있음"). 단순 ID 나열은 금지 — 의미를 풀어 설명한다.
- 매칭 실패 (route 부재·`surface_key` 미상): **후보 작성을 중단**하고 반환 요약에 `[INCOMPLETE: auth_boundary:<후보_id>]` 마커를 추가한다. 메인 에이전트는 Step 3-1 fallback을 수행한 뒤 그룹 재실행한다.
- `auth-boundary.json`이 `applicable: false`이면 본 절차를 건너뛰고 진입 경계는 "해당 없음"으로 표기한다.
