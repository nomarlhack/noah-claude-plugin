# semgrep 인덱싱과 Phase 1 분석 상세

## 1. 전체 흐름 개요

```
프로젝트 소스코드
        ↓
semgrep_index.py (Step 2)
        ↓
<scanner>.locindex.json (스캐너별)
        ↓
locindex_summary.py (Phase 1 에이전트가 Bash로 실행)
        ↓
파일 목록 (파일당 1줄, 2000줄 이내)
        ↓
파일별 Read → source→sink 추적 → 후보 등록
```

---

## 2. semgrep 인덱싱 (semgrep_index.py)

### 2-1. semgrep이 만드는 raw JSON

semgrep을 실행하면 매칭 항목당 이런 구조가 나옵니다:

```json
{
  "check_id": "noah-javascript-xss-phase1-pattern",
  "path": "/path/to/NowRender.js",
  "start": {"line": 22, "col": 22},
  "end":   {"line": 22, "col": 30},
  "extra": {
    "lines": "this.$nowList.append(jQuery(list.map((item) => {",
    "severity": "WARNING"
  }
}
```

- `check_id` — 어느 룰에 매칭됐는지
- `path` + `start.line` — 파일 경로와 라인 번호
- `extra.lines` — 매칭된 코드 한 줄

### 2-2. semgrep_index.py가 하는 일

raw JSON을 받아 스캐너별로 두 파일을 생성합니다.

**① `<scanner>.json` — 평평한 인덱스**

룰 ID별로 매칭 위치 목록을 저장합니다.

```json
{
  "noah-javascript-xss-phase1-pattern": [
    "/path/NowRender.js:22",
    "/path/B.Profile.js:296",
    ...
  ],
  "noah-java-spring-xss-taint": [
    "/path/ArticleController.java:313",
    ...
  ]
}
```

**② `<scanner>.locindex.json` — 위치 중심 인덱스**

같은 위치(파일:라인)에 여러 룰이 매칭되면 1개로 합치고, 신뢰도가 높은 tier로 승격합니다.

```json
{
  "_scanner": {
    "name": "xss-scanner",
    "has_taint": true,
    "tier_counts": {"taint": 379, "ast": 3310, "generic": 1049}
  },
  "locations": {
    "/path/NowRender.js:22": {
      "rule_ids": ["noah-javascript-xss-phase1-pattern", "noah-xss-phase1-pattern"],
      "tier": "ast",
      "severity": "WARNING"
    },
    "/path/ArticleController.java:313": {
      "rule_ids": ["noah-java-spring-xss-taint"],
      "tier": "taint",
      "severity": "ERROR"
    }
  }
}
```

### 2-3. tier 결정 규칙

룰 ID 이름으로 tier를 자동 결정합니다.

| 룰 ID 패턴 | tier | 의미 |
|---|---|---|
| `...-taint` | `taint` | semgrep dataflow 분석으로 source→sink 흐름 확정 |
| `...-sink` | `ast` (고신뢰) | 실제 위험 함수(innerHTML 등) 정밀 매칭 |
| `...-pattern` | `ast` | 언어 파서 기반 매칭, source/sanitizer 미확인 |
| generic regex | `generic` | 정규식 매칭, 최저 신뢰도 |

같은 위치에 taint + ast가 동시에 걸리면 → tier는 `taint`로 승격, rule_ids에는 둘 다 보존.

### 2-4. 결과 규모 (brunch 프로젝트 기준)

| 스캐너 | 매칭 건수 | locindex 줄 수 |
|---|---|---|
| xss-scanner | 4,738건 | 36,861줄 |
| idor-scanner | 5,370건 | 39,705줄 |
| unbounded-consumption | 8,788건 | 66,129줄 |
| **전체 합계** | **66,910건** | — |

locindex.json은 파일 크기가 커서 Read 도구(2,000줄 제한)로 직접 읽으면 JSON 파싱이 실패합니다.

---

## 3. locindex_summary.py

locindex.json을 Phase 1 에이전트가 소화할 수 있는 크기로 변환합니다.

### 3-1. 하는 일

1. locindex.json을 Python으로 읽음
2. 노이즈 경로 제거 (`vendor/`, `.min.js:`, `.yaml:`, 룰 파일 자기 매칭 등)
3. 남은 항목을 **파일명 기준으로 그룹핑**
4. 파일별로 best_tier / taint 건수 / ast 건수 / generic 건수 집계
5. sink 룰(`-sink`, `-taint` 이름 포함) 매칭 여부 → `[SINK]` 표시
6. 정렬: taint → ast → generic, 동 tier 내 taint 건수 내림차순
7. stdout으로 출력 (파일 저장 없음)

### 3-2. 출력 형식

```
=== xss-scanner 매칭 파일 요약 ===
총 4738건 → 실제 3824건 / 노이즈 제거 914건
tier: taint=379 ast=3310 generic=1049
파일 수: 510개

best_tier    t     a     g  파일명
----------------------------------------------------------------------
taint       39   140     0  ArticleController.java [SINK]  (3개 경로)
taint       31    22     0  EventController.java [SINK]
...
ast          0     2     0  B.Sign.SignupConfirm.js [SINK]
ast          0     1     0  NowRender.js
...
generic      0     0     2  DonateSuccessModal.svelte
...

[노이즈 제거] 914건 (ast=8 generic=906) — vendor/min/YAML/룰파일
```

- **파일 수 기준으로 전 47개 스캐너에서 2,000줄 이내가 보장**됩니다. (가장 큰 스캐너도 파일 수 ~2,000개 이하)
- `(N개 경로)` — 같은 파일명이 여러 디렉토리에 있을 때 표시

### 3-3. 사용법

Phase 1 에이전트가 Bash로 실행합니다. 파일로 저장하지 않고 stdout을 바로 읽습니다.

```bash
python3 <NOAH_SAST_DIR>/tools/locindex_summary.py \
  <PATTERN_INDEX_DIR>/<scanner-name>.locindex.json
```

---

## 4. Phase 1 분석 상세

### 4-1. 에이전트가 받는 입력

각 그룹 에이전트는 다음을 받습니다:

- `phase1.md` — 스캐너별 sink 의미론 / 안전 패턴 / 판정 기준
- `locindex_summary.py` 실행 명령 — 파일 목록 확보용
- 결과 파일 경로 — 분석 결과를 저장할 위치

### 4-2. 분석 순서

**① locindex_summary.py 실행**

파일 목록을 확보합니다.

**② [SINK] 파일 우선 분석**

sink 룰 직접 매칭 파일입니다. 실제 XSS sink 함수(`innerHTML`, `.html($Y)` 등)가 있는 파일이므로 우선 Read합니다.

```
B.Sign.SignupConfirm.js [SINK]
  → Read → $userNameError.html(r.responseJSON.desc) 확인
  → source 추적: r.responseJSON.desc = 서버 하드코딩 메시지
  → FALSE_POSITIVE
```

**③ taint 파일 분석**

semgrep dataflow 분석이 source→sink 흐름을 확정한 파일입니다.

```
ArticleController.java (taint 39건)
  → Read → @RequestParam String title 확인 (source)
  → sink까지 경로 추적: DB 저장 → /v1/article/recent → NowRender.js
  → NowRender.js Read → jQuery.append(template_literal) 확인 (sink)
  → XSS-1 후보 등록
```

**④ ast 파일 분석**

파일당 1회 Read해서 패턴 의미를 확인합니다. 대부분은 `@RequestParam` 선언부(source이지만 sink 아님) 또는 안전한 패턴으로 FALSE_POSITIVE 처리됩니다.

**⑤ generic 파일 분석**

정규식 매칭 파일입니다. 클래스 판정으로 대량 제외가 가능합니다.

```
DonateSuccessModal.svelte (generic 2건)
  → Read → {@html title} 확인
  → has_taint=true이나 generic도 검토 (FN 방지)
  → source 추적: articleTitle → DonationCommentCompleteMessage → title
  → XSS-2 후보 등록
```

**⑥ Source-first 추가 탐색**

locindex에 없는 파일에서 추가 패턴을 grep으로 탐색합니다.

### 4-3. COVERAGE 감사

200건 초과 스캐너는 결과 파일에 전체 매칭 건수를 어떻게 처리했는지 기록해야 합니다.

```
<!-- COVERAGE matches=4738 accounted=4738 method="
  taint 379건 전수 분석(admin 게이트, DB 파생값),
  sink JS 380건(vendor 52 제외, admin-only 76 제외, 2건 후보),
  generic 1049건(Svelte 자동 escape, vm 정적 문자열),
  노이즈 914건 포함" -->
```

`phase1_review_assert.py` 게이트가 `accounted == matches`를 기계로 검증합니다. 설명되지 않은 잔여가 있으면 exit 7로 차단합니다.

---

## 5. 관련 파일

| 파일 | 역할 |
|---|---|
| `tools/semgrep_index.py` | semgrep 실행 + locindex.json 생성 |
| `tools/locindex_summary.py` | locindex.json → 파일 목록 요약 |
| `tools/phase1_review_assert.py` | COVERAGE 감사 게이트 |
| `prompts/phase1-group-agent.md` | Phase 1 에이전트 지시 (Bash 실행 방법 포함) |
| `prompts/guidelines-phase1.md` | Phase 1 분석 공통 지침 (§6-A-1 locindex 사용법) |
