# semgrep 인덱싱과 Phase 1 분석

## 전체 흐름

```
① semgrep_index.py
   코드베이스 전체를 한 번 스캔 → 스캐너별 locindex.json 생성

② locindex_summary.py  (Phase 1 에이전트가 Bash로 실행)
   locindex.json → 파일 목록 요약 (파일당 1줄, 2,000줄 이내 보장)

③ Phase 1 에이전트
   파일 목록을 보고 각 파일을 Read → source→sink 추적 → 후보 등록
```

---

## semgrep 인덱싱

### semgrep이 만드는 결과

semgrep은 룰이 매칭될 때마다 다음 정보를 반환합니다.

```json
{
  "check_id": "noah-javascript-xss-phase1-pattern",
  "path": "/path/to/NowRender.js",
  "start": {"line": 22},
  "extra": {
    "lines": "this.$nowList.append(jQuery(list.map((item) => {"
  }
}
```

`semgrep_index.py`는 이 결과를 받아서 스캐너별로 두 파일로 가공합니다.

---

### 생성되는 파일

**`<scanner>.json` — 룰별 위치 목록**

룰 ID를 키로, 해당 룰이 매칭된 위치 목록을 값으로 저장합니다.

```json
{
  "noah-javascript-xss-phase1-pattern": ["NowRender.js:22", "B.Profile.js:296", ...],
  "noah-java-spring-xss-taint":         ["ArticleController.java:313", ...]
}
```

**`<scanner>.locindex.json` — 위치별 매칭 정보**

같은 위치에 여러 룰이 걸리면 1개로 합칩니다. tier는 셋 중 가장 높은 것으로 승격하고, 어떤 룰들이 걸렸는지는 `rule_ids`에 모두 남깁니다.

```json
{
  "_scanner": {
    "name": "xss-scanner",
    "has_taint": true,
    "tier_counts": {"taint": 379, "ast": 3310, "generic": 1049}
  },
  "locations": {
    "NowRender.js:22": {
      "tier": "ast",
      "rule_ids": ["noah-javascript-xss-phase1-pattern", "noah-xss-phase1-pattern"]
    },
    "ArticleController.java:313": {
      "tier": "taint",
      "rule_ids": ["noah-java-spring-xss-taint"]
    }
  }
}
```

---

### tier 의미

tier는 semgrep이 어떤 방식으로 매칭했는지를 나타냅니다. 룰 ID 이름으로 자동 결정됩니다.

| tier | 결정 기준 | 의미 |
|------|-----------|------|
| `taint` | 룰 ID에 `-taint` 포함 | dataflow 분석으로 source→sink 흐름까지 확정. 신뢰도 최고 |
| `ast` | 룰 ID에 `-sink` 또는 `-pattern` 포함 | 언어 파서로 구문 매칭. 위치는 정확하나 source·sanitizer는 미확인 |
| `generic` | 그 외 | 정규식 매칭. 노이즈가 많고 신뢰도 최저 |

---

### 파일 크기 문제

`locindex.json`은 매칭 건수에 비례해 커집니다.

| 스캐너 | 매칭 건수 | locindex 줄 수 |
|--------|-----------|----------------|
| xss-scanner | 4,738건 | 36,861줄 |
| idor-scanner | 5,370건 | 39,705줄 |
| unbounded-consumption | 8,788건 | 66,129줄 |
| **전체 합계** | **66,910건** | — |

Read 도구는 기본 2,000줄 제한이 있습니다. 에이전트가 직접 Read하면 JSON이 잘려 파싱에 실패합니다. 이 문제를 해결하기 위해 `locindex_summary.py`를 사용합니다.

---

## locindex_summary.py

### 하는 일

`locindex.json`을 읽어 **파일 단위로 묶어** 요약합니다.

1. 노이즈 경로 제거 — `vendor/`, `.min.js:`, `.yaml:` 등 실제 프로젝트 코드가 아닌 파일
2. 남은 항목을 파일명 기준으로 그룹핑
3. 파일별 best_tier / taint·ast·generic 건수 집계
4. `-sink` 또는 `-taint` 룰이 걸린 파일에 `[SINK]` 표시
5. 정렬: taint → ast → generic 순, 동 tier 내 taint 건수 내림차순
6. stdout 출력 (파일 저장 없음)

파일 수는 매칭 건수보다 훨씬 적어서, **47개 스캐너 모두 2,000줄 이내가 보장**됩니다.

### 출력 예시

```
=== xss-scanner 매칭 파일 요약 ===
총 4738건 → 실제 3824건 / 노이즈 제거 914건
tier: taint=379  ast=3310  generic=1049
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

[노이즈 제거] 914건 — vendor/min/YAML/룰파일
```

Phase 1 에이전트는 이 출력을 보고 어느 파일을 먼저 Read할지 결정합니다.

### 실행 방법

```bash
python3 <NOAH_SAST_DIR>/tools/locindex_summary.py \
  <PATTERN_INDEX_DIR>/<scanner-name>.locindex.json
```

---

## Phase 1 분석

### 분석 순서

파일 목록을 받은 에이전트는 우선순위에 따라 파일을 Read합니다.

**1) `[SINK]` 파일 — 먼저 확인**

sink 룰이 직접 매칭된 파일입니다. `innerHTML`, `.html($Y)` 등 실제 위험 함수가 있는 파일이므로 가장 먼저 봅니다.

```
B.Sign.SignupConfirm.js [SINK]
  → $userNameError.html(r.responseJSON.desc) 확인
  → source 추적: r.responseJSON.desc = 서버 하드코딩 메시지
  → FALSE_POSITIVE
```

**2) `best_tier=taint` 파일 — source→sink 흐름 확인**

semgrep이 dataflow 분석으로 흐름을 확정한 파일입니다.

```
ArticleController.java  (taint 39건)
  → @RequestParam String title 확인 (source)
  → DB 저장 → /v1/article/recent → NowRender.js 경로 추적
  → NowRender.js: jQuery.append(template_literal) 확인 (sink)
  → 방어 코드 없음 → XSS-1 후보 등록
```

**3) `best_tier=ast` 파일 — 패턴 의미 확인**

파일당 1회 Read해서 실제 sink인지 판단합니다. 대부분은 `@RequestParam` 선언부(source이지 sink 아님)라 FALSE_POSITIVE로 처리됩니다.

**4) `best_tier=generic` 파일 — 클래스 판정**

정규식 매칭이라 노이즈가 많습니다. "이 파일들은 전부 Svelte `{value}` 보간 — 자동 escape" 같은 클래스 판정으로 묶어서 제외할 수 있습니다.

```
DonateSuccessModal.svelte  (generic 2건)
  → {@html title} 확인 — Svelte raw HTML 렌더링 (generic이어도 실제 sink)
  → source 추적: articleTitle → DonationCommentCompleteMessage → title
  → XSS-2 후보 등록
```

**5) Source-first 추가 탐색**

locindex에 없는 파일에서 취약 패턴을 grep으로 직접 탐색합니다. semgrep이 놓친 경로를 보완합니다.

---

### COVERAGE 감사

매칭이 200건을 넘는 스캐너는 전체 건수를 어떻게 처리했는지 결과 파일에 기록해야 합니다. `phase1_review_assert.py` 게이트가 이를 검증하고, 설명되지 않은 잔여가 있으면 exit 7로 차단합니다.

```
<!-- COVERAGE matches=4738 accounted=4738
     method="taint 379건 전수 분석 / sink JS 380건(vendor 52 제외, 2건 후보) /
             generic 1049건(Svelte 자동 escape) / 노이즈 914건" -->
```

---

## 관련 파일

| 파일 | 역할 |
|------|------|
| `tools/semgrep_index.py` | semgrep 실행 → locindex.json 생성 |
| `tools/locindex_summary.py` | locindex.json → 파일 목록 요약 |
| `tools/phase1_review_assert.py` | COVERAGE 감사 게이트 |
| `prompts/phase1-group-agent.md` | Phase 1 에이전트 지시 (§3 Bash 실행 방법) |
| `prompts/guidelines-phase1.md` | Phase 1 분석 공통 지침 (§6-A-1 locindex 사용법) |
