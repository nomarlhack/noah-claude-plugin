# semgrep 인덱싱

Phase 1 그룹 에이전트가 분석을 시작하기 전에 `semgrep_index.py`가 먼저 실행된다. 이 스크립트가 만드는 인덱스 파일이 Phase 1 전체의 단일 진실 원천이다.

---

## 왜 인덱싱이 필요한가

Phase 1 에이전트가 21개 그룹으로 병렬 실행된다. 각 에이전트가 소스코드를 직접 semgrep으로 스캔하면:

- 같은 소스파일을 21번 스캔 → 시간 낭비
- 에이전트마다 결과가 달라질 수 있음 → 비결정성

그래서 **스캔을 1회만 실행해 인덱스로 저장**하고, 각 에이전트는 인덱스를 읽는다.

---

## 전체 흐름

```
소스코드
    │
    ▼
semgrep 룰 실행 (스캐너별 rules/*.yaml)
    │
    ▼
semgrep_index.py
    ├── 룰 ID → tier 분류 (taint / ast / generic)
    ├── 같은 file:line 병합 + tier 승격
    └── 두 파일로 저장
         ├── <scanner>.json        ← 룰별 위치 목록
         └── <scanner>.locindex.json ← 위치별 tier/rule_ids + 스캐너 메타
    │
    ▼
Phase 1 그룹 에이전트
    │  locindex_summary.py로 요약 읽기
    └── 소스 파일 Read → 후보 판정
```

---

## semgrep이 반환하는 것

semgrep은 룰이 매칭될 때마다 아래 정보를 반환한다.

```json
{
  "check_id": "noah-javascript-xss-phase1-pattern",
  "path": "/path/to/render.js",
  "start": { "line": 22 }
}
```

`semgrep_index.py`는 이 결과를 받아 스캐너별로 두 파일로 가공한다.

---

## 출력 파일 2종

### `<scanner>.json` — 룰별 위치 목록

룰 ID를 키로, 매칭된 위치 목록을 값으로 저장한다. Phase 1 에이전트가 특정 룰의 매치 위치를 빠르게 조회할 때 사용한다.

```json
{
  "noah-javascript-xss-phase1-pattern": ["render.js:22", "profile.js:296"],
  "noah-java-xss-taint":                ["ArticleController.java:313"]
}
```

### `<scanner>.locindex.json` — 위치별 매칭 정보

같은 `file:line`에 여러 룰이 걸리면 1개로 병합한다. tier는 가장 높은 것으로 승격하고, 어떤 룰들이 걸렸는지는 `rule_ids`에 모두 남긴다.

```json
{
  "_scanner": {
    "name": "xss-scanner",
    "has_taint": true,
    "tier_counts": { "taint": 379, "ast": 3310, "generic": 1049 }
  },
  "locations": {
    "render.js:22": {
      "tier": "ast",
      "rule_ids": ["noah-javascript-xss-phase1-pattern", "noah-xss-phase1-pattern"]
    },
    "ArticleController.java:313": {
      "tier": "taint",
      "rule_ids": ["noah-java-xss-taint"]
    }
  }
}
```

두 파일의 역할 차이:

| 파일 | 키 | 용도 |
|------|----|------|
| `<scanner>.json` | 룰 ID | 특정 룰의 매치 위치 조회 |
| `<scanner>.locindex.json` | file:line | Phase 1 에이전트가 tier 순서로 분석할 파일 목록 파악 |

---

## tier — 매칭 신뢰도

tier는 semgrep이 어떤 방식으로 매칭했는지를 나타낸다. **룰 ID 이름**으로 자동 결정된다.

| tier | 결정 기준 | 예시 rule ID | 의미 |
|------|----------|-------------|------|
| taint | rule ID가 `-taint`로 끝남 | `noah-java-xss-taint` | dataflow 분석으로 source→sink 흐름 확정. 신뢰도 최고 |
| ast | rule ID가 `-phase1-pattern`으로 끝나고 언어 prefix 있음, 또는 그 외 모두 | `noah-java-xss-phase1-pattern`, `noah-xss-sink-pattern` | 언어 파서로 구문 매칭. 위치는 정확하나 source·sanitizer는 미확인 |
| generic | rule ID가 `-phase1-pattern`으로 끝나고 언어 prefix 없음 | `noah-xss-phase1-pattern` | 범용 정규식 매칭. 언어 무관, 노이즈 많음. 신뢰도 최저 |

"언어 prefix"란 rule ID의 두 번째 토큰이 `java`, `javascript`, `typescript`, `python`, `kotlin`, `go`, `ruby`, `php`, `csharp`, `scala` 중 하나인 경우다.

같은 위치에 taint와 ast가 모두 매칭됐으면 taint로 승격하고, 두 rule_ids를 모두 보존한다.

---

## 스캐너 유형

모든 스캐너가 semgrep 룰을 가지는 것은 아니다.

| 유형 | 설명 | 결과 |
|------|------|------|
| 룰 기반 스캐너 | `scanners/<name>/rules/*.yaml` 존재 | semgrep 실행 → 매치 인덱싱 |
| grep-less 스캐너 | `rules/` 디렉토리 없음 (business-logic 등) | 빈 `{}` 인덱스 저장 — Phase 1 에이전트가 직접 코드 탐색 |

---

## 주요 처리 세부사항

### UTF-8 미러

한국어 레거시 코드(EUC-KR)나 일본어 코드(Shift-JIS) 파일은 semgrep이 직접 읽지 못한다. `semgrep_index.py`는 비-UTF8 파일을 임시 디렉토리에 UTF-8로 변환한 뒤 스캔하고, 결과 경로를 원본 경로로 복원한다.

디코딩 시도 순서: `utf-8-sig` → `euc-kr` → `cp949` → `shift_jis` → `iso-8859-1`

### PHP 단일 스레드 처리

semgrep의 PHP 분석기는 병렬 멀티파일 스캔에서 매치를 비결정적으로 누락한다. PHP 전용 룰(파일명이 `.php.yaml`로 끝나는 룰)은 `-j 1` 단일 스레드로 별도 실행해 결정성을 확보한다.

### 코드 확장자 필터링

`languages: [generic]` 룰은 `.png`, `.lock` 등 무관 파일까지 스캔하려 한다. `semgrep_index.py`는 스캔 대상을 코드 확장자(`.ts`, `.js`, `.java`, `.py`, `.rb` 등 약 80종)로 제한한다.

### 스킬 디렉토리 자동 제외

스킬 디렉토리(`noah-8719/skills/sast/`)가 project-root 안에 있으면 자동으로 스캔 대상에서 제외된다. SAST 도구 자체 코드가 매칭 결과에 섞이는 것을 방지한다.

---

## locindex가 커지는 문제

`locindex.json`은 매칭 건수에 비례해 커진다.

| 스캐너 | 매칭 건수 | locindex 줄 수 |
|--------|----------|---------------|
| xss-scanner | 4,738건 | ~37,000줄 |
| idor-scanner | 5,370건 | ~40,000줄 |
| unbounded-consumption-scanner | 8,788건 | ~66,000줄 |

Read 도구는 기본 2,000줄 제한이 있어 에이전트가 직접 읽으면 JSON이 잘려 파싱 실패한다. 이 때문에 `locindex_summary.py`를 사용한다.

---

## locindex_summary.py

`locindex.json`을 **파일 단위로 묶어** 요약 출력한다. 파일 수는 매칭 건수보다 훨씬 적어 어떤 스캐너도 2,000줄 이내가 보장된다.

처리 순서:
1. 노이즈 경로 제거 — `vendor/`, `.min.js`, `.yaml`, SAST 도구 파일 등
2. 남은 항목을 파일명 기준으로 그룹핑
3. 파일별 best_tier / taint·ast·generic 건수 집계
4. `-sink` 또는 `-taint` 룰이 걸린 파일에 `[SINK]` 표시
5. tier 순 정렬 출력 (taint → ast → generic)

출력 예시:

```
=== xss-scanner 매칭 파일 요약 ===
총 4738건 → 실제 3824건 / 노이즈 제거 914건
tier: taint=379  ast=3310  generic=1049
파일 수: 510개

best_tier    t     a     g  파일명
----------------------------------------------------------------------
taint       39   140     0  ArticleController.java [SINK]
taint       31    22     0  EventController.java [SINK]
ast          0     2     0  render.js [SINK]
ast          0     1     0  profile.js
generic      0     0     2  Modal.svelte

[노이즈 제거] 914건 — vendor/min/YAML/룰파일
```

실행 방법:

```bash
python3 <NOAH_SAST_DIR>/tools/locindex_summary.py \
  <PATTERN_INDEX_DIR>/<scanner-name>.locindex.json
```

---

## exit code

스크립트는 stdout에 `run_semgrep_index_exit=N`을 출력한다.

| exit | 의미 | 조치 |
|------|------|------|
| 0 | 모든 스캐너 정상 처리 | Phase 1 진행 |
| 1 | semgrep CLI 부재 또는 경로 오류 | semgrep 설치 후 재실행 |
| 2 | 부분 실패 — `_semgrep_failures.json` 참조 | 실패 사유별 대응 (아래 참조) |

exit 2 시 `_semgrep_failures.json`의 `reason` 필드:

| reason | 의미 |
|--------|------|
| `no_rule_files` | 스캐너 디렉토리에 룰 파일 없음 |
| `semgrep_timeout` | 스캔 타임아웃 (프로젝트 분할 검토) |
| `semgrep_rule_error` | 룰 YAML 문법 오류 |
| `json_decode_error` | semgrep 출력 손상 — 재실행 |

실패한 스캐너의 JSON은 빈 `{}`로 저장되므로 나머지 스캐너는 정상 진행된다.

---

## 관련 파일

| 파일 | 역할 |
|------|------|
| `tools/semgrep_index.py` | semgrep 실행 → json + locindex.json 생성 |
| `tools/locindex_summary.py` | locindex.json → 파일 목록 요약 출력 |
| `prompts/guidelines-phase1.md` | Phase 1 에이전트의 locindex 사용 지침 |
| `docs/phase1-execution-flow.md` | Phase 1 전체 실행 흐름 |
