# Phase 1 후보 판정 의사결정 프레임워크

모든 스캐너의 Phase 1 그룹 에이전트가 매치 1건마다 적용하는 **단일 의사결정 표**다. 각 스캐너의 `phase1.md`는 sink/source/안전 패턴의 **의미론**만 정의하고, "후보 vs 안전"의 **분류 로직**은 본 프레임워크가 단일 진실 원천이다. `phase1-review`(2단계 검증)도 동일 프레임워크로 평가한다 → 1·2단계 판정 정렬.

> 본 문서는 LLM 변동성(같은 코드를 다르게 판정하는 문제)을 줄이기 위한 결정론적 기준이다. 모호어("적절한", "충분한")를 객관 사실로 대체한다.

---

## 1. tier 자동 분기 (LLM 재판단 최소화)

매치 1건마다 먼저 `<scanner>.locindex.json`에서 해당 file:line의 `tier`를 확인한다. tier가 결정한 것은 다시 판단하지 않는다.

| locindex tier | sink 의미론(phase1.md) 정합 | 자동 판정 | 추가 작업 |
|---|---|---|---|
| `taint` | ✓ | **자동 후보** | URL 경로 확정(§6-C), 트리거 4단계(아래 §4), 라벨(§3) 부여 |
| `taint` | ✗ (룰이 잘못 매치) | 제외 (`safe_category: false_positive`) | 사유 1줄 기록 |
| `ast` | ✓ | 후보 + §6-D 5단계 골격 전체 | 라벨 + 트리거 4단계 |
| `ast` | ? (모호) | §6-B 의미 기반 재판정 | — |
| `generic` | ✓ + has_taint=false | 후보 + 5단계 골격 | 라벨 + 트리거 4단계 |
| `generic` | ? + has_taint=true | 후순위(§6-A-1) | 예산 소진 시 `[INCOMPLETE]` |
| `generic` | ✗ | 제외 (`safe_category: false_positive`) | 사유 1줄 |

**핵심 규칙**: `tier: taint` 매치는 dataflow가 Source 도달성 + sanitizer 부재를 이미 확정했으므로 **에이전트가 다시 검증하지 않는다**. sink 의미론 정합 여부만 확인.

---

## 2. 객관 사실 체크리스트 (모호어 제거)

후보 등록 조건을 **확인 가능한 사실의 AND**로 정의. 각 사실은 코드 read 1회로 검증 가능.

### 2-A: 사용자 입력 도달성 (모든 Injection 계열 공통)

**(a) source 식별**:
- sink 인자가 변수 X일 때, X의 최초 대입을 호출 체인 최대 3단계 이내에서 다음 중 하나로 추적 가능:
  - HTTP 파라미터/바디/헤더/쿠키 (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`, `request.GET/POST/args/form/json`, `req.query/params/body`, `@RequestParam`/`@RequestBody`/`@PathVariable`, `r.URL.Query().Get`/`c.Query` 등)
  - DB SELECT 결과 (2차 케이스 — 라벨 `SECOND_ORDER`)
  - 외부 쓰기 가능 저장소/메시지 큐/외부 API 콜백 응답

**(b) 위생 처리 부재**:
- X 또는 X 유래 변수에 대해 동일 함수 + 호출자 체인 상위 3단계 이내에서 다음이 없음:
  - 강제 타입 캐스트 (`intval`/`(int)`/`Number()`/`parseInt`/`int()`/`Integer.parseInt`/`strconv.Atoi`)
  - 화이트리스트 매칭 (`in [...]`/`includes`/`in_array`/`contains`)
  - sink 별 안전 sanitizer (각 phase1.md "안전 패턴" 참조)
  - 파라미터 바인딩 / prepare+bind / 명시 escape 함수

→ (a) AND (b) 만족 = 후보 등록. (a) 또는 (b) 위반 = 제외하되 사유 명시.

### 2-B: tier=taint인 경우 단축

(a), (b)는 룰엔진이 확정 (pattern-sources 정의 + pattern-sanitizers 미매치). 에이전트는:
- sink 의미론 정합만 1줄 확인
- URL 경로 / 라벨 / 트리거 4단계 부여

---

## 2-C. 안전 패턴의 잘못된 일반화 주의

decision-framework 적용 중 가장 흔한 오류는 **scanner phase1.md의 "안전 패턴"을 잘못된 범위로 확장 적용**하는 것이다. 안전 패턴은 정확한 코드 형태에만 성립하며 변형에 무차별 적용하면 진성 결함을 놓친다. 대표 사례:

- **컴퓨티드 프로퍼티 안전성**: `{[key]: value}` 객체 리터럴 내 컴퓨티드 키는 `__proto__`여도 own property로 추가되어 안전하다. **그러나 `obj[key] = value` bracket assignment, 특히 `obj[k] = obj[k] || {}; obj = obj[k]` path-walk + 단축 평가 패턴**은 별개 위험 (prototype getter 호출 → cursor가 `Object.prototype`으로 점프). 객체 리터럴 한정 안전성을 bracket assignment에 일반화 금지.
- **`hasOwnProperty` 가드**: 적용 위치가 walk 진입 전이 아니라 walk 중간이면 우회 가능. 첫 segment에서 이미 prototype chain 진입한 후 다음 segment의 `hasOwnProperty`는 무용.
- **타입 캐스트 sanitizer**: `Integer.parseInt`/`intval`이 NaN/오버플로 시 0이나 예외를 던지지 않으면 false→0 캐스팅으로 우회. 캐스트 후 null/NaN 처리 확인 필수.
- **프레임워크 기본 안전**: "Spring/Django/Express가 기본적으로 안전"이라는 일반화는 framework 버전·옵션·설정 의존. 코드에서 명시적 안전 메커니즘 호출이 확인되지 않으면 안전 가정 금지.
- **방어 호출 존재 ≠ 방어 범위 적정**: sanitizer/검증/인가 함수가 **호출되는 것**을 봤다고 안전으로 단정하지 말 것. 그 함수가 **모든 경로·타입·액션을 빠짐없이 커버하는지** 함수 본문을 Read하여 확인한다. `if (위험조건 && !예외타입) throw;` 처럼 특정 타입/플래그/액션을 throw에서 제외하는 부분 방어는 흔하며, 이때는 안전이 아니라 `DEFENSE_BYPASS` 후보(우회 경로 명시). 호출의 **존재**가 아니라 **효과의 완전성**으로 판정.
- **형제·다른 분기를 표본 삼아 안전으로 묶어 판단 금지**: 형제 엔드포인트나 다른 분기(다른 enum 값·role 등)가 게이트를 가졌다는 사실을 근거로 다른 진입점·분기까지 안전하다고 묶어 판단하지 말 것. 각 진입점·각 분기의 안전·취약은 그 코드를 직접 Read해 **개별** 확정한다. 형제 비대칭은 검토 대상이 **취약**하다는 deviance 신호로만 쓰며 안전 근거로는 무효다. ("형제가 게이트 있으니 이것도 안전"은 무효 추론.)

**규칙**: 안전 패턴 적용 시 반드시 (1) 패턴이 sink와 정확히 같은 코드 형태인가, (2) 변형/우회 가능성이 없는가를 검증한다. 의심스러우면 보수적으로 후보 유지.

---

## 2-D. Safe-by-Proof 의무 모델 (입증책임 역전 — FN 방지의 핵심)

> 정탐을 안전으로 오분류(FN)하는 것이 가장 치명적이다(회복 불가). 따라서 **"취약"을 기본값으로 두고, "안전"으로 분류하려면 증명 의무를 이행**하게 한다. 이는 §2-A 객관 사실을 "버리는 쪽에 입증 부담"으로 재구성한 것이다. (근거: soundiness manifesto — unsound 경계를 명시적으로 문서화 / z-ranking — 삭제 대신 랭킹.)

### 원칙 1 — SAFE는 증명, VULNERABLE은 기본값

매치를 **안전(제외)으로 분류하려면 아래 의무를 모두 이행**해야 한다. 하나라도 미이행이면 **후보 유지**다. 각 의무 이행은 **증거(file:line 인용)** 또는 "왜 이행 불가인지(unsound 경계 명시)"로 기록한다.

| 의무 | SAFE로 인정받는 이행 조건 | 이행 불가 = 후보 유지 신호 |
|---|---|---|
| **O1 source 비제어** | 입력이 공격자 비제어임을 증거로 입증 (컴파일 상수 / 내부 생성 / 기검증 통과) | source가 외부 입력 표면(§2-A (a))에 닿으면 미이행 |
| **O2 reachability** | sink가 진입점에서 도달 불가임을 입증 (호출부 0건 = dead code 등) | 도달 경로가 **람다/클로저·reflection·동적 디스패치·메시지큐·크로스서비스**를 지나 추적 불가하면 → **"엔진이 눈먼 것"이지 "도달 불가"가 아님** → 미이행 |
| **O3 sanitization** | 유효 sanitizer가 source→sink 모든 경로를 지배함을 입증 (함수 본문 Read + 범위 적정성 §2-C) | 부분 방어·우회 가능·미적용 경로 존재 시 미이행 |
| **O4 capability** | 그 위치가 위험 동작 sink가 **아님**을 입증 (예: eval이 클라이언트 `<script>` 컨텍스트임을 file:line으로 / 정적 리터럴 인자) | sink 능력이 실재하면 미이행 |

**[필수] O2의 unsound 경계 규칙**: taint 엔진이 람다 클로저·고차함수·reflection·메타프로그래밍·2차(저장→로드)·크로스 모듈을 못 넘어 매치가 안 됐다면, 그것은 **"안전(clean)"이 아니라 "엔진이 눈먼(blind)"** 것이다. 이 경우 O2를 이행한 것으로 치지 말고, source-only 전수(인벤토리)로 에스컬레이션하거나 후보로 유지한다. (실측 FN: `accountId?.let { svc.get(it) }` 람다 → taint 미추적 → "clean"으로 오인하면 IDOR 누락.)

**[필수] O3의 분기·부재 경로 규칙 (absence/인가 게이트 일반화)**: O3의 "모든 경로 지배"는 두 가지를 포함한다 — ⓐ 방어가 **판별자(enum·role·type·플래그)로 분기**하면 **전 분기**가 방어를 가져야 한다(한 분기의 방어로 전체를 안전 판정 금지), ⓑ 방어가 조회·검증이면 **부재 경로(빈 결과/null/no-match/미일치)에서 접근이 거부됨**을 입증해야 한다(fail-open 금지). 한 분기라도, 부재 경로 한 곳이라도 거부가 입증 안 되면 O3 미이행 → 후보. **판정은 코드 패턴·메서드 네이밍·언어·관용구가 아니라 "부재·미일치 시 거부" 효과로** 하며, 특정 shape에 의존하지 않으므로 스캐너·언어·프로젝트 불문 동일 적용된다.

### 원칙 2 — 삭제하지 말고 랭킹 (Rank, don't Drop)

판정은 binary(후보/제외)가 아니라 **confidence 밴드**다. "안전"은 **최하위 밴드일 뿐 삭제가 아니다** — 인벤토리에 남고, spot-check 대상이며, DAST 권한 diff 입력이 된다. confidence = `tier(taint>ast>generic) × 미이행 의무 수 × deviance(지역 관례 일탈이면 ↑)`. 이렇게 하면 "조용한 누락"이 구조적으로 불가능하다(아무것도 지워지지 않으므로).

### 원칙 3 — 아키타입별 의무 특화

의무의 "무엇이 이행인가"는 취약점 구조마다 다르다(scanner phase1.md frontmatter의 `exclusion_policy` 태그):

| 아키타입 | 스캐너 예 | 의무 초점 |
|---|---|---|
| **capability** (매치=위험동작 실재) | code-injection, command-injection, ssti, deserialization, xss, dom-xss | **O4가 핵심** — 능력형 토큰(각 phase1.md Sink 의미론 표)은 **클래스 일괄 제외 금지**. SAFE하려면 매치별 또는 **동질 하위클래스**(판별 축 명시 + spot-check)로 O4 증거 제시 |
| **injection-with-safe-form** | sqli, ldap, xpath, ssrf, path-traversal, open-redirect | 위험 토큰 + **위험 형태**(보간/연결/사용자 host)만 개별 검토. 안전 형태(파라미터 바인딩/상수 host)는 증거 첨부 후 클래스 제외 허용 |
| **absence** (sink 부재 = 검증 누락) | idor, csrf, business-logic | 토큰 무관. 인벤토리 전수 + 게이트는 service Read로 확인(추정 금지). deviance(형제 엔드포인트 비대칭)가 강한 신호 |
| **config** (설정 유무) | tls, security-headers, cookie, springboot | 저볼륨. "플랫폼이 방어할 것" 단정 금지 → 인프라 미확인 시 후보 유지(PLATFORM_DEFENSE 라벨) |
| **presence** (값 자체가 위험) | hardcoded-secrets, log-injection | 값/패턴의 존재 자체가 취약점. Source 도달성(O2) 불필요 — 코드에 박힌 비밀값(hardcoded-secrets)이나 민감 정보가 로그 sink에 도달하는 흐름(log-injection)이면 O4(sink 의미론 정합) 확인 후 후보 등록. 환경 변수 참조나 개행 제거는 안전. **스캐너 선언**: 해당 스캐너의 phase1.md frontmatter에 `archetype: presence` 기재. |

> **`exclusion_policy: capability` frontmatter 태그의 정확한 의미**: 이 태그는 `phase1_review_assert.py`의 **기계적 OBLIGATION 게이트**(ast-tier 전수 disposition 강제)를 켠다. 따라서 **ast-tier 매치가 신뢰성 있게 "능력형 sink"일 때만** 부여한다(실측 검증: code-injection·deserialization은 ast=eval/unserialize 등 정밀·소량). **command-injection·ssti·xss·dom-xss는 capability 아키타입이지만** broad-pattern 룰이 ast-tier에 source 마커·과부하 토큰(`Template(`/출력 컨텍스트) 노이즈를 대량 섞으므로(실측: Spring 프로젝트 ast 1000건+) 기계 게이트가 노이즈 계상을 강요해 부적합 — 태그 대신 각 phase1.md의 **"[필수] 능력형 토큰 클래스-제외 금지"** 지침으로 보호한다. 이 4개에 기계 게이트를 적용하려면 broad 패턴과 분리된 **고정밀 능력형 sub-rule**(예: `noah-xss-innerHTML-sink`)을 먼저 추가해야 한다(향후 과제).

### 원칙 4 — 영향은 sink가 실제로 하는 일로 기술 (과장·과소 둘 다 방지)

취약점의 **영향(impact)은 sink가 코드에서 실제로 하는 일로만 기술**한다. 엔드포인트 의미·형제 취약점·worst-case로 외삽하지 않는다(과장 예: 조회형 sink의 응답 구조를 확인하지 않고 worst-case PII 노출로 외삽).

- **조회·공개형(read)**: 실제로 반환되는 필드 — 응답으로 직렬화되는 데이터 구조에서 **읽은 필드**로 한정한다. 그 구조에 없는 데이터 범주(이름·주소·전화 등)는 단정하지 않는다.
- **변경·부수효과형(write/side-effect)**: sink가 실제로 일으키는 **상태 변화나 부수 효과**로 기술한다 — 어떤 자원/외부 상태를 어떻게 바꾸거나 작동시키는지. 노출형 프레임("PII 유출")을 이쪽에 잘못 씌우지 않는다.
- **동적으로 효과를 관측하지 못한 후보**: 코드로 확인된 효과로 한정하고, 미전개 중첩 타입·미관측분은 **"미확인"**, 코드 근거 없는 추정은 **"추론"**으로 라벨한다. 이는 원칙 2(rank, don't drop)의 영향축 적용 — **과장도, 미확인을 "안전/무해"로 닫는 과소평가(FN)도 금지**한다.

> **요약**: 안전 단정에는 의무 이행(증거)이 필요하고, 의심·이행불가·unsound 경계는 모두 후보 유지로 귀결된다. 능력형 토큰은 동질성을 입증하지 않는 한 클래스로 뭉개지 않는다. 영향 서술은 sink의 실제 효과(반환 필드/상태 변화·부수 효과)에 근거하며, 코드로 확인 안 된 부분은 외삽하지 않고 "미확인/추론"으로 표기한다.

### 원칙 4 — Deviance: 지역 관례 일탈은 고신뢰 신호 (전 스캐너 일반화)

> 근거: Engler "bugs as deviant behavior" — 코드베이스가 **스스로 지키는 지배적 관례가 곧 명세**다. 절대 규칙("이 코드는 취약한가?")을 판단하는 것보다, 상대 판단("이 코드는 같은 코드베이스의 다수 관례에서 벗어나는가?")이 더 견고하고 FN에 강하다.

**규칙**: 동일 sink/연산이 한 모듈·클래스·라우트 그룹에서 N회 나타나고 **다수(대략 ≥70%)가 방어(sanitizer/인가 게이트/파라미터 바인딩/escape)를 갖췄는데 소수가 안 갖췄다면, 그 소수는 HIGH-confidence 후보**다(confidence 부스터, §2-D 원칙 2). 코드베이스가 그 방어를 "해야 한다"는 것을 스스로 입증했는데 일부만 누락한 것이기 때문이다.

**[필수] 역방향 금지**: 다수가 안전하다고 해서 그 소수 일탈자를 "다수와 같은 클래스"로 묶어 함께 제외하지 말 것. **다수의 안전성은 일탈자의 안전성을 증명하지 않는다** — 오히려 일탈자가 결함일 확률을 높인다. (이것이 §2-D 비동질 클래스 제외 금지의 deviance 버전.)

**적용 예** (전 스캐너):
- IDOR: 형제 엔드포인트 다수가 소유권 게이트 보유, 이 메서드만 누락 → `IDOR_ASYMMETRIC` (이미 자동 후보). 예: 인증 분기 중 특정 경로만 소유권/멤버십 검증을 누락한 경우.
- SQLi: 같은 Repository의 쿼리 다수가 파라미터 바인딩, 한 곳만 문자열 보간 → 그 한 곳 HIGH.
- XSS: 같은 컴포넌트의 출력 다수가 escape, 한 곳만 raw → 그 한 곳 HIGH.
- 인가: 같은 컨트롤러 액션 다수가 `before_action :authenticate`, 한 액션만 `skip` → 그 액션 HIGH.

일탈자 발견 시 라벨에 `DEVIANT`를 부기하여 "지역 관례 위반"임을 표시한다(`IDOR_ASYMMETRIC`는 그 IDOR 특화 별칭).

---

## 3. 표준 라벨 시스템 (47개 스캐너 일관)

후보 등록 시 `phase1_eval_state` 또는 본문 헤더에 라벨 1개 이상 부여. 라벨이 후보의 성격을 1초에 식별 가능하게 만든다.

| 라벨 | 의미 | 적용 sink 예 |
|---|---|---|
| `DIRECT` | 1차 — HTTP 입력이 직접 sink 도달 | `eval($_GET['x'])`, `query("..." + req.body.id)` |
| `INDIRECT` | 헬퍼/wrapper 경유 도달 | `setContent(req.body)` → 내부 `innerHTML` |
| `SECOND_ORDER` | DB/저장값 → 다른 컨텍스트의 sink로 재사용 | DB 컬럼값이 cron eval에 보간 |
| `IDENTIFIER` | 컬럼명/테이블명/ORDER BY 식별자 위치 (쿼트 무관) | `ORDER BY {col}` |
| `IN_CLAUSE` | `IN (...)` 동적 배열 직렬화 | `IN (${ids.join(',')})` |
| `DEFENSE_BYPASS` | 방어 코드 존재하나 우회 가능 (구체 우회 방식 본문에) | `replace("'","")` 회피, eregi 데드 |
| `RUNTIME_DEPENDENT` | 언어 버전/설정/플래그 의존 (PHP7 eregi 제거 등) | preg_replace `/e` 5.x 한정 |
| `OPEN_REDIRECT` (path/host) | 외부 도메인 도달 부분 결합 | endsWith("a.com") 부분매치 |
| `AUTH_BYPASS` | 인증/인가 우회 1단계 | X-Forwarded-For 기반 키 |
| `IDOR_CROSS_USER` | 객체 레벨 인가 부재 | user_id IN 절 스코프 미검증 |
| `STATE_MISSING` | OAuth state/PKCE/nonce 부재 | `state` 파라미터 미검증 |
| `LOOSE_EQUALITY` | `==` 보안 비교 (PHP magic hash 등) | token 검증에 `!=` |
| `MASS_ASSIGNMENT` | 모든 입력이 모델에 그대로 매핑 | `Member::insert($_POST)` |
| `NO_PATH` | 외부 도달 경로 없음 → **안전** | dormant 라이브러리, dead code, 비공개 cron |
| `FALSE_POSITIVE` | 룰이 잘못 매치 (sink 의미 불일치) → **안전** | regex `/e` 매치이나 `e`는 메타문자 아님 |
| `PLATFORM_DEFENSE` | 브라우저/런타임 기본값이 동등 방어 → **안전** | Chrome 85+ Referrer-Policy 기본 |

**규칙**: NO_PATH/FALSE_POSITIVE/PLATFORM_DEFENSE 라벨이 붙으면 그 후보는 `status: safe`, `safe_category` 매핑. 나머지 라벨은 후보 유지.

---

## 4. 재현 가능성 4단계 (트리거 현실성)

`§10 트리거 조건의 현실성`을 결정론적 4단계로 분류. 에이전트는 1개만 선택.

| 단계 | 정의 | 처리 |
|---|---|---|
| **T1** | 비인증 + URL 1회 호출로 트리거 | 후보 (라벨 없음) |
| **T2** | 인증 필요하나 일반 회원/파트너로 가능 | 후보 + `AUTH_USER` |
| **T3** | 관리자 또는 특정 설정 변경(1줄)으로 트리거 | 후보 + `AUTH_ADMIN` 또는 `RUNTIME_DEPENDENT` |
| **T4** | 다중 외부 전제 필요 (서버 침해/MITM/0-day 결합) | 제외 (지침 8 - 외부 전제 다중) |

각 후보 본문 `### Trigger Conditions`에 T1~T3 중 하나 명시.

---

## 5. 후보 통합/분리 규칙 (카운팅 일관성)

동일 결함이 여러 파일·라인에 있을 때 통합 기준:

**[필수] 불변식: 후보 1건 ↔ 독립적으로 트리거·검증되는 공격 벡터 1개.** 보통 진입점
(externally-reachable route/handler) 단위다. **서로 다른 진입점은 어떤 경우에도 한 후보로
통합하지 않는다** — sink 함수가 같든, 고치는 코드 위치가 같든 무관하다. (이유: 통합하면 진입점별
상태·POC가 뭉개지고, 특히 한 진입점만 동적 확인됐는데 통합하면 미테스트 진입점이 "확인됨"을
거짓 상속한다.) 통합이 허용되는 유일한 경우는 한 진입점이 **단일 요청으로 함께 발화되는** 내부
sink 라인을 여러 개 갖는 경우(같은 POC·같은 검증으로 커버)이며, 이때만 1후보로 묶고 본문
`### Code`에 그 라인들을 열거한다. 같은 진입점이라도 파라미터·조건이 달라 별도 POC·별도 검증이
필요한 벡터가 2개 이상이면 분리한다. 이 불변식은 전 스캐너 공통이다.

### 5-A: 통합 (1 후보로) — 단일 진입점 내부 한정

- **한 진입점이 단일 요청으로 함께 발화하는 내부 sink 라인들** = 1 후보로 묶고, 본문 `### Code`에 모든 file:line 열거
- **[금지] 서로 다른 진입점(다른 route/handler)을 1후보로 묶지 않는다** — 같은 sink·같은 수정 위치라도, 동일 패턴이 N개 진입점에 반복돼도, 진입점이 다르면 각각 후보다

### 5-B: 분리 (각각 후보)

- 권장 조치가 다르면 (예: 같은 sink여도 source가 달라 escape 위치 다름) 별도 후보
- sink는 같지만 source 채널이 의미적으로 분리되는 경우 (예: 일반 사용자 vs 파트너 API)
- 보고서 가독성과 권장 조치 적용 단위가 일치하도록
- **검토 단위 ≠ 등록 단위 함정**: 리스트/인벤토리 단위로 검토하는 유형(통제 부재가 결함이라 진입점을 전수 열거하게 되는 경우)에서 검토 단위를 등록 단위로 오인하기 쉽다. 1:1 불변식은 전 스캐너 공통이며, 한 파일에 서로 다른 진입점이 여러 개면 각각 후보다.
- **형제 route를 본문에 붙여 묶지 말 것**: 후보 본문에 형제 엔드포인트의 route 어노테이션을 붙이지 않는다(다른 진입점으로 오인되어 묶음으로 보임). 형제 deviance는 메서드명·동작으로 인용한다(§2-C "형제·다른 분기를 표본 삼아 안전으로 묶어 판단 금지").

### 5-C: 카테고리 경계 (지침 12)

- 같은 file:line이 sqli + idor 두 스캐너에 모두 부합 → 각 스캐너에서 독립 후보 + 본문에 cross-ref
- 같은 스캐너 내에서는 §5-A/5-B 통합 규칙 적용

---

## 6. phase1-review의 평가 기준 정렬

`phase1-review`(2단계)도 본 프레임워크의 표를 그대로 적용:
- 축 1 (코드 정확성): §2-A의 사실 (a)·(b)가 코드에 실제 존재하는가
- 축 2 (Source→Sink 흐름): §2-A 호출 체인 3단계 추적이 타당한가
- 축 3 (부재 주장): §2-A (b) sanitizer 부재가 실제 코드와 일치하는가
- 축 4 (Source 도달성): §1 tier로 자동 분기 (taint면 ✓ 유지)
- 축 5 (플랫폼 방어): §3 라벨 `PLATFORM_DEFENSE` 적용 여부

→ Phase 1 에이전트와 phase1-review가 같은 표를 참조하므로 CONFIRM/OVERRIDE/DISCARD 사유가 결정론적.

---

## 7. sanity check (스캐너별 예상 범위)

각 phase1.md 끝에 `예상 후보 수 범위` 명시(권장). 에이전트가 자체 결과와 대조:

| 스캐너 유형 | 코드베이스 규모 | 예상 후보 수 |
|---|---|---|
| Injection 계열 (sqli/xss/cmdi/ssrf 등) | PHP 백오피스 5만+ LOC | 5~20건 |
| Injection 계열 | 모던 Spring Boot 1만 LOC | 0~5건 |
| Injection 계열 | 정적 사이트 | 0~1건 |
| 설정 검사 (security-headers/tls/cookie) | 모든 웹 앱 | 2~8건 |
| 인증/세션 (jwt/oauth/csrf/idor) | API/백오피스 | 1~5건 |
| LLM 4종 | LLM 미사용 프로젝트 | 0건 (전부 이상 없음) |
| LLM 4종 | LLM 통합 프로젝트 | 2~10건 |

에이전트가 자기 결과가 도메인 통상 범위 밖이면 (예: PHP 백오피스 sqli 0건) `[SANITY_LOW]` 또는 `[SANITY_HIGH]` 표기. **하드 컷이 아니라 자체 점검 트리거**.

---

## 적용 순서 (그룹 에이전트가 매치 1건마다)

1. **locindex tier 확인** (§1) → taint면 자동 후보, generic-only면 후순위 판정
2. **sink 의미론 정합 확인** (해당 phase1.md "Sink 의미론" 1줄 확인)
3. **객관 사실 체크리스트** (§2-A) → (a) source 식별 + (b) sanitizer 부재 둘 다 만족?
   - tier=taint면 §2-B로 단축
4. **라벨 부여** (§3) — DIRECT/SECOND_ORDER/DEFENSE_BYPASS 등 1개 이상
5. **트리거 4단계** (§4) — T1~T4 중 1개
6. **통합/분리 결정** (§5) — 같은 sink 묶을지
7. **결과 파일에 반영** — 라벨·T단계·통합 단위로 후보 본문 작성

이 7단계를 거치면 LLM 자율 판단의 변동 범위가 매치당 거의 0에 가까워진다.
