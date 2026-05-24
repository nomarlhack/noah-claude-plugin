---
id_prefix: CODEINJ
rules_dir: rules/
exclusion_policy: capability
---

> ## 핵심 원칙: "사용자 입력이 코드로 실행되면 RCE이다"
>
> Code Injection은 사용자가 제어하는 데이터가 **언어 인터프리터의 코드 입력**(eval/assert/create_function 등)에 도달하여 임의 코드로 실행될 때 발생한다. OS 명령 실행(`system`/`exec`/`shell_exec`)은 command-injection-scanner, 템플릿 표현식 실행은 ssti-scanner, LLM 출력이 sink로 흐르는 경우는 insecure-output-handling-scanner가 담당한다. 본 스캐너는 **언어 자체의 동적 코드 실행 sink**에 집중한다.
>
> ```
> 위험 — eval($_GET['x']);  /  assert($_REQUEST['cmd']);  /  create_function('', $userInput)
> 위험 — new Function(userInput)();  /  eval(req.query.code)  (JS)
> 안전 — eval("정적 리터럴")  /  json_decode($x)  /  ast.literal_eval(x) (Python)
> ```

## Sink 의미론

Code Injection sink는 "문자열 인자를 해당 언어의 코드/표현식으로 컴파일·실행하는 지점"이다. 사용자 입력이 그 문자열에 도달하면 RCE.

| 언어 | 코드 실행 sink | 비고 |
|---|---|---|
| PHP | `eval()`, `assert()` (문자열 인자), `create_function()`, `preg_replace('/.../e', ...)` (PHP<7), `${$var}` 가변변수 극단 케이스 | `assert`는 PHP 7.0+ deprecated, 7.2+ 비활성 권장. `create_function`은 7.2 deprecated/8.0 제거. `/e` modifier는 PHP 7.0 제거 |
| JavaScript/TS | `eval()`, `new Function(...)`, `setTimeout("코드문자열", ...)`, `setInterval("문자열", ...)`, `vm.runInNewContext()`, `vm.runInThisContext()` | Node `vm`은 샌드박스가 아님 (탈출 가능) |
| Python | `eval()`, `exec()`, `compile()` + `exec`, `__import__()` 동적 + 호출 | `ast.literal_eval`은 안전 |
| Ruby | `eval`, `instance_eval`, `class_eval`, `Kernel#eval`, `binding.eval` | |
| Java | `ScriptEngine.eval()`, `Nashorn`, `GroovyShell.evaluate()`, `Groovy Eval.me()` | SpEL/OGNL은 ssti 영역과 겹침 — cross-ref |
| Kotlin | `ScriptEngineManager().getEngineByExtension("kts").eval()` | |
| C# | `CSharpScript.EvaluateAsync()`, `CodeDomProvider.CompileAssemblyFromSource()`, `DataTable.Compute()` | |
| Go | (네이티브 eval 없음) `plugin.Open` 동적 로드, `text/template` + 외부 함수 | 드묾 |

## Source-first 추가 패턴

- HTTP 파라미터/바디/헤더/쿠키가 직접 코드 sink로 흐르는 1차 경로
- **2차 Code Injection**: 사용자 입력을 DB/파일에 저장한 뒤, 다른 코드 경로(배치/cron/렌더링)에서 그 값을 eval에 사용. sink 인자가 DB 컬럼값(`$row->col`)을 eval 문자열에 보간하는 형태(`eval("\$arr['$row->col'] = ...")`)이면, 그 컬럼의 쓰기 경로를 역추적하여 사용자 입력이 저장되는지 확인.
- 설정/플러그인 시스템에서 사용자·관리자 입력을 코드로 평가하는 경로
- 콜백 이름을 문자열로 받아 동적 실행 (`call_user_func($_GET['fn'])`는 RCE는 아니나 임의 함수 호출 — 별도 라벨 `DYNAMIC_CALL`)
- 직렬화 해제 후 매직 메서드를 통한 간접 코드 실행 (deserialization-scanner와 cross-ref)

## 자주 놓치는 패턴 (Frequently Missed)

- **2차(Stored) Code Injection**: sink와 source가 다른 파일·다른 실행 컨텍스트(웹 요청 vs cron/배치)에 있어 단일 함수 dataflow로는 안 잡힘. sink의 인자 변수가 DB 조회 결과($row->X)이면, 그 컬럼에 사용자 입력이 저장되는 쓰기 경로를 역추적한다.
- **`eval`이 SQL 문자열 조립에 쓰이는 케이스**: `eval("\$arr['$key'] = '$val';")` — `$key`/`$val`이 사용자 제어면 PHP 코드 인젝션 (작은따옴표 탈출로 임의 PHP 실행).
- **`assert` 문자열 인자**: 많은 개발자가 assert를 디버그 검증으로 오해하지만 PHP 5.x/7.0에서 문자열 인자는 eval처럼 실행됨.
- **`preg_replace` `/e` modifier**: `preg_replace('/(\w+)/e', '$func("\\1")', $input)` — replacement가 코드로 평가됨 (PHP < 7).
- **JS `setTimeout`/`setInterval`에 문자열 전달**: 함수 대신 문자열을 넘기면 eval과 동일.
- **동적 `require`/`include`로 원격 코드 (RFI)**: path-traversal과 겹치지만, `allow_url_include=On`이면 원격 PHP 실행. cross-ref.

## 안전 패턴 (FP Guard)

코드에서 직접 확인된 경우에만 제외:

- **정적 리터럴 인자**: `eval("return 1+1;")`처럼 인자가 컴파일 타임 상수.
- **Python `ast.literal_eval`**: 리터럴만 파싱, 코드 실행 없음.
- **`json_decode`/`JSON.parse`/`json.loads`**: 데이터 파싱, 코드 실행 아님.
- **정규식 매칭 함수의 일반 사용**: `RegExp.exec()`, `preg_match()` 등은 코드 실행 sink 아님 (이름이 exec여도 정규식 매칭).
- **`subprocess`/`Runtime.exec`/`os.system`**: OS 명령 실행 — command-injection-scanner 영역 (코드 인젝션 아님).
- **화이트리스트 후 호출**: `if ($fn in ALLOWED) call_user_func($fn)`.
- **숫자 캐스트/검증 후**: 사용자 입력이 `intval`/정규식 검증을 통과해 코드 메타문자가 제거됨.

> **⚠️ [필수] "PHP 파일 안의 eval은 클라이언트 JS"라는 클래스 일괄 제외 금지** — 실측 미탐 사례: 에이전트가 `.php` 파일의 eval 매치 295건을 "`<script>` 안 클라이언트 JS DOM 관용구(`eval("f.field_"+i)`)" 클래스로 일괄 제외하면서, 같은 클래스에 섞인 **서버사이드 PHP `eval("\$return_value['$row->writer_name']...")`**(DB값 보간 2차 주입, class_program_daily.php:429)를 읽지 않고 함께 버려 RCE를 놓쳤다. 두 가지를 반드시 지켜라:
> 1. **eval 매치를 클래스로 제외하기 전에 각 매치 라인을 Read하여 실행 컨텍스트를 확인**한다. `<script>`/HTML 출력 블록 내부여야 클라이언트 JS다. PHP 코드 본문(메서드/함수 내, `$obj->prop`·`$arr[]` 주변)의 `eval("...")`는 **서버사이드 PHP eval**이다.
> 2. **"서버측 eval 부재" 검증 grep은 문자열-인자 형태를 포함**해야 한다. `eval($var)`(변수 인자)만 grep하면 PHP의 흔한 형태 `eval("...$var...")`(큰따옴표 문자열 + 보간; 선두 `\$`로 시작하기도 함)를 놓친다. 반드시 `eval\("`·`eval\(\$`·`assert\("`·`assert\(\$`·`create_function`·`preg_replace\(['\"]/.*?/e` 를 모두 확인하라. PHP eval 인자가 `\$`로 시작하면 그것은 eval **내부**에서 평가될 PHP 변수 할당문이며, 그 문자열에 `$row->col`/`$_REQUEST` 등이 보간되면 2차/직접 코드 인젝션이다(§자주 놓치는 패턴, 후보 판정 `SECOND_ORDER`).

## 우회 가능 패턴

| 방어 | 우회 |
|---|---|
| `'`/`"` 이스케이프 | 가변변수 `${...}`, 백틱(셸), 함수 호출 형태 `phpinfo()` (쿼트 불필요) |
| 키워드 블랙리스트 (`eval`,`system`) | PHP 가변함수 `$f='sy'.'stem'; $f($x)`, `call_user_func` |
| 함수명 블랙리스트 | `create_function`, `array_map('assert', [...])`, callback 우회 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → eval/assert(문자열)/create_function/new Function/exec(py) + 검증 없음 | 후보 |
| 사용자 입력 저장 → 다른 경로의 eval에서 그 값 사용 (2차) | 후보 (라벨 `SECOND_ORDER`) |
| `preg_replace` `/e` + 사용자 입력 (PHP<7) | 후보 |
| 인자가 정적 리터럴/숫자 캐스트/json 파싱 | 제외 |
| `RegExp.exec`/`preg_match` 등 정규식 매칭 | 제외 (코드 sink 아님) |
| OS 명령(`system`/`exec`/`shell_exec`) | 제외 (command-injection 영역, cross-ref) |
| `call_user_func($userFn)` 임의 함수 호출 (eval은 아님) | 후보 (라벨 `DYNAMIC_CALL`) |

## 후보 판정 제한

HTTP 입력·저장 데이터와 무관한 경로(빌드 스크립트, 테스트, 마이그레이션)는 제외. 단 cron/배치라도 그 입력이 웹에서 저장되는 2차 경로면 후보로 유지.

## [필수] Safe-by-Proof 의무 출력 (capability 정책)

본 스캐너는 `exclusion_policy: capability` — 매치가 곧 코드 실행 능력의 실재를 뜻한다(decision-framework §2-D 원칙 3). 따라서 **능력형 토큰(위 "Sink 의미론" 표의 `eval`/`assert`/`create_function`/`new Function`/`instance_eval`/`exec`(코드) 등) ast-tier 매치는 클래스로 일괄 제외 금지**다. 실측 FN: PHP `eval` 295건을 "클라이언트 JS" 클래스로 뭉개다 서버 `eval("...$row->col...")` RCE 16건을 함께 누락.

ast-tier 능력형 매치는 **하나도 빠짐없이 dispositioned**되어야 한다. 각 매치는 다음 중 하나로 처리:

1. **후보 등록** (O1~O3 중 하나라도 미이행 = 취약 가능)
2. **개별 SAFE** — O4 증거 인용 (예: "`<script>` 블록 내 클라이언트 JS, foo.php:120" / "정적 리터럴 인자")
3. **동질 하위클래스 SAFE** — 판별 축(실행 컨텍스트 등)을 명시하고 그 축으로 동질임을 입증 + spot-check 표본 제시. **비동질 클래스(같은 토큰이 안전·위험 양쪽에 나타남) 일괄 제외 금지** — 동질이 될 때까지 분할.

결과 MD에 다음 마커를 1줄 포함한다(게이트 `phase1_review_assert.py`가 파싱):

```
<!-- OBLIGATION ast_matches=<locindex ast 매치 수> dispositioned=<처리한 수> method="<처리 요약: 개별후보 N / 동질클래스 제외 M(판별축) / spot-check K>" -->
```

`ast_matches`는 locindex `tier_counts.ast` 값과 같아야 하며(언더신고 불가), `dispositioned`가 `ast_matches`와 같아야 한다(잔여는 `[INCOMPLETE]` 표기). generic-tier 노이즈는 기존 §6-A-2 COVERAGE로 처리한다.
