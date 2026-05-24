---
id_prefix: SSTI
rules_dir: rules/
exclusion_policy: capability
capability_via_sink_rule: true
---

> ## 핵심 원칙: "템플릿 표현식이 실행되지 않으면 취약점이 아니다"
>
> 템플릿 엔진을 사용한다고 SSTI가 아니다. SSTI는 사용자 입력이 **템플릿 문자열 자체**에 삽입되어 엔진이 코드로 해석할 때만 발생한다. 템플릿의 **변수**로 전달되는 것은 SSTI가 아니다.
>
> ```
> 안전 — render('hello.ejs', { name: userInput })
> 위험 — ejs.render('Hello ' + userInput)
> ```

## Sink 의미론

SSTI sink는 "사용자 입력이 템플릿 컴파일러의 입력 문자열 위치에 도달하는 지점"이다. 핵심 구분: 사용자 입력이 **컴파일 대상**인가, **데이터 컨텍스트**인가.

| 엔진 | 언어 | 표현식 | 테스트 |
|---|---|---|---|
| Jinja2 | Python | `{{ }}` `{% %}` | `{{7*7}}` → 49 |
| Mako | Python | `${}` | `${7*7}` → 49 |
| Django Template | Python | `{{ }}` | 기본 안전 (sandbox) |
| EJS | Node | `<%= %>` `<%- %>` | `<%= 7*7 %>` |
| Pug | Node | `#{}` | `#{7*7}` |
| Nunjucks | Node | `{{ }}` | `{{7*7}}` |
| Handlebars | Node | `{{ }}` | 기본 안전 (helper만 호출) |
| ERB | Ruby | `<%= %>` | `<%= 7*7 %>` |
| Thymeleaf | Java | `${}` | `${7*7}` (StandardDialect는 OGNL 미사용, SpringEL 사용) |
| Freemarker | Java | `${}` | `${7*7}`, `<#assign x=...>` |
| Velocity | Java | `$x` | `$class.forName('java.lang.Runtime')` |
| Twig | PHP | `{{ }}` | `{{7*7}}` |
| Smarty | PHP | `{}` | `{7*7}` |

**위험 sink 함수:**

| 엔진 | 위험 (컴파일 대상에 입력) | 안전 (데이터 컨텍스트) |
|---|---|---|
| EJS | `ejs.render(x)`, `ejs.render('...'+x)`, `ejs.compile(x)` | `ejs.render(file, {k:x})`, `res.render('view', {k:x})` |
| Pug | `pug.render(x)`, `pug.compile(x)` | `pug.renderFile(file, {k:x})` |
| Nunjucks | `nunjucks.renderString(x)` | `nunjucks.render('view', {k:x})` |
| Jinja2 | `Template(x).render()`, `Environment.from_string(x)`, Flask `render_template_string(x)` | `render_template('view', k=x)` |
| Mako | `Template(x).render()` | `template.render(k=x)` |
| Thymeleaf | `templateEngine.process(x, ctx)`, SpringEL이 controller 반환값에 평가되는 경우 (`return "redirect:" + userInput`) | `process('view', ctx)` + ctx에 입력 |
| Freemarker | `new Template("n", new StringReader(x), cfg)`, `Template.process` with dynamic body | dataModel에 입력 |
| ERB | `ERB.new(x).result` | `ERB.new(file).result_with_hash(k:x)` |
| Twig | `$twig->createTemplate(x)->render()` | `$twig->render('view', ['k'=>x])` |
| Velocity | `Velocity.evaluate(ctx, sw, "log", x)` | template 파일 + ctx |

## Source-first 추가 패턴

- 이메일 템플릿 본문 편집기 (관리자/마케팅이 작성하는 템플릿이지만 결국 서버에서 컴파일됨 → 권한 우회 가능 시 후보)
- 에러 페이지/리다이렉트 메시지에 사용자 입력 반영 (`return "redirect:" + url` Spring SpringEL 평가 케이스)
- CMS의 위젯/숏코드 시스템
- i18n 메시지 키가 사용자 제어
- "동적 보고서 템플릿" 기능
- 챗봇 응답 템플릿

## 자주 놓치는 패턴 (Frequently Missed)

- **Spring `return "redirect:" + userInput`**: Thymeleaf/SpringEL이 view name을 평가하면서 `${}` 표현식을 실행. CVE-2022-22965 계열.
- **Flask `render_template_string`**: f-string과 결합되면 항상 위험.
- **이메일 템플릿 미리보기**: 관리자가 입력한 템플릿을 즉시 컴파일하는 미리보기 기능.
- **`.format()` / f-string vs 템플릿 엔진 혼동**: Python `format` 자체도 `{0.__class__.__init__.__globals__}` 같은 attribute walk 가능 (제한적 SSTI/정보 노출).
- **Velocity의 reflection**: `$class.forName('java.lang.Runtime').getMethod(...)` — sandbox 비활성 시 RCE.
- **Handlebars 커스텀 helper**: 기본은 안전하지만 helper가 `eval`/`Function`을 호출하면 위험.
- **Mustache → Handlebars 마이그레이션 잔재**: triple-stash `{{{x}}}`는 escape 안 함 (XSS이지 SSTI는 아니지만 함께 점검).
- **i18n 라이브러리 (i18next, ICU MessageFormat)** 의 동적 키 평가에 사용자 입력.
- **에러 메시지에 입력 반영 후 템플릿 처리**: `flash[:notice] = "Welcome #{params[:name]}"` + ERB로 렌더.
- **Go `text/template` vs `html/template`**: `text/template`은 HTML escape 없음 + 반사된 입력이 템플릿 문자열이면 SSTI.
- **Razor (.NET) `@Html.Raw()` + 동적 view 컴파일**: `RazorEngine.Compile(userInput)`.
- **JSP EL + 동적 include**: `<jsp:include page="${userInput}">` — page가 `.jsp`면 서버사이드 평가.
- **Tornado (Python) `tornado.template.Template(x)`**: Python 코드 블록 포함 가능 — RCE 직결.
- **Pebble (Java) `engine.getTemplate(x)`**: Spring Boot 환경에서 자주 사용. sandbox 기본 없음.

## [필수] 능력형 토큰 클래스-제외 금지 (Safe-by-Proof §2-D)

템플릿 표현식 평가 능력형 토큰(`SpelExpressionParser`/`parseExpression`/`TemplateEngine.process`+동적 템플릿 문자열/`Velocity.evaluate`/`new Template(userString)`/`render inline:`/`Jinja2 from_string`/`Smarty eval`)은 **매치 = 템플릿 표현식 평가 능력 실재**다. 일괄 제외 금지 — 개별 또는 동질 하위클래스(판별 축 명시) + spot-check. **주의**: `*RedisTemplate`/`R2dbcEntityTemplate`/`*IndexTemplate`/`buildConstraintViolationWithTemplate` 등 프레임워크 인프라의 `Template` 토큰은 SSTI sink가 아니므로(동질 비-sink 클래스) 그 판별 축을 명시해 분리하되, **진짜 표현식 평가 토큰을 그 노이즈 클래스에 섞어 함께 버리지 말 것**.

**기계 게이트(Java/Kotlin/Ruby)**: `exclusion_policy: capability` + `capability_via_sink_rule: true`. 고정밀 sink 룰(`noah-<lang>-ssti-eval-sink`: `parseExpression`/`Velocity.evaluate`/`createTemplate`/`ERB.new`/`render inline`)이 `Template` 생성자 노이즈와 분리해 능력형 매치를 집계(실측: gift broad ast 1131 → sink 1, booking 1241 → 0). 이 `-sink` 매치는 전수 dispositioned. 결과 MD에 마커:

```
<!-- OBLIGATION capability_matches=<-sink 매치 수> dispositioned=<처리 수> method="..." -->
```

`capability_matches`=locindex `-sink` 매치 수, `dispositioned`=동일(잔여 `[INCOMPLETE]`). 그 외 언어/`Template` 노이즈는 §6-A-2 COVERAGE로 처리.

## 안전 패턴 (FP Guard)

- **파일 기반 템플릿 + 데이터 컨텍스트**: `render('view.ejs', {data})` — 사용자가 파일 경로를 제어하지 않는 한 안전.
- **Handlebars 기본 사용** (커스텀 unsafe helper 없음).
- **Django Template 기본 사용** (sandbox 적용).
- **Jinja2 SandboxedEnvironment** 사용.
- **템플릿 컴파일 캐시**: 미리 컴파일된 템플릿 객체에 데이터만 주입.
- **Freemarker `new_builtin_class_resolver=TemplateClassResolver.SAFER_RESOLVER`**: reflection 기반 공격 차단.
- **Twig sandbox (`SecurityPolicy`)**: 허용 tag/filter/function 명시 화이트리스트.
- **Velocity 2.x `SecureUberspector`**: 구 Velocity 1.x와 달리 기본 reflection 차단.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| Jinja2 SandboxedEnvironment | 환경 의존 | 구버전 sandbox escape CVE 존재 (`__class__.__mro__` walk 일부 변형). 버전 확인 필수 |
| Freemarker `SAFER_RESOLVER` | 부분 가능 | `?eval` built-in, `"freemarker.template.utility.Execute"?new()` 같은 ObjectWrapper 경로 확인 |
| 키워드 블랙리스트 (`__class__` 차단) | 가능 | `["__class__"]` attribute access, `\x5f\x5fclass\x5f\x5f` unicode, `request.__init_subclasses__()` 우회 |
| Velocity 2.x SecureUberspector | 부분 가능 | SSTI 자체 차단되나 custom uberspector 등록되면 약화 |
| 길이 제한 (예: 100자) | 가능 | 짧은 페이로드 `{{().__class__.__bases__[0].__subclasses__()[N].__init__.__globals__["...` (수십 자) |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력이 컴파일 대상(첫 번째 인자)에 직접/연결로 삽입 | 후보 |
| 사용자 입력이 데이터 컨텍스트(`{k: v}`)에만 전달 | 제외 (단 XSS 별도 점검) |
| 컴파일 대상이지만 SandboxedEnvironment 적용 확인 | 제외 (sandbox escape 알려진 CVE 없는 한) |
| Spring `return userInput`/`return "redirect:" + x` | 후보 (라벨: `SPRINGEL_VIEW_NAME`) |
| 관리자만 접근 가능한 템플릿 편집 기능 | 후보 유지, 위협 모델은 권한 우회/내부 위협 |

## 후보 판정 제한

서버사이드 템플릿 엔진의 컴파일 함수에 사용자 입력이 템플릿 문자열로 삽입되는 경우만 후보. 데이터 컨텍스트 전달은 제외.
