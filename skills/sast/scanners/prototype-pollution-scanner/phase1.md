---
id_prefix: PROTO
grep_patterns:
  - "__proto__"
  - "constructor\\.prototype"
  - "merge\\s*\\("
  - "extend\\s*\\("
  - "deepMerge\\s*\\("
  - "deepCopy\\s*\\("
  - "defaultsDeep\\s*\\("
  - "lodash\\.merge"
  - "lodash\\.set"
  - "jQuery\\.extend"
  - "Object\\.assign\\s*\\("
  - "dot-prop"
  - "set-value"
  - "object-path"
  - "Object\\.setPrototypeOf"
  - "hoek\\.merge"
  - "hoek\\.applyToDefaults"
  - "koa-body"
  - "koa-multer"
  - "@koa/multer"
  - "qs\\.parse"
  - "allowPrototypes"
  - "bodyParser\\.urlencoded"
  - "express\\.urlencoded"
  - "urlencoded\\s*\\(\\{"
---

> ## 핵심 원칙: "프로토타입이 오염되지 않으면 취약점이 아니다"
>
> `merge`/`extend`/`defaultsDeep` 사용 자체는 취약점이 아니다. 사용자 입력으로 `Object.prototype` 또는 다른 프로토타입에 속성이 실제로 추가/변경되어야 한다. 단순히 "라이브러리에 알려진 취약점"만으로는 부족 — 실제 취약 경로가 도달 가능해야 한다.

## Sink 의미론

Prototype Pollution sink는 "사용자 제어 키가 객체 속성 키 위치(`obj[key]`/path 분리 후 walk)에 도달하고, `__proto__`/`constructor`/`prototype` 키가 차단되지 않는 지점"이다.

| 카테고리 | 위험 sink |
|---|---|
| 재귀 병합 | 커스텀 `merge`/`extend`/`deepMerge`/`defaultsDeep`, `lodash.merge`/`defaultsDeep`/`set`/`setWith` (취약 버전), `jQuery.extend(true, ...)`, `hoek.merge`/`applyToDefaults` (취약), `deap`/`deep-extend`/`merge-deep`/`mixin-deep`/`defaults-deep` |
| 동적 속성 path | `lodash.set(obj, path, val)`, `_.set`, `dot-prop.set`, `set-value`, `object-path.set`, `unset-value` |
| 직접 키 할당 | `obj[req.body.key] = val`, `obj[a][b] = c` (a 또는 b가 사용자 입력) |
| JSON 파서 | 일부 보안 JSON 파서는 `__proto__` 키 제거, 일반 `JSON.parse`는 그대로 둠 |
| 쿼리 파서 | `qs` 라이브러리 (express 기본 `extended:true`)의 중첩 객체 + `__proto__` 키 |
| **입력 파서 (Source-side sink)** | **multipart/form/urlencoded 파서가 `__proto__.key=value` 필드를 객체 키로 reconstruct → Object.prototype 직접 오염. parser 내부가 구조적 sink이며 sink 함수 호출 형태가 없음.** |

`Object.assign`은 1-depth만 복사 → 직접 sink 아님. 단 중첩 객체에서 래핑되면 위험.

## Source-first 추가 패턴

- `req.body` (JSON 파싱 후) — 가장 흔함
- **`req.body` / `ctx.request.body` (multipart/urlencoded 파싱 후)** — multer/formidable/busboy/koa-body가 `__proto__.key=value` 필드를 객체에 그대로 할당
- **`ctx.req.files` / `req.files`** — 파일 필드 메타데이터 객체 키에 `__proto__` 혼입 가능
- `req.query` (`qs` 파서가 중첩 객체 지원)
- URL path 파라미터
- WebSocket 메시지 payload
- 설정 파일 / 사용자 옵션
- YAML/TOML 파싱 결과 (구조적으로 동일)

## 자주 놓치는 패턴 (Frequently Missed)

- **multipart/urlencoded 파서의 `__proto__` 키 수용**: `multer`/`formidable`/`busboy`/`koa-body`/`express.urlencoded({extended:true})` 등이 키 필터링 없이 body를 plain object로 구성. `qs` 우회와 동일 경로, sink 함수 호출 불필요. (파서 라이브러리명은 `file-upload-scanner` 쪽에서 grep 탐지되므로 본 스캐너는 `__proto__`/`allowPrototypes`/`urlencoded` 등 오염 신호에 집중.)
- **`qs` 파서의 `__proto__` 우회**: `qs.parse('__proto__[isAdmin]=true')` → 객체에 `__proto__.isAdmin = true`. Express 4.x 기본 `qs` 사용.
- **MongoDB `$` 연산자와 동시 차단 미흡**: NoSQLi 방어로 `$` prefix는 막아도 `__proto__`는 안 막는 케이스.
- **서버 가젯 (가장 영향도 큼)**:
  - `child_process.spawn` 옵션의 `shell`/`env`/`cwd`가 오염된 속성 참조 → RCE
  - 템플릿 엔진(`ejs`/`pug`/`handlebars`) 컴파일 옵션의 `outputFunctionName` 등이 오염되면 RCE
  - Express `res.render` 옵션
  - `require` 경로 조작
- **클라이언트 가젯**:
  - jQuery, Bootstrap, AngularJS 등에서 옵션 객체의 missing 속성을 prototype에서 lookup → DOM XSS
  - sanitizer bypass (DOMPurify의 hook 옵션 오염)
- **Lodash CVE 체인**: `lodash._.merge`, `_.defaultsDeep`, `_.set`, `_.setWith`, `_.zipObjectDeep` — 4.17.x 미만 다수 CVE.
- **`hoek.merge`/`applyToDefaults`** (CVE-2018-3728).
- **`yargs-parser`/`minimist` `--__proto__.x=y`** (CLI argv 파서 오염).
- **JSON5/JSON.parse + reviver**: reviver 함수가 `__proto__` 키를 처리하지 않음.
- **GraphQL resolver 인자 spread**: `{...args}` 후 키 walk.
- **TypeScript "타입 안전"이 런타임 안전과 무관**: 타입 정의에 `[key: string]` 있어도 prototype 오염 가능.
- **Map/Set이 아닌 plain object를 cache로 사용**: cache key가 사용자 입력이면 오염.
- **Class-based pollution (CVE-2022-21824)**: Node.js `console` formatters 오염 — class method walk로 RCE.
- **`Object.fromEntries(userArray)`**: key가 `__proto__`/`constructor`면 오염.
- **Proxy handler 오염**: 오염된 `Object.prototype.get`으로 모든 proxy 동작 변경.
- **AST parser 오염**: `esprima`/`acorn` 옵션 객체 오염 → 파싱 결과 조작.

## 안전 패턴 (FP Guard)

- **`Object.create(null)` 사용**: 프로토타입 체인 자체가 없어 오염 불가.
- **`Map`/`Set` 사용**: prototype lookup 없음.
- **키 화이트리스트 검증**: `if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue`.
- **`Object.freeze(Object.prototype)`**: 전역 freezing. 일부 라이브러리 호환 문제 있을 수 있음.
- **JSON Schema validator (Ajv 등) 적용** + `additionalProperties: false`.
- **lodash 4.17.21+** + 위험 함수 미사용.
- **`hasOwnProperty` 체크**: walk 시 own property만 처리.
- **`secure-json-parse` 사용**: `__proto__` 키 자동 제거.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `__proto__` 키 차단 | 가능 | `constructor.prototype` 또는 `constructor["prototype"]` 경로 — 별도 차단 필요 |
| `hasOwnProperty` 체크 | 가능 | 오염된 `hasOwnProperty` 자체 (prototype pollution으로 덮어쓴 상태)는 false 반환 가능 — `Object.prototype.hasOwnProperty.call(obj, key)` 필요 |
| `secure-json-parse` (JSON 전용) | 부분 가능 | JSON은 안전하나 multipart/urlencoded 파서는 별도 — 파서별 방어 필요 |
| `Object.freeze(Object.prototype)` | 환경 의존 | 일부 라이브러리가 prototype 확장에 의존 — freeze 후 동작 이상 또는 try/catch로 silent fail |
| Lodash 4.17.21+ 업그레이드 | 부분 가능 | Lodash 내 CVE는 수정되나 custom merge/set 함수는 별도 확인 |
| JSON Schema `additionalProperties: false` | 가능 | 검증 후 다시 merge하는 코드가 있으면 우회 — 검증과 사용 시점 사이 재오염 가능 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → 재귀 merge sink + `__proto__` 차단 없음 | 후보 |
| `lodash.set(obj, userPath, val)` + path 화이트리스트 없음 | 후보 |
| `obj[req.body.key] = val` + key 검증 없음 | 후보 |
| **multipart/urlencoded 파서 사용 + `__proto__` 키 필터링 없음 + body가 plain object로 downstream 전달** | **후보 (라벨: `INPUT_PARSER`)** |
| **`qs.parse` with `allowPrototypes: true`** 또는 Express 기본 query parser 사용 + query 객체 downstream 전달 | 후보 (라벨: `INPUT_PARSER`) |
| `Object.create(null)` 또는 `Map` 사용 확인 | 제외 |
| 키 차단 (`__proto__`/`constructor`/`prototype`) 코드 확인 | 제외 |
| 오염은 가능하나 가젯 부재 (영향 없음) | 후보 유지 (라벨: `NO_GADGET`) — 후속 코드 변경으로 가젯 발생 가능 |
| 오염 + 가젯 식별 (RCE/auth bypass/sanitizer 우회 등) | 후보 (라벨: `WITH_GADGET`) |
| 라이브러리 알려진 CVE이지만 호출 경로 도달 불가 | 제외 |

## 후보 판정 제한

소스코드에서 직접 import/호출하는 경우만 분석 대상. lock 파일의 전이 의존성은 제외. `Object.assign`은 1-depth 복사이므로 제외.
