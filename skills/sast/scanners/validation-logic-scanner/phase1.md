---
id_prefix: VAL
grep_patterns:
  # Loose equality (type confusion sink)
  - "==\\s*null"
  - "!=\\s*null"
  - "==\\s*undefined"
  - "!=\\s*undefined"
  - "==\\s*false"
  - "==\\s*true"
  - "==\\s*0\\b"
  - "==\\s*''"
  - "==\\s*\"\""
  # Validation framework (validation boundary detection)
  - "Joi\\."
  - "\\.validate\\s*\\("
  - "ValidationPipe"
  - "@Valid\\b"
  - "express-validator"
  - "class-validator"
  - "checkSchema"
  - "ajv"
  # Client-side validation indicators
  - "checkValidity"
  - "setCustomValidity"
  # Schema/DTO configuration
  - "additionalProperties"
  - "stripUnknown"
  - "allowUnknown"
  - "forbidNonWhitelisted"
  - "@IsOptional"
  - "@IsNotEmpty"
  # Null/type check patterns
  - "typeof\\s+\\w+"
  - "instanceof\\s+"
---

> ## 핵심 원칙: "검증이 없는 것 자체가 취약점이 아니라, 검증 불일치로 인해 의도하지 않은 동작이 발생할 수 있어야 후보다"
>
> 단순히 "서버 검증이 없다"만으로 후보 판정하지 않는다. 검증 불일치가 **실제로 악용 가능한 동작**(인증 우회, 데이터 손상, 비정상 상태 전이 등)을 초래해야 후보다.

## Sink 의미론

이 스캐너의 "Sink"는 **사용자 입력이 검증 로직을 거쳐 비즈니스 로직에 도달하는 지점으로, 검증 불일치·타입 혼동·null 처리 결함·스키마 검증 누락이 보안에 영향을 미치는 곳**이다.

### VALIDATION_MISMATCH — 유효성 검사 로직 불일치

| 카테고리 | 패턴 |
|---|---|
| 클라이언트 전용 검증 | HTML `required`, `pattern`, `maxlength`, `checkValidity()`, `setCustomValidity()` — 서버에 대응 검증 없음 |
| 프론트엔드 정규식 vs 서버 정규식 | 클라이언트 `/^\d{3}-\d{4}$/` vs 서버 `/\d+/` (서버 정규식이 더 느슨) |
| 조건부 검증 | 특정 조건(역할, 플랜 등)에서만 검증이 활성화되어 우회 가능 |
| API 라우트 검증 누락 | 일부 엔드포인트에만 validation middleware가 적용되고 나머지는 미적용 |

### TYPE_CONFUSION — 타입 혼동

| 카테고리 | 패턴 |
|---|---|
| JS loose equality | `==` 비교로 인한 타입 강제 변환 (`"0" == false → true`, `"" == 0 → true`) |
| PHP loose comparison | `"0e123" == "0e456" → true` (magic hash), `0 == "any_string" → true` (PHP 7 이하) |
| 배열/객체 주입 | 문자열 파라미터에 배열/객체 전달 (`param[]=value`, JSON `{"param": ["value"]}`) |
| 숫자 파싱 차이 | `parseInt("123abc") === 123` (JavaScript), 선행 0이 8진수로 해석 |
| Boolean 강제 변환 | `"false"` 문자열이 truthy로 평가, `0`과 빈 문자열의 falsy 동작 |

### NULL_SAFETY — Null 안전성 결함

| 카테고리 | 패턴 |
|---|---|
| null/undefined 참조 | `user.role` 접근 시 `user`가 null → 에러 또는 기본값 폴백으로 의도치 않은 권한 부여 |
| 결함 있는 null 검사 | `if (value)` vs `if (value !== null)` — `0`, `""`, `false`가 falsy로 처리되어 유효한 값 거부 |
| Optional chaining 미사용 | `obj.nested.prop` — `nested`가 null이면 TypeError 발생, 에러 핸들러가 기본값을 반환하여 로직 우회 |
| null 병합 연산자 오용 | `value ?? defaultValue` — `0`이나 `""`는 null이 아니므로 통과하지만 `value || defaultValue`에서는 기본값으로 대체 |
| 필수 파라미터에 null 전달 | API에서 필수 필드에 `null`을 전달하면 ORM이 NULL 저장, 이후 비교 로직에서 `NULL != anything` |

### SCHEMA_DEFECT — 스키마/모델 검증 결함

| 카테고리 | 패턴 |
|---|---|
| additionalProperties 미제한 | JSON Schema에 `additionalProperties: false` 미설정 → 미정의 필드 수용 |
| stripUnknown 미설정 | Joi/Yup 스키마에서 알 수 없는 필드를 자동 제거하지 않음 |
| forbidNonWhitelisted 미설정 | NestJS ValidationPipe에서 DTO 외 필드 수용 |
| 필수/선택적 혼동 | `@IsOptional()` + `@IsNotEmpty()` 동시 적용 (모순), required 필드 누락 시 기본값 사용 |
| ORM 직접 바인딩 | `Model.create(req.body)` — DTO 없이 요청 바디를 직접 모델에 바인딩 |

## Source-first 추가 패턴

- API 컨트롤러의 `req.body`, `req.query`, `req.params` 사용처
- GraphQL resolver의 `args`/`input` 파라미터
- 폼 핸들러의 `request.POST`, `request.GET` (Django)
- Spring의 `@RequestBody`, `@RequestParam`, `@ModelAttribute`
- 환경별 검증 설정 차이 (개발 환경에서 검증 비활성화)
- API 게이트웨이/미들웨어의 검증 설정

## 자주 놓치는 패턴 (Frequently Missed)

- **파일 확장자 검증**: 클라이언트에서 `accept=".jpg,.png"` 제한하지만 서버에서 MIME 타입/확장자 미검증
- **열거형 검증 누락**: 상태값(status, role 등)을 문자열로 받으면서 허용 목록 검증 없음
- **배열 길이 미제한**: 배열 파라미터의 최대 길이를 제한하지 않아 대량 데이터 주입 가능
- **중첩 객체 검증 누락**: 최상위 필드만 검증하고 중첩 객체의 필드는 미검증
- **Content-Type 불일치**: `application/json` 기대하지만 `application/x-www-form-urlencoded`도 수용하여 파싱 차이 발생
- **숫자 범위 미검증**: 나이, 수량 등 논리적 범위가 있는 필드에 음수/극대값 허용
- **유니코드 정규화 누락**: 이메일/username에 `Café` vs `Café` (NFC/NFD) 혼용 — 동일 사용자 중복 등록/계정 혼동
- **Zero-width/invisible 문자**: `user\u200Bname`이 원본과 달라 중복 허용 또는 검증 우회
- **Case sensitivity 차이**: 이메일 `Admin@example.com`과 `admin@example.com` — 저장은 case-sensitive, 검증은 lowercase 비교
- **Locale-aware comparison**: Turkish locale에서 `i`.toUpperCase() → `İ` (대문자 dot 포함) — 문자 비교 불일치
- **JSON duplicate keys**: 대부분 파서가 마지막 값 유지하나 일부는 첫 값 — 파서별 동작 차이로 우회
- **Positional vs named parameter 혼합**: API가 둘 다 받으면 다른 처리 경로 유발
- **NaN/Infinity 처리**: `JSON.parse`에 없는 특수값이지만 `parseFloat`/`Number`는 허용 — 범위 검증 후 NaN 통과

## 안전 패턴 (FP Guard)

- **NestJS ValidationPipe + class-validator DTO**: `@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))` — 미정의 필드 자동 거부
- **Joi/Yup 스키마 + `stripUnknown: true`**: 알 수 없는 필드 자동 제거
- **JSON Schema + `additionalProperties: false`**: 정의되지 않은 필드 거부
- **TypeScript strict mode**: `strictNullChecks` 활성화 시 컴파일러가 null 참조 방지
- **Spring `@Valid` + DTO 패턴**: Bean Validation으로 필드별 검증 적용
- **Express-validator 체인**: `body('field').isString().isLength({ min: 1, max: 100 })` — 타입 + 길이 검증
- **ORM allowlist/select**: Sequelize `attributes`, Mongoose `select`, ActiveRecord `permit` — 바인딩 필드 제한
- **`===` 일관 사용 (ESLint eqeqeq rule)**: strict equality만 사용하면 타입 혼동 방지

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 클라이언트에만 검증 존재 + 서버에 대응 검증 없음 + 상태 변경 API | 후보 (VALIDATION_MISMATCH) |
| loose equality(`==`)가 보안 관련 비교(인증, 권한, 토큰)에 사용 | 후보 (TYPE_CONFUSION) |
| `typeof` 체크 없이 사용자 입력을 산술/비교 연산에 사용 | 후보 (TYPE_CONFUSION) |
| null 참조 시 에러 핸들러가 기본 권한/역할을 부여 | 후보 (NULL_SAFETY) |
| `additionalProperties: false` 미설정 + 상태 변경 API | 후보 (SCHEMA_DEFECT) |
| `===` 사용 (strict equality) | 제외 |
| 서버 검증이 클라이언트보다 같거나 더 엄격 | 제외 |
| TypeScript `strictNullChecks` + 타입 가드 사용 | 제외 |
| ORM allowlist/DTO 패턴으로 필드 제한 | 제외 |
| 읽기 전용 API (GET)에서 검증 누락 | 제외 (상태 변경 없음) |

## 후보 판정 제한

- **모든 loose equality를 후보로 올리지 않는다**: `== null` (null/undefined 동시 체크 관용구)은 JavaScript에서 일반적인 안전 패턴이다. 보안 관련 비교에서만 후보로 판정한다.
- **프레임워크 기본 검증을 신뢰한다**: Spring Boot의 `@Valid`, NestJS의 `ValidationPipe`, Django의 ModelForm 등은 프레임워크 수준에서 검증을 제공한다. 명시적 비활성화가 없으면 안전으로 판단한다.
- **읽기 전용 엔드포인트는 대상 외**: 상태를 변경하지 않는 GET 요청에서의 검증 누락은 본 스캐너의 범위가 아니다.
- **개발 환경 한정 설정 제외**: 테스트/개발 환경에서만 검증이 비활성화되는 경우는 후보에서 제외한다.
