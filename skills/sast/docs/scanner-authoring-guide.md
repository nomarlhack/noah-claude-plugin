# 스캐너 작성 가이드

스캐너 디렉토리(`scanners/<name>-scanner/`)의 `phase1.md`/`phase2.md` 작성 시 따라야 할 문서 구조 표준이다.

신규 스캐너에 적용한다. 기존 스캐너는 점진 마이그레이션 대상.

---

## phase1.md 구조 표준

### 기본형 — sink 추적 스캐너

```
---
id_prefix: <SCANNER_ID>
grep_patterns: [...]
---

> ## 핵심 원칙: "<한 문장 판정 철학>"
>
> <2~3문장 부연 — 무엇을 보고하고 무엇을 보고하지 않는지>

## Sink 의미론                          — sink 정의 + 위험 sink 표
## Source-first 추가 패턴               — 입력 진입점 후보
## 자주 놓치는 패턴 (Frequently Missed)  — 패턴 카탈로그
## 안전 패턴 (FP Guard)                 — 코드 패턴 기준 제외
## 우회 가능 패턴                        — 방어 코드가 있어도 우회 가능 (sink 추적형 권장)
## 후보 판정 의사결정                    — 판정 매트릭스 (표)
## 후보 판정 제한                        — 스코프 기준 제외 (분석 범위 밖)
```

### 변형형 — 라벨/항목 기반 (cookie-security, tls, security-headers, business-logic 등)

```
---
id_prefix: ...
grep_patterns: ...
---

> ## 핵심 원칙: "..."

## Sink 의미론 (또는 ## 분석 방법)
## 점검 라벨 및 판정 테이블 (또는 ## 분석 대상)
  ### `LABEL_A` — 짧은 설명
  ### `LABEL_B` — 짧은 설명
## 후보 판정 의사결정
## 후보 판정 제한
```

### 섹션 의미 구분 (헷갈리기 쉬운 항목)

| 섹션 | 제외 기준 |
|---|---|
| `## 안전 패턴 (FP Guard)` | **코드 패턴** — sink 자리에 방어 코드(PreparedStatement, escape 등)가 있으면 제외 |
| `## 우회 가능 패턴` | 방어가 있어 보이지만 우회 가능한 회색 코드 — 후보 유지하되 사유 기록 (sink 추적형 스캐너에서 권장. 라벨 기반 변형형/정보 노출형은 부적합) |
| `## 후보 판정 제한` | **스코프** — 분석 대상 위치/컨텍스트가 아님 (마이그레이션, 시드, 테스트, 빌드 스크립트) |

### 핵심 원칙 인용 블록

frontmatter 직후 `>` 인용 블록으로 1문장 판정 철학과 2~3문장 부연을 둔다. 작성자에게 도메인 핵심 가치를 강제 명문화시켜, 후속 패턴 추가 시 일관성을 유지하기 위함.

기준 예시: `scanners/sqli-scanner/phase1.md`

### 금지 헤딩

- `## 인접 스캐너 분담` — 표준에서 제외 (필요하면 본문에 인라인 메모로)
- 비표준 명칭 (예: `## 자주 놓치는 파일`) — 표준 명칭(`## 자주 놓치는 패턴`) 사용

---

## phase2.md 구조 표준

### 기본형 — 단일 취약점

```
(선택) ### 정찰 페이로드    — 진입점/엔드포인트/스키마 동적 탐색 (해당 스캐너만)
       #### <sub-section>  — 페이로드 그룹 (h4, 본문과 구분)
### 기본 페이로드           — 표준 페이로드 cheat sheet (시나리오별, 엔진/DBMS 변형)
       #### <sub-section>
### 우회 페이로드           — 차단 시 대안 (방어별 표, 인코딩/WAF 변형)
(선택) ### 참고사항        — 도메인 특수 응답 신호 + 검증 노하우
```

**헤딩 계층 원칙:**
- phase2.md는 `## Phase 2:` 래퍼 **없음** — `### 기본 페이로드`가 최상위
- 4 섹션은 모두 `### h3`: 정찰/기본/우회/참고사항
- sub-section은 `#### h4`: 본문보다 시각적으로 큰 크기 보장 (`**bold:**` 금지)
- 인라인 강조는 `**bold**` 가능 (단독 소제목 용도 금지)

**시나리오 분리 허용 형식** (페이로드가 많을 때, h4 사용):
```
### 기본 페이로드

#### Classic SQLi
#### Blind SQLi
#### ORDER BY 위치
```

**엔진/환경 변형은 페이로드 내부 표로 포함** (별도 섹션 금지):
```
### 기본 페이로드

| DB | Time-based | OOB |
|---|---|---|
| MySQL | `' AND SLEEP(3)--` | `LOAD_FILE('/etc/passwd')` |
```

**페이로드 작성 규칙:**
- **순수 페이로드 본체만** — `curl -X POST "https://target/..."` 같은 wrapper 금지
- **페이로드 옆 짧은 컨텍스트 주석** — `(query/body/header/XML body)`, `(MySQL)`, `(GET)` 등
- **각 페이로드 1줄 설명** — `' OR '1'='1' --` — Boolean (query)
- **파괴적 페이로드 금지** — `rm -rf`, `DROP TABLE`, fork bomb 등 가용성/무결성 영향 페이로드는 sandbox 가드 대신 **삭제**. 읽기 전용 PoC(`id`, `/etc/passwd`, OOB callback)로 충분

### 변형형 — 다중 라벨 (business-logic, validation-logic, cookie-security, tls, security-headers, springboot-hardening 류)

```
### 기본 페이로드 (또는 정찰/우회/참고사항)
#### `LABEL_A`
  sub-content
#### `LABEL_B`
  sub-content
### 참고사항
```

또는 라벨별로 기본/우회를 섞어 쓰는 경우 `## 라벨별 테스트 절차` 같은 조직 섹션을 예외적으로 허용(business-logic).

### 정찰 페이로드 적용 대상

동적 진입점/스키마/시그니처 탐색이 의미 있는 스캐너만 추가:

**엔드포인트/스키마 탐색:**
- GraphQL (`/graphql`, `/graphiql` enumeration + introspection)
- Springboot Hardening (`/actuator/*` enumeration + Spring Boot fingerprint)
- Sourcemap (`.map` 추측 + JS/CSS enumeration)
- Subdomain Takeover (DNS CNAME 수집 + fingerprint)
- Security Headers (path별 헤더 일괄 조회)
- SOAPAction Spoofing (WSDL/MEX endpoint + operation enumeration)
- WebSocket (WS endpoint 후보 + subprotocol enumeration)

**자산/속성 탐색:**
- Cookie Security (Set-Cookie 발행 시점 수집 + 속성 파싱)
- JWT (JWKS endpoint 발견 + 토큰 헤더 분석)
- CSRF (SameSite 쿠키 / CORS 정책 / Sec-Fetch 검증 활용 확인)
- Deserialization (요청/응답 직렬화 시그니처 탐지)

sink 추적형 (sqli/xss/cmdi/ssrf/idor/path-traversal/xxe 등)은 정찰 페이로드 불필요 — Phase 1이 sink 식별. 정찰 단계가 곧 Phase 1 정적 분석.

### 금지 헤딩 (모두 제거 대상)

- `## Phase 2: 동적 테스트 (검증)` 래퍼 — 4 섹션이 최상위
- `#### 사전 준비` — guidelines-phase2.md 지침 7/9/11 중복
- `#### 검증 순서` — 동적 진단 공통 원칙은 guidelines 책임
- `#### 검증 기준` (단독) — 참고사항이나 페이로드 설명에 통합
- `#### 응답 분석 기준` — AI가 판정. 도메인 특수 신호는 참고사항으로
- `#### 테스트 방법` — 자명
- `#### curl 예시` — 페이로드와 중복
- `#### JSON 바디 테스트` — 페이로드 컨텍스트 주석으로 흡수
- `#### [엔진별 변형]` 단독 — 페이로드 내부 표
- `#### Tools` / `#### References` — phase2.md 비대화 회피
- 단독 소제목으로 `**X:**` 사용 — `#### X`로 승격

### 핵심 원칙

- **검증 cheat sheet**: Phase 1 후보의 검증을 위한 페이로드 카탈로그. 풍부하게 작성
- **순수 페이로드**: curl/Playwright wrapper 없이 페이로드 본체만. 도구 선택은 Phase 2 에이전트가 guidelines 따라 자체 결정
- **phase1 ↔ phase2 연계**: phase1 `## 우회 가능 패턴` 표의 각 행이 phase2 `**우회 페이로드:**`로 구체화
- **응답 분석은 AI 판단**: 명시 표 대신 페이로드 옆 짧은 신호(`→ "uid=" 응답 시 확인됨`)나 참고사항으로 위임

### 기준 예시

`scanners/sqli-scanner/phase2.md`, `scanners/graphql-scanner/phase2.md`
