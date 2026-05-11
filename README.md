# noah-8719

> Claude Code 보안 분석 플러그인. 46개 취약점 스캐너 + AI 자율 탐색으로 정적 분석 + 동적 테스트 + 보고서 생성.

## 설치

```bash
git clone https://github.com/nomarlhack/noah-claude-plugin.git noah-8719
claude --plugin-dir ./noah-8719
```

#### 요구사항

| 항목 | 조건 |
|------|------|
| Claude Code | 최신 버전 |
| Git | 클론 시 필요 |
| Python 3 | 보고서 생성/검증 기능에 필요 |

#### 업데이트

```bash
cd noah-8719 && git pull
```

## 사용법

Claude Code에서 다음 중 하나를 입력합니다:

```
/noah-8719:sast
```

> `sast`, `소스코드 취약점 스캔` 등으로도 트리거됩니다.

## 실행 흐름

```mermaid
flowchart TD
    User["사용자: /noah-8719:sast"] --> S1["Step 1: 실행 경로 확정"]
    S1 --> S2["Step 2: grep 인덱싱"]
    S2 --> S3["Step 3: 프로젝트 스택 파악"]
    S3 --> S4["Step 4: 스캐너 선별\n(다국어 의존성 + AI 검토)"]
    S4 --> S5["Step 5: 정적 분석\n(그룹 병렬 → 파일 저장)"]
    S5 --> BML2["phase1_build_master_list.py\n결과 검증 + master-list.json"]
    BML2 --> S6["Step 6: AI 자율 분석\n(내부 3단계)"]
    S6 --> MLUpdate2["master-list.json 갱신\n(Phase 1 + AI 후보 통합)"]
    MLUpdate2 --> S7["Step 7: 정적·AI 리뷰\n(phase1-review, blind eval)"]
    S7 -->|DISCARD| ML_Safe["status: safe\n(Phase 2 낭비 방지)"]
    S7 -->|CONFIRM / OVERRIDE| Check{후보 발견?}
    ML_Safe --> Check
    Check -->|0건| S12["Step 12: 보고서 생성\n+ safe 분류 자동 섹션"]
    Check -->|1건+| S81["Step 8-1: 동적 테스트 정보 요청\n(URL_PROVIDED + ATTACK_CONSENT 분리)"]
    S81 --> S82["Step 8-2: 도구 권한 확인"]
    S82 --> LLMCheck{LLM 그룹 활성?\nprereq_group=='llm' 후보 1건+}
    LLMCheck -->|Yes| S83["Step 8-3: 그룹 사전 단계\nLLM endpoint probe\nprobe_mode: full / connectivity-only / static-only"]
    LLMCheck -->|No| AttackCheck
    S83 --> AttackCheck{동적 공격 동의?\nATTACK_CONSENT}
    AttackCheck -->|Yes| S84["Step 8-4: Phase 2 실행 (Tier A/B/C 병렬)\n- LLM 스캐너: probe 결과로 분기 (full+endpoint OK → 본 검증, 그 외 → placeholder)\n- 비-LLM 스캐너: 정상 본 검증 (LLM probe 결과 무관)"]
    AttackCheck -->|No| S12
    S84 --> S9["Step 9: 동적 분석 리뷰\n(phase2-review)"]
    S9 -->|불일치 감사 로그| Conflicts["phase1_eval_state.conflicts\n(append-only)"]
    Conflicts --> ChainCheck
    S9 --> ChainCheck{"안전 제외\n후보 2건+?"}
    ChainCheck -->|Yes| S10["Step 10: 연계 분석"]
    ChainCheck -->|No| S11
    S10 --> S11["Step 11: 결과 검증"]
    S11 --> S12
    S12 --> ReviewCheck{"후보 1건+?"}
    ReviewCheck -->|Yes| Review["Step 12-1: report-review\n보고서 본문 품질 개선"]
    ReviewCheck -->|No| Finalize
    Review --> Finalize["Step 12-2: report_finalize.py\n(html → validate → lint → links → open)"]

    style User fill:#e94560,stroke:#e94560,color:#fff
    style S6 fill:#e94560,stroke:#e94560,color:#fff
    style MLUpdate2 fill:#0f3460,stroke:#e94560,color:#eee
    style S7 fill:#0f3460,stroke:#e94560,color:#eee
    style S9 fill:#0f3460,stroke:#e94560,color:#eee
    style Review fill:#0f3460,stroke:#e94560,color:#eee
    style Conflicts fill:#0f3460,stroke:#e94560,color:#eee
    style ML_Safe fill:#533483,stroke:#533483,color:#fff
    style S10 fill:#533483,stroke:#533483,color:#fff
    style Finalize fill:#e94560,stroke:#e94560,color:#fff
    style Check fill:#533483,stroke:#533483,color:#fff
    style ChainCheck fill:#533483,stroke:#533483,color:#fff
    style ReviewCheck fill:#533483,stroke:#533483,color:#fff
    style LLMCheck fill:#533483,stroke:#533483,color:#fff
    style AttackCheck fill:#533483,stroke:#533483,color:#fff
```

## 개요

Noah SAST는 Claude Code의 **스킬(Skill)** 시스템 위에 구축된 통합 취약점 분석 프레임워크입니다.

| 설계 원칙 | 설명 |
|-----------|------|
| **중복 탐색 방지** | Step 0에서 모든 grep 패턴을 사전 인덱싱하여 개별 스캐너가 코드베이스를 중복 탐색하지 않음 |
| **병렬 실행** | 스캐너 그룹을 Agent 도구로 동시 실행 (grep 히트 수 기반 동적 리밸런싱) |
| **단일 진실 원천** | `master-list.json` 파일이 전체 프로세스의 유일한 상태 저장소. Writer 권한 matrix로 모드별 쓰기 범위 분리 |
| **Phase 2 우선** | Phase 2는 실증 데이터. Phase 1 정적 주장과 모순 시 항상 Phase 2 증거로 status 확정 (인프라 방어 관측 포함) |
| **인간 개입 최소화** | 파이프라인 차단 없이 자동 수렴. Phase 1↔Phase 2 불일치는 append-only 감사 로그(`conflicts`)로만 기록 |
| **오탐 방지** | Sink-first + Source-first 병행 분석, phase1-review/phase2-review의 blind eval + Phase 2 증거 기반 판정, 보고서 조립 후 본문 품질 개선 (체크리스트 10항목) |
| **다중 언어 지원** | Node.js, Python, Ruby, Java, Go 매니페스트에서 의존성을 파싱하여 스캐너 선별 |

## 스캐너 목록

| # | 스캐너 | 취약점 유형 | 그룹 |
|---|--------|-----------|------|
| 1 | xss-scanner | Cross-Site Scripting (Reflected/Stored) | url-navigation |
| 2 | dom-xss-scanner | DOM-based XSS | url-navigation |
| 3 | open-redirect-scanner | Open Redirect | url-navigation |
| 4 | crlf-injection-scanner | CRLF Injection / HTTP Response Splitting | response-header |
| 5 | host-header-scanner | Host Header Attack / IP Spoofing | response-header |
| 6 | http-method-tampering-scanner | HTTP Method Tampering | response-header |
| 7 | sqli-scanner | SQL Injection | db-query |
| 8 | nosqli-scanner | NoSQL Injection | db-query |
| 9 | command-injection-scanner | OS Command Injection | process-execution |
| 10 | ssti-scanner | Server-Side Template Injection | process-execution |
| 11 | ssrf-scanner | Server-Side Request Forgery | server-request |
| 12 | pdf-generation-scanner | PDF Generation SSRF/LFI | server-request |
| 13 | path-traversal-scanner | Path Traversal / LFI | file-system |
| 14 | file-upload-scanner | Unrestricted File Upload | file-system |
| 15 | zipslip-scanner | Zip Slip (Archive Path Traversal) | file-system |
| 16 | xxe-scanner | XML External Entity | xml-serialization |
| 17 | xslt-injection-scanner | XSLT Injection | xml-serialization |
| 18 | deserialization-scanner | Insecure Deserialization | xml-serialization |
| 19 | jwt-scanner | JWT Tampering | auth-protocol |
| 20 | oauth-scanner | OAuth Authentication Bypass | auth-protocol |
| 21 | saml-scanner | SAML Authentication Bypass | auth-protocol |
| 22 | csrf-scanner | Cross-Site Request Forgery | auth-protocol |
| 23 | idor-scanner | Insecure Direct Object Reference | auth-protocol |
| 24 | redos-scanner | Regular Expression DoS | client-rendering |
| 25 | css-injection-scanner | CSS Injection | client-rendering |
| 26 | prototype-pollution-scanner | Prototype Pollution | client-rendering |
| 27 | http-smuggling-scanner | HTTP Request Smuggling | infra-config |
| 28 | sourcemap-scanner | Source Map Exposure | infra-config |
| 29 | subdomain-takeover-scanner | Subdomain Takeover | infra-config |
| 30 | csv-injection-scanner | CSV / Formula Injection | data-export |
| 31 | graphql-scanner | GraphQL Vulnerabilities | protocol-check |
| 32 | websocket-scanner | WebSocket Vulnerabilities | protocol-check |
| 33 | soapaction-spoofing-scanner | SOAPAction Spoofing | protocol-check |
| 34 | ldap-injection-scanner | LDAP Injection | protocol-check |
| 35 | xpath-injection-scanner | XPath Injection | protocol-check |
| 36 | security-headers-scanner | Security Headers (CSP, CORS, HSTS 등) | infra-config |
| 37 | business-logic-scanner | Business Logic Vulnerabilities | business-logic |
| 38 | springboot-hardening-scanner | Spring Boot Hardening (설정 보안) | infra-config |
| 39 | cookie-security-scanner | Cookie Security (Secure, HttpOnly, Persistent 등) | auth-protocol |
| 40 | tls-scanner | TLS/SSL Misconfiguration | infra-config |
| 41 | validation-logic-scanner | Validation Logic Mismatch | business-logic |
| 42 | prompt-injection-scanner | LLM Prompt Injection (Direct/Indirect) | llm |
| 43 | system-prompt-leakage-scanner | LLM System Prompt Leakage | llm |
| 44 | insecure-output-handling-scanner | LLM Insecure Output Handling | llm |
| 45 | unbounded-consumption-scanner | LLM Unbounded Consumption | llm |
| 46 | android-deeplink-scanner | Android Deeplink / WebView | mobile |

## 디렉토리 구조

```
noah-8719/
├── .claude-plugin/
│   └── plugin.json                # 플러그인 매니페스트
├── hooks/
│   └── hooks.json                 # 보안 후크
├── skills/
│   └── sast/
│       ├── SKILL.md               # 오케스트레이터 (실행 프로세스 상세)
│       ├── scanners/              # 46개 취약점 스캐너 (각 phase1.md + phase2.md)
│       ├── prompts/               # 서브 에이전트 지시 문서 (LLM 그룹 사전 단계 포함)
│       ├── tools/                 # Python 유틸리티 스크립트 (LLM 채널 어댑터 포함)
│       ├── sub-skills/            # 내부 서브스킬
│       │   ├── scan-report/       # 보고서 생성
│       │   ├── scan-report-review/# 보고서 정확성 검증
│       │   └── chain-analysis/    # 공격 체인 연계 분석
│       └── tests/
├── install.sh
├── uninstall.sh
├── VERSION
├── LICENSE
└── README.md
```

## 상세 문서

| 문서 | 경로 | 내용 |
|------|------|------|
| 오케스트레이터 | `skills/sast/SKILL.md` | 전체 실행 프로세스 (Step 1~12), 스캐너 그룹 편성, 동적 분석 Tier, 결과 검증 |
| Phase 1 공통 지침 | `skills/sast/prompts/guidelines-phase1.md` | Sink-first + Source-first 분석, 래퍼 추적, 의미 기반 판정, Source 도달성 |
| Phase 2 공통 지침 | `skills/sast/prompts/guidelines-phase2.md` | 동적 테스트 절차, 에러 핸들링, 차단 응답 처리, 도메인 안전 규칙 |
| AI 자율 탐색 | `skills/sast/prompts/ai-discovery-agent.md` | 3단계 자율 탐색, 7개 제외 필터, Phase 1 충돌 해소 |
| LLM 그룹 사전 단계 | `skills/sast/prompts/llm-endpoint-probe-agent.md` | LLM endpoint 식별·확정 (probe_mode: full / connectivity-only / static-only). LLM 4개 스캐너 Phase 2의 단일 입력 계약 생성 |
| LLM 채널 어댑터 | `skills/sast/tools/llm_channel_probe.py` | HTTP / ws-raw / ws-stomp / SSE 단일 어댑터. probe-agent와 Phase 2가 공유하는 헬퍼 (의존성: `websocket-client`, `requests`) |
| 보고서 생성 | `skills/sast/sub-skills/scan-report/SKILL.md` | 스켈레톤 → 병렬 작성 → 조립 → HTML 변환 → 검증. safe 분류(6종) 섹션 자동 생성 |
| 평가·리뷰 (dispatcher) | `skills/sast/sub-skills/scan-report-review/SKILL.md` | 3모드 진입점 안내. 모드별 파일을 직접 Read하도록 오케스트레이션 |
| └ 공통 판정 원칙 | `skills/sast/sub-skills/scan-report-review/_principles.md` | Source 도달성, 부재 주장, 반환 형식 규칙 |
| └ 공통 계약 | `skills/sast/sub-skills/scan-report-review/_contracts.md` | Writer 권한 matrix, exit code, master-list.json 스키마, DISCARD 보호 |
| └ Phase 1 품질 평가 | `skills/sast/sub-skills/scan-report-review/phase1-review.md` | blind eval, 5축 독립 판정(축 5: 현실 영향 가중치), DISCARD 시 Phase 2 낭비 방지 |
| └ Phase 2 증거 해석 | `skills/sast/sub-skills/scan-report-review/phase2-review.md` | Phase 2 우선 원칙, status 확정, `conflicts` 감사 로그 |
| └ 보고서 본문 품질 개선 | `skills/sast/sub-skills/scan-report-review/report-review.md` | 조립된 MD 본문 설명 보강 — 스니펫·POC 교정, 중복 통합, 원인 분석·권장 조치 보강 (판정 필드 불변) ([3모드 상세 가이드](skills/sast/docs/review-modes.md)) |
| 연계 분석 | `skills/sast/sub-skills/chain-analysis/SKILL.md` | R1~R5 체인 구성 규칙, 전제조건/연계 매트릭스 |
| 개별 스캐너 | `skills/sast/scanners/{name}/phase1.md` | Sink 의미론, 안전 패턴, 판정 의사결정, 자주 놓치는 패턴 |
