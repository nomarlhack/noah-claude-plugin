---
name: scan-report
description: "noah-sast 분석 결과와 동적 테스트 증거를 취합해 통합 및 단일 스캐너 보고서를 작성하는 서브스킬."
---

# Scan Report — 취약점 스캔 보고서 작성

noah-sast에서 호출되며, `<NOAH_SAST_DIR>`은 이미 결정된 상태이다. 취합된 분석 결과 데이터를 입력받아 보고서를 작성한다.

> `[필수]`는 규약 강제 항목이다. 태그가 없는 항목도 모두 준수 의무가 있다.

> **참고**: 취약점 상세 형식(확인됨/후보/이상 없음 템플릿), 통합 보고서 구조 마크다운 예시, 공통 HTML 사양 + 앵커 스크립트는 별도 파일 `<NOAH_SAST_DIR>/sub-skills/scan-report/vuln-format.md`에 정의되어 있다. 본 SKILL.md는 오케스트레이션만 다룬다.

**입력:**
- 스캐너별 분석 결과 (확인됨/후보/안전 판정, Source→Sink 경로, 코드 스니펫)
- AI 자율 탐색 결과 (`<PHASE1_RESULTS_DIR>/evaluation/ai-discovery-eval.md`, 부재 시 `<PHASE1_RESULTS_DIR>/ai-discovery.md` fallback)
- 동적 테스트 결과 (curl 요청/응답 증거)
- 인증 경계(`<PHASE1_RESULTS_DIR>/auth-boundary.json`): 표면별 {진입 도메인·base path·자격증명·신원 출처·인증 근거·도달성}. 인증 경계 표/흐름도 작성과 후보 `**진입 경계**:` 필드·POC 호스트 결정에 사용
- 이상 없음 스캐너의 점검 항목 요약
- 미적용 스캐너 목록 및 제외 사유

**출력:**
- 통합 보고서: `noah-sast-report.md` + `noah-sast-report.html`
- 단일 스캐너 보고서: `{scanner-type}-scan-report.md` + `.html`

> **작업 디렉토리에 여러 프로젝트가 존재하더라도, 보고서는 반드시 1개만 생성한다.** 프로젝트별로 보고서를 분리하지 않는다. 각 취약점의 `**위치**:` 필드에 프로젝트 경로가 포함되므로 독자가 프로젝트를 식별할 수 있다.

---

## 보고서 생성 프로세스

### Step 1: 스켈레톤 자동 생성 (`generate_skeleton.py`)

> **[변경]** 메인 에이전트가 스켈레톤을 직접 작성하지 않는다. `generate_skeleton.py`가 master-list.json·auth-boundary.json·Phase 1 결과 디렉토리에서 스켈레톤을 100% 기계적으로 생성한다. AI가 구조를 잘못 작성해서 개요 카드·대시보드·인증경계 표가 깨지는 문제를 원천 차단한다.

메인 에이전트가 다음 명령을 실행한다:

```bash
python3 <NOAH_SAST_DIR>/sub-skills/scan-report/generate_skeleton.py \
  --master-list <PHASE1_RESULTS_DIR>/master-list.json \
  --auth-boundary <PHASE1_RESULTS_DIR>/auth-boundary.json \
  --phase1-dir <PHASE1_RESULTS_DIR> \
  --project-root <PROJECT_ROOT> \
  --scan-date <SCAN_DATE> \
  --stack "<STACK>" \
  --test-env "<SANDBOX_DOMAINS_쉼표구분>" \
  --output /tmp/skeleton.md
```

**생성 내용** (AI 개입 없음):
- `## 개요` 헤딩 + 5개 메타 필드 (올바른 위치 보장)
- 인증 경계 게이트웨이·클라이언트·경로 표 (auth-boundary.json 직접 파싱)
- mermaid 흐름도 (routes/clients/gateways >= 2 시 자동 생성, 특수문자 이스케이프 보장)
- 4개 플레이스홀더 (`<!-- CHAIN_SECTION_HERE -->` 등)
- 이상 없음 스캐너 표 (Phase 1 결과에서 자동 집계)
- 미적용 스캐너 표 (scanners/ 디렉토리 - expected 스캐너 차집합)
- 총괄 수치는 assemble_report.py의 inject_summary_table()이 이후 단계에서 채움

**`--stack` 인수**: Step 3에서 파악한 프로젝트 스택. 예:
```
"언어 :: Kotlin 2.1.21, Java 17 ;; 웹 :: Spring MVC, Spring Boot 3.2.5 ;; 스토리지 :: MongoDB, Redis"
```

**`--test-env` 인수**: Step 8-1에서 확인된 sandbox 도메인 목록(쉼표 구분). `SANDBOX_DOMAINS`에서 추출. 없으면 빈 문자열.

생성 완료 후 `/tmp/skeleton.md` 내용을 간단히 확인(`head -20`)하여 이상 없으면 Step 2로 진행한다.

**[필수] `## 연계 시나리오`를 스켈레톤에 직접 추가하지 않는다.** assemble_report.py의 `--chain` 인자로 자동 렌더링된다.

### Step 2: 스캐너별 상세 섹션 — JSON 제출 + 스크립트 렌더 (서브에이전트)

> **[변경]** 서브에이전트가 자유 형식 MD 텍스트를 반환하지 않는다. **구조화된 JSON을 Write 도구로 임시 파일에 저장**하고, `render_vuln_section.py`가 확정된 MD로 렌더링한다. AI가 헤딩 레벨, 필드 순서, 형식을 잘못 작성하는 문제를 원천 차단한다.

**서브에이전트 프롬프트에 반드시 포함할 내용:**

1. `<NOAH_SAST_DIR>/sub-skills/scan-report/vuln_section_prompt_template.md`를 Read 도구로 읽고 그 안의 JSON 반환 지침을 따른다. (MD 텍스트 반환 금지 — JSON만 반환)
2. 해당 스캐너의 취약점 데이터:
   - Phase 1 결과: `<PHASE1_RESULTS_DIR>/evaluation/<scanner-name>-eval.md` (phase1-review 평가본, 부재 시 원본 MD fallback)
   - Phase 2 증거: `<PHASE1_RESULTS_DIR>/<scanner-name>-phase2.md` — `evidence.commands[]`(실행한 curl)·`evidence.responses[]`(실제 응답)를 JSON의 `poc.steps` content에 verbatim 인용
   - AUTH_BOUNDARY 슬라이스: 이 스캐너 후보들의 surface_key에 매칭되는 routes/gateways/clients 행만 동봉 (전체 auth-boundary.json 금지)
3. JSON 필드 작성 규칙 (vuln_section_prompt_template.md 참조):
   - `status`: "확인됨" 또는 "후보"만 사용. 심각도(HIGH/MEDIUM/LOW) 금지.
   - `entry_boundary`: AUTH_BOUNDARY 슬라이스에서 자연어로 기술. `도달성=확정`이면 실제 호스트, 아니면 `<TARGET_HOST>` 플레이스홀더.
   - `poc.steps`: 최소 3단계. Step 2 content에 curl 코드블록 필수. 동적 실행된 경우 phase2.md evidence.commands[] verbatim 인용.

**서브에이전트 작업 흐름:**

```
1. vuln_section_prompt_template.md Read
2. eval MD + phase2.md Read
3. JSON 구성 (구조화된 취약점 데이터)
4. Write 도구로 /tmp/sr_<scanner>.json 저장 (MD 아닌 JSON)
5. 저장 완료 경로 반환
```

**메인 에이전트가 각 JSON을 수신 후 실행:**

```bash
python3 <NOAH_SAST_DIR>/sub-skills/scan-report/render_vuln_section.py \
  /tmp/sr_xss.json /tmp/sr_ssrf.json \
  --output /tmp/sr_rendered.md
```

여러 스캐너를 한 번에 렌더링하면 자동으로 합쳐진다. `--validate-only`로 schema 검증만 먼저 수행 가능.

**관련 스캐너 묶음 분할**: 하나의 서브에이전트가 담당하는 취약점은 **최대 10건**. 초과 시 분할.

**AI 자율 탐색 결과 섹션:**

scanner를 `"ai-discovery"`로 설정한 동일한 JSON 형식을 사용한다. `vuln_section_prompt_template.md`의 지침을 그대로 따르되, 모든 status는 "후보"만 사용.

결과를 `/tmp/sr_ai.json`으로 저장하고 `render_vuln_section.py --output /tmp/ai_section.md`로 렌더링 후, `assemble_report.py`의 `--ai` 인자로 전달.

**서브에이전트 실패 시 fallback:**

JSON 제출이 실패하면 MD 텍스트를 직접 Write 도구로 저장 (기존 방식). render_vuln_section.py 호출 없이 MD 파일을 그대로 `--sections` 인자로 사용.

### Step 3: MD 보고서 조립

**[필수] Write 도구를 직접 사용하지 않는다.** 보고서 전체를 한 번에 Write하면 32K 토큰 한도를 초과할 수 있다. 반드시 아래 Python 스크립트로 조립한다. **스크립트 실행 실패 시:** 서브에이전트 결과를 `\n\n---\n\n`로 연결하여 Write 도구로 직접 저장하는 fallback을 수행한다.

**조립 절차:**

1. Step 1에서 `generate_skeleton.py`가 생성한 `/tmp/skeleton.md`를 사용한다 (별도 Write 불필요).
2. Step 2에서 `render_vuln_section.py`가 렌더링한 MD 파일들 (예: `/tmp/sr_rendered.md`)을 사용한다.
3. 연계 분석을 수행한 경우, `chain_analysis` 데이터를 JSON 파일로 저장한다 (예: `/tmp/chain.json`).
4. AI 자율 탐색 결과 MD (`/tmp/ai_section.md`, render_vuln_section.py 출력).
5. `assemble_report.py`를 파일 경로 인자로 실행한다:

```bash
python3 <NOAH_SAST_DIR>/sub-skills/scan-report/assemble_report.py \
  --skeleton /tmp/skeleton.md \
  --sections /tmp/sr_001_xss.md /tmp/sr_002_ssrf.md \
  --output noah-sast-report.md \
  --chain /tmp/chain.json \
  --ai /tmp/ai_section.md \
  --master-list <PHASE1_RESULTS_DIR>/master-list.json
```

- `--chain` 생략: 연계 분석 미수행
- `--ai` 생략: AI 자율 탐색 후보 0건
- `--master-list` 생략: `<!-- SAFE_SECTION_HERE -->` 플레이스홀더가 빈 값으로 치환 (안전 판정 섹션 미생성). **4분류 safe 섹션을 자동 생성하려면 master-list.json 경로를 반드시 전달한다**

**`chain_analysis` JSON 형식** (`--chain` 파일 내용):

```json
{
    "chains": [
        {
            "title": "체인 제목",
            "attacker": "공격자 프로필",
            "impact": "최종 영향",
            "steps": [
                {"vuln": "XSS-2", "desc": "설명"},
                {"vuln": "SSRF-1", "desc": "설명"}
            ],
            "poc": "#### 재현 방법 및 POC\n\n**Step 1: ...**\n```bash\ncurl ...\n```"
        }
    ],
    "independent": [
        {"id": "XSS-2", "reason": "체인 미구성 사유"}
    ]
}
```

스크립트가 수행하는 처리:
- `build_chain_section()`: `chain_analysis` 데이터 → `## 연계 시나리오` MD 자동 생성 (체인 있으면 상세, 없으면 사유 테이블)
- `normalize_vuln_headings()`: `**N번 - ID**: 제목` → `#### N. 제목` 자동 변환
- `clean_section()`: 서브에이전트가 포함한 `## 스캐너별 실행 결과`, `## 미적용 스캐너 목록` 등 자동 제거
- 플레이스홀더 치환으로 `## 미적용 스캐너 목록`이 항상 마지막에 위치

> **후처리 (scan-report-review, HTML 변환, 링크 검증, 정량 검증, 브라우저 열기)는 메인 오케스트레이터(SKILL.md Step 12)가 수행한다.** scan-report는 MD 조립(Step 3)까지만 담당한다.

---

## 보고서 유형

### 통합 보고서 (noah-sast 호출 시)

분석 결과는 프로젝트 루트에 두 가지 정적 파일로 저장한다:
- `noah-sast-report.md` — 마크다운 원본
- `noah-sast-report.html` — 가독성 좋은 HTML 리포트

구조와 HTML 추가 요소는 `vuln-format.md`의 "통합 보고서 구조" / "통합 HTML 보고서 추가 요소" 섹션 참조.

### 단일 스캐너 보고서 (개별 스캐너 호출 시)

분석 결과는 프로젝트 루트에 두 가지 정적 파일로 저장한다:
- `{scanner-type}-scan-report.md` — 마크다운 원본
- `{scanner-type}-scan-report.html` — 가독성 좋은 HTML 리포트

단일 스캐너 보고서에서는 분할 작성(Step 2)을 생략하고, 메인 에이전트가 직접 작성한다. 취약점 상세 형식은 `vuln-format.md`와 동일하다.

---

## 보고서 품질 규칙

- **[필수] 입력 데이터의 완전성**: 모든 취약점 항목(확인됨/후보)을 빠짐없이 보고서에 포함한다.
- **[필수] 심각도 표시 금지**: 상태는 "확인됨" 또는 "후보"로만 구분한다.
- **[필수] 모든 취약점에 재현 방법 및 POC를 포함한다:**
  - **"확인됨"**: 실제 사용한 값을 그대로 포함. 플레이스홀더 사용 금지. curl 요청 + 응답 증거 필수.
  - **"후보"**: 소스코드에서 파악한 엔드포인트·파라미터·페이로드를 구체적 curl 명령어로 기재. 직접 획득 불가한 값만 플레이스홀더 허용. POC의 URL 경로는 Phase 1에서 확정된 "실제 경로" 값을 그대로 사용한다.
- **[필수] 확인됨과 후보의 상세도 동일**: 건수가 많더라도 어떤 섹션도 축약하거나 생략할 수 없다.
- **[필수] 연계 시나리오 섹션 규칙**:
  - 연계 분석을 수행한 경우 반드시 포함한다 (체인 유무 무관).
  - 체인이 있으면 각 체인에 `#### 재현 방법 및 POC` 섹션을 포함한다.
  - 체인이 없으면 후보별 체인 미구성 사유 테이블만 기재한다.
  - 메타 설명("N개 후보 간 연계 없음" 등 요약 문구)을 포함하지 않는다. 테이블이 곧 내용이다.
  - 단독 위험도를 중복 기재하지 않는다. 각 취약점 상세에 이미 기술되어 있다.
- **테스트 환경(sandbox/production)을 보고서 헤더에 명시한다.**
- 이상 없음 스캐너는 점검 항목 요약 테이블만 간략히 포함한다.
- "안전" 판정 항목은 취약점 목록에 포함하지 않는다.
- 권장 조치는 각 취약점 상세 안에 포함한다. 별도 섹션을 만들지 않는다.
