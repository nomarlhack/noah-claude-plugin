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

### Step 1: 스켈레톤 작성 (메인 에이전트)

메인 에이전트가 보고서의 뼈대를 작성한다. 이 단계에서는 취약점 상세를 작성하지 않는다. 통합 보고서 구조 예시는 `vuln-format.md`의 "통합 보고서 구조" 섹션 참조.

작성 항목:
- 보고서 헤더 (개요): `vuln-format.md`의 "통합 보고서 구조" 형식을 따른다. **볼드 키-값 쌍**으로 작성하며, `## 개요`를 사용한다. 헤더 영역 안에 `###` 소제목을 두지 않는다. (`###`는 `md_to_html.py`에서 스캐너 헤딩 스타일이 적용될 수 있으므로 헤더 영역에서 사용 금지.)
- 총괄 요약 테이블
- 인증 경계 표 + mermaid 흐름도 (`vuln-format.md`의 `## 인증 경계` 형식. `AUTH_BOUNDARY` 기반으로 메인 에이전트가 직접 렌더. 게이트웨이 표·클라이언트 표·경로 표 세 표를 모두 포함하되 빈 표는 생략. **흐름도 게이팅 (v11):** `len(routes) >= 2` OR `len(clients) >= 2` OR `len(gateways) >= 2`인 경우에만 작성 — 단일 표면이라도 다중 클라이언트면 흐름도 필수, 그 외엔 빈 흐름도 금지. 흐름도는 실선=`도달성=확정`·점선=`동적 확인 필요`/실패 모드. `vuln-format.md`의 monolith/single-gateway/multi-gateway 3종 예시 참조. **[필수] mermaid 노드·서브그래프 라벨은 슬래시(`/`), 콜론(`:`), 괄호(`()`), 파이프(`|`), `<br/>` 등 특수문자가 포함되면 반드시 큰따옴표로 감싼다** (예: `S1["/api 표면"]`) — `[/text]`는 mermaid 11.x에서 평행사변형 도형 문법(`[/text/]`)으로 오인되어 syntax error 발생. `validate_report.py`가 위반 시 경고 출력. 안전 기본값: **모든 라벨을 따옴표로 감싸는 것을 기본 정책**으로 한다.)
- 취약점 요약 테이블 (전체 항목의 제목/유형/스캐너/상태만)
- 이상 없음 스캐너 점검 항목 요약 테이블
- 미적용 스캐너 목록
- 부가 발견

**[필수] 총괄 요약 테이블의 건수에는 단위 접미사를 반드시 포함한다.** `md_to_html.py`가 이 접미사로 대시보드 수치를 파싱한다. 접미사가 누락되면 대시보드가 전부 0으로 표시된다.
- 확인됨/후보: `N건` (예: `0건`, `8건`)
- 이상 없음 스캐너/미적용 스캐너: `N개` (예: `16개`, `17개`)

**[필수] 스켈레톤에 아래 플레이스홀더를 반드시 포함한다. `## 미적용 스캐너 목록`은 모든 플레이스홀더 뒤에 위치해야 한다.**
- `<!-- CHAIN_SECTION_HERE -->` — 연계 시나리오 섹션 (assemble_report.py가 chain_analysis 데이터에서 자동 생성)
- `<!-- SCANNER_SECTIONS_HERE -->` — 스캐너별 실행 결과 섹션
- `## AI 자율 탐색 결과` 헤딩 + `<!-- AI_DISCOVERY_SECTION_HERE -->` — AI 자율 탐색 결과 섹션 (`## 스캐너별 실행 결과` 뒤, `## 미적용 스캐너 목록` 앞에 위치). 헤딩과 플레이스홀더를 함께 포함해야 `assemble_report.py`가 후보 0건 시 정리 가능
- `<!-- SAFE_SECTION_HERE -->` — 안전 판정 4분류 섹션 (`이상 없음 스캐너 점검 항목 요약` 앞, `## AI 자율 탐색 결과` 뒤에 위치). `assemble_report.py`가 master-list.json의 `status=safe` 후보를 4분류(외부 접근 경로 없음 / 방어 계층 작동 확인 / 취약점 성립 조건 미충족 / 정적 분석 오탐)로 자동 생성한다. **스켈레톤에는 `## 안전 판정 항목` 헤딩이나 소분류를 직접 작성하지 않는다.** 자동 생성 결과를 그대로 삽입한다. 상세 규약은 `vuln-format.md`의 "safe 판정 4분류" 섹션 참조.

**[필수] 스켈레톤에 `## 연계 시나리오`를 직접 작성하지 않는다.** 연계 시나리오 섹션은 연계 분석 JSON 파일을 `assemble_report.py`의 `--chain` 인자로 전달하면 스크립트가 고정된 형식으로 자동 렌더링한다. 메타 설명, 단독 위험도 등 불필요한 내용이 구조적으로 끼어들 수 없다.

**참고: 취약점 요약 테이블은 `assemble_report.py`가 상세 섹션에서 자동 생성한다 (단일 진실 원천).** 스켈레톤에 작성한 요약 테이블은 형식만 유지하면 되고, 최종 보고서에서는 상세 섹션의 `#### N. 제목`, `**유형**:`, `**상태**:` 필드와 `### Scanner` 헤딩에서 파싱한 데이터로 자동 대체된다.

### Step 2: 스캐너별 상세 섹션 분할 작성 (서브에이전트)

발견이 있는(확인됨 또는 후보) 스캐너별로 서브에이전트를 병렬 실행하여, 해당 스캐너의 MD 상세 섹션을 작성한다.

**서브에이전트 프롬프트에 반드시 포함할 내용:**

1. 해당 스캐너의 취약점 데이터 전체 (파일 경로, 코드 스니펫, Source→Sink, 동적 테스트 증거). **Phase 1 결과는 `<PHASE1_RESULTS_DIR>/evaluation/<scanner-name>-eval.md`(phase1-review 평가본)을 전달**하고 서브에이전트가 Read하도록 지시한다. eval MD의 Override 여부(CONFIRM/OVERRIDE/DISCARD), 수정 권고, phase1_quality_notes가 보고서에 반영되도록 한다. **Phase 1 원본(`<PHASE1_RESULTS_DIR>/<scanner-name>.md`) 직접 참조 금지** (`sub-skills/scan-report-review/_contracts.md §6` C1 lint). eval MD가 부재하면 원본 MD를 fallback으로 사용.
   - **[필수] 동적 테스트 증거(POC 리터럴)는 `<PHASE1_RESULTS_DIR>/<scanner-name>-phase2.md` 경로를 함께 전달**하고 서브에이전트가 Read하도록 지시한다. 이 파일의 `evidence.commands[]`(실제 실행한 curl)·`evidence.responses[]`(실제 응답)가 POC의 단일 진실 원천이다. **동적 실행된 항목(evidence.commands 존재)의 "재현 방법 및 POC"는 이 리터럴을 그대로 인용(verbatim)**하며, 세션 쿠키·URL·파라미터·페이로드·응답을 플레이스홀더로 치환하거나 재작성하지 않는다. phase2.md가 부재한 항목(정적 후보)만 소스코드 기반 구체 curl로 기재한다.
   - **[필수] 이 스캐너 후보들의 `AUTH_BOUNDARY` 슬라이스를 프롬프트에 함께 전달 (v11 슬라이싱):**
     1. 메인 에이전트가 이 스캐너의 후보 진입 경계 필드를 모아 surface_key 집합(`{"POST /papi/...", ...}`)을 만든다.
     2. `auth-boundary.json`을 Read하여 (a) 해당 surface_key와 M5 매칭(METHOD 정확 + `{...}`·`**`→`*` 정규화 + trailing `/` 제거)되는 `routes[]` 행만, (b) 그 행이 참조하는 `gateway_id`와 `client_ids[]`에 해당하는 `gateways[]`·`clients[]` 행만 슬라이스한다.
     3. 슬라이스된 부분(가벼운 JSON)을 서브에이전트 프롬프트에 동봉한다. **전체 `auth-boundary.json` 동봉 금지 — 후보×스캐너 곱으로 토큰 폭증.**
     4. 서브에이전트는 각 후보 본문에 슬라이스의 `gateway_id`·`client_ids`·`failure_modes`·`credential_chain`을 자연어로 인라인 (예: "이 진입은 `oahu-gateway` Bearer 인증을 거쳐 도달. `credential_mismatch` 실패 모드가 있어 잘못된 자격증명 시 500"). 단순 ID 나열 금지 — 의미를 풀어 설명.
     5. POC curl 호스트: 매칭된 게이트웨이의 `host_pattern`이 단일 호스트로 확정되고 `도달성=확정`이면 그 호스트를 인라인. 그 외(`동적 확인 필요`·와일드카드·미상)는 `<TARGET_HOST>` 플레이스홀더.
2. 다음 한 줄 지시: **"`<NOAH_SAST_DIR>/sub-skills/scan-report/vuln-format.md`를 Read 도구로 읽고, 그 안의 '확인됨 형식' / '후보 형식' / '이상 없음 형식' 템플릿을 그대로 따라 MD 텍스트를 작성하라."** 메인 에이전트는 템플릿 본문을 인라인으로 복사하지 않는다.
3. 다음 필수 준수 사항:

> **필수 준수 사항:**
> - 보고서 파일(.md, .html)을 직접 생성하지 않는다. MD 텍스트를 반환만 한다.
> - 확인됨과 후보 모두 동일한 상세도로 작성한다. 어떤 섹션도 축약하거나 생략할 수 없다.
> - 모든 취약점에 "재현 방법 및 POC" 섹션을 포함한다. Step 1~3 구조 + curl 명령어 필수.
> - 각 상세 섹션 `#### N. 제목` 헤딩 **바로 다음 줄**에 `**ID**: <master-list.candidates[].id>`를 포함한다. 프롬프트로 전달된 master-list id를 그대로 사용하며, 한 섹션에 `**ID**:` 라인은 정확히 1회만 존재한다.
> - **동적 테스트를 실행한 항목(상태 무관, phase2.md `evidence.commands` 존재)**: 플레이스홀더 사용 금지. phase2.md의 실제 실행값(세션 쿠키, URL, 파라미터, 페이로드, 응답)을 **그대로(verbatim) 인용**한다. 무인증이라 쿠키가 불필요했던 후보도 실제 실행한 curl·응답을 그대로 기재한다(상태가 "후보"여도 동적 실행값이면 실값 필수).
> - **정적 후보(동적 미실행, phase2.md 부재)**: 소스코드에서 파악한 엔드포인트, HTTP 메서드, 파라미터명, 페이로드를 구체적 curl 명령어로 기재한다. 플레이스홀더는 **환경상 직접 획득 불가한 값**(피해자 OTP, 외부 콜백 URL 등)에 한해 허용한다. 세션 쿠키는 sandbox에서 획득 가능하므로 동적 실행 항목에선 플레이스홀더 대상이 아니다.
> - **POC curl 명령어의 호스트**: 프롬프트로 전달된 `SANDBOX_DOMAINS` 값 중 하나 또는 `<TARGET_HOST>` 플레이스홀더만 사용한다. 그 외 임의 호스트(예: `https://api.example.com` 같은 실제 프로덕션 도메인 직접 기술)는 금지한다. `SANDBOX_DOMAINS`가 빈 값인 경우에는 모든 POC 호스트를 `<TARGET_HOST>`로 통일한다. 이 호스트 값은 보고서 개요의 `**테스트 환경**` 필드와 일치해야 하며 `validate_report.py`의 URL 일관성 검증 기준이 된다. **각 후보의 호스트는 `AUTH_BOUNDARY`에서 그 후보 표면의 진입 도메인으로 채우되(표면이 1개여도 동일하게 적용), 그 표면의 `도달성=확정`인 경우에만 실제 도메인을 인라인하고 `동적 확인 필요`·진입 도메인 `미상`이면 `<TARGET_HOST>` 플레이스홀더를 쓴다. `도달성=확정`인 진입 도메인은 모두 개요 `**테스트 환경**` 필드에 포함해 `validate_report.py` 호스트 검증과 정합시킨다(추정 도메인을 정답처럼 박지 않는다).**
> - 심각도(HIGH/MEDIUM/LOW)를 표시하지 않는다. 상태는 "확인됨" 또는 "후보"만 사용한다.
> - 반환하는 MD 텍스트의 첫 줄은 `### [스캐너명] Scanner`로 시작한다.

> **참고:** 관련 스캐너를 묶어서 하나의 서브에이전트에 할당할 수 있으나, 하나의 서브에이전트가 담당하는 취약점은 **최대 10건**으로 제한한다. 10건을 초과하면 분할한다.

**AI 자율 탐색 결과 섹션:**

AI 자율 탐색에서 후보가 발견된 경우, 별도 서브에이전트로 AI 자율 탐색 상세 섹션을 작성한다. 서브에이전트 프롬프트에 다음을 포함한다:

1. `<PHASE1_RESULTS_DIR>/evaluation/ai-discovery-eval.md`(phase1-review이 생성한 AI 자율 탐색 평가본)를 우선 전달. 부재 시 `<PHASE1_RESULTS_DIR>/ai-discovery.md` 원본을 fallback으로 사용 (서브에이전트가 Read하도록 지시). **ai-discovery-eval.md는 §12-H C1 lint의 화이트리스트이므로 예외 처리된다.**
2. 다음 한 줄 지시: **"`<NOAH_SAST_DIR>/sub-skills/scan-report/vuln-format.md`를 Read 도구로 읽고, 그 안의 '후보 형식' 템플릿을 그대로 따라 MD 텍스트를 작성하라."**
3. 스캐너 서브에이전트와 동일한 필수 준수 사항:

> **필수 준수 사항:**
> - 보고서 파일(.md, .html)을 직접 생성하지 않는다. MD 텍스트를 반환만 한다.
> - 모든 취약점에 "재현 방법 및 POC" 섹션을 포함한다. Step 1~3 구조 + curl 명령어 필수.
> - 각 상세 섹션 `#### N. 제목` 헤딩 **바로 다음 줄**에 `**ID**: <master-list.candidates[].id>`를 포함한다(예: `AI-1`). 한 섹션에 `**ID**:` 라인은 정확히 1회만 존재한다.
> - "후보" 항목: 소스코드에서 파악한 엔드포인트, HTTP 메서드, 파라미터명, 페이로드를 구체적 curl 명령어로 기재한다. 직접 획득 불가한 값(세션 쿠키 등)만 플레이스홀더 허용.
> - **POC curl 명령어의 호스트**: 프롬프트로 전달된 `SANDBOX_DOMAINS` 값 중 하나 또는 `<TARGET_HOST>` 플레이스홀더만 사용한다. 그 외 임의 호스트 사용 금지.
> - 심각도(HIGH/MEDIUM/LOW)를 표시하지 않는다. 상태는 "후보"만 사용한다.
> - 반환하는 MD 텍스트의 첫 줄은 `### AI 자율 탐색`으로 시작한다. 각 취약점 헤딩은 `#### N. 제목` 형식을 사용한다.

이 결과를 임시 파일(예: `/tmp/ai_section.md`)로 저장하고, `assemble_report.py`의 `--ai` 인자로 전달하여 `<!-- AI_DISCOVERY_SECTION_HERE -->` 위치에 삽입한다.

**서브에이전트 에러 핸들링:**

서브에이전트가 실패(API 에러, 타임아웃 등)한 경우:
1. 메인 에이전트가 해당 섹션을 직접 작성한다. (재시도/분할 없이 즉시 fallback)
2. 어떤 경우에도 서브에이전트 실패로 인해 취약점 항목이 보고서에서 누락되어서는 안 된다.

### Step 3: MD 보고서 조립

**[필수] Write 도구를 직접 사용하지 않는다.** 보고서 전체를 한 번에 Write하면 32K 토큰 한도를 초과할 수 있다. 반드시 아래 Python 스크립트로 조립한다. **스크립트 실행 실패 시:** 서브에이전트 결과를 `\n\n---\n\n`로 연결하여 Write 도구로 직접 저장하는 fallback을 수행한다.

**조립 절차:**

1. Step 1에서 작성한 스켈레톤을 Write 도구로 임시 파일에 저장한다 (예: `/tmp/skeleton.md`).
2. Step 2에서 각 서브에이전트의 반환 텍스트를 Write 도구로 개별 임시 파일에 저장한다 (예: `/tmp/sr_001_xss.md`, `/tmp/sr_002_ssrf.md`).
3. 연계 분석을 수행한 경우, `chain_analysis` 데이터를 JSON 파일로 저장한다 (예: `/tmp/chain.json`).
4. AI 자율 탐색 결과가 있으면 Write 도구로 임시 파일에 저장한다 (예: `/tmp/ai_section.md`).
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
