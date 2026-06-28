# 취약점 섹션 JSON 반환 지침

취약점 분석 결과를 아래 JSON 형식으로 반환하라. MD 텍스트가 아닌 **JSON만** 반환한다.

## 스키마

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "VulnSection",
  "description": "취약점 상세 섹션 서브에이전트 반환 형식",
  "type": "object",
  "required": ["scanner", "vulnerabilities"],
  "properties": {
    "scanner": {
      "type": "string",
      "description": "스캐너 이름 (예: xss-scanner)"
    },
    "vulnerabilities": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "title", "type", "status", "location", "entry_boundary", "source", "sink", "cause", "poc", "remediation"],
        "properties": {
          "id": {"type": "string", "description": "master-list candidates[].id (예: XSS-1)"},
          "title": {"type": "string", "description": "취약점 제목 — | 문자 포함 금지 (대신 '/' 또는 '또는'으로 대체). 예: addBot/delBotPenalty"},
          "type": {"type": "string", "description": "취약점 유형 (예: XSS, SSRF)"},
          "status": {"type": "string", "enum": ["확인됨", "후보"], "description": "판정"},
          "location": {"type": "string", "description": "파일경로:라인번호"},
          "entry_boundary": {"type": "string", "description": "진입 경계 설명 (auth-boundary 슬라이스 기반)"},
          "source": {"type": "string", "description": "소스 설명"},
          "sink": {"type": "string", "description": "싱크 설명"},
          "unconfirmed_reason": {"type": "string", "description": "후보일 때만 — 미확인 사유"},
          "cause": {"type": "string", "description": "원인 분석 텍스트 (마크다운 허용, 코드 스니펫 포함 가능)"},
          "poc": {
            "type": "object",
            "required": ["steps"],
            "properties": {
              "steps": {
                "type": "array",
                "items": {
                  "type": "object",
                  "required": ["title", "content"],
                  "properties": {
                    "title": {"type": "string", "description": "Step 제목 (예: Step 1: 취약 엔드포인트 식별)"},
                    "content": {"type": "string", "description": "단계 내용 (마크다운 허용, curl 코드블록 포함 가능)"}
                  }
                }
              }
            }
          },
          "remediation": {"type": "string", "description": "권장 조치 텍스트 (마크다운 허용)"}
        }
      }
    }
  }
}
```

## 작성 규칙

- `id`: master-list.json의 candidates[].id 값을 그대로 사용한다.
- `status`: "확인됨" 또는 "후보"만 허용. Phase 2 결과 기반으로 판정.
- `cause`: 마크다운 허용. 코드 스니펫은 백틱 코드블록으로 감싼다.
- `poc.steps`: 최소 3단계 (Step 1: 엔드포인트 식별, Step 2: 페이로드 전송, Step 3: 결과 확인).
  - Step 2 content에 curl 명령어를 코드블록으로 포함한다.
  - 동적 실행된 경우: phase2.md의 evidence.commands[]를 verbatim으로 포함.
  - 정적 후보: 소스코드 기반 구체적 curl 명령어.
- `entry_boundary`: auth-boundary 슬라이스에서 이 후보 표면의 값을 자연어로 기술.
  - 형식: "{host} {path} (인증: {credential}, 신원: {identity_source}, 인증근거: {auth_basis}, 도달성: {reachability})"
- `unconfirmed_reason`: 후보일 때만 작성. 왜 동적 확인이 불가능했는지 구체 사유.
- `remediation`: 구체적이고 실행 가능한 코드/설정 수정 방법. 마크다운 허용.

## 반환 형식

응답 전체가 유효한 JSON이어야 한다. 설명 텍스트나 마크다운 코드펜스 없이 JSON만 반환한다.

```json
{
  "scanner": "...",
  "vulnerabilities": [...]
}
```
