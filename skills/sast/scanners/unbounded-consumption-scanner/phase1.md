---
id_prefix: UC
prereq_group: llm
grep_patterns:
  - "openai"
  - "anthropic"
  - "google\\.generativeai"
  - "google\\.genai"
  - "vertexai"
  - "bedrock"
  - "cohere"
  - "mistralai"
  - "replicate"
  - "litellm"
  - "ollama"
  - "huggingface"
  - "transformers"
  - "langchain"
  - "llama_index"
  - "llamaindex"
  - "chat\\.completions\\.create"
  - "messages\\.create"
  - "generate_content"
  - "responses\\.create"
  - "embeddings\\.create"
  - "\\.invoke\\s*\\("
  - "\\.predict\\s*\\("
  - "\\.generate\\s*\\("
  - "\\.complete\\s*\\("
  - "max_tokens"
  - "max_output_tokens"
  - "max_completion_tokens"
  - "max_new_tokens"
  - "stream\\s*="
  - "n\\s*="
  - "best_of"
  - "temperature"
  - "Retriever"
  - "VectorStore"
  - "embedding"
  - "rate_limit"
  - "ratelimit"
  - "express-rate-limit"
  - "slowapi"
  - "django-ratelimit"
  - "Bucket4j"
  - "redis"
---

> **Phase 2 진입 조건**: 본 스캐너는 LLM 그룹에 속하며, Phase 2 동적 검증은 Step 8-3 그룹 사전 단계(`llm-endpoint-probe-agent`)가 chat endpoint를 확보한 경우에만 진입한다. Phase 2 입력 contract는 `<LLM_PROBE_DIR>/llm_endpoint.json` 단일 파일이다.

> ## 핵심 원칙: "비용·자원 한도가 사용자/세션 단위로 강제되지 않으면 후보다"
>
> LLM 호출은 토큰·요청 횟수·계산량 비용이 있다. 사용자 입력이 직접 또는 간접으로 호출 횟수·입력 크기·출력 크기·중첩 호출을 키울 수 있고, 그것을 제한하는 게이트가 없으면 가용성/비용 폭발 위험으로 후보다. 모델 응답 시간 단순 지연만으로는 부족하다 — 자원 소비가 외부 입력으로 증폭 가능해야 한다.

## Sink 의미론

Unbounded Consumption sink는 "외부 입력이 LLM 호출의 (1) 빈도 (2) 입력 토큰 (3) 출력 토큰 (4) 호출 fan-out 중 하나 이상을 제한 없이 키울 수 있는 지점"이다. 추가로 모델/임베딩 응답을 통한 모델 추출(model extraction) 위험도 동일 카테고리에서 다룬다.

| 카테고리 | 위험 sink |
|---|---|
| 호출 빈도 | 사용자/세션/IP 단위 rate limit 부재한 LLM 호출 endpoint |
| 입력 크기 | 사용자 제공 텍스트·문서·URL을 길이 제한 없이 프롬프트로 사용 |
| 출력 크기 | `max_tokens`/`max_output_tokens` 미설정 또는 비합리적으로 큰 값 |
| 호출 fan-out | RAG 검색 결과 chunk 수·에이전트 step 수·도구 호출 횟수 무제한 |
| 임베딩 비용 | 대량 텍스트 임베딩을 사용자 트리거로 무제한 수행 |
| 모델 추출 | 모델 출력만으로 surrogate 모델 학습 가능한 양의 쿼리를 무제한 허용 |
| 비용 격리 | 사용자/테넌트별 비용·쿼터 격리 부재 — 한 사용자가 전체 budget 소진 |

## Source-first 추가 패턴

- chat endpoint의 메시지 길이/이력 길이
- 업로드 문서 본문 길이, URL fetch 결과 본문 길이
- 검색/요약 쿼리의 결과 수 파라미터(`top_k`, `n`)
- 에이전트 step 상한(`max_iterations`), tool 호출 재귀 깊이
- 배치 임베딩 endpoint, 자동 인덱싱 endpoint

## 자주 놓치는 패턴 (Frequently Missed)

- **사용자/세션 단위 rate limit 부재** — 전역 limit만 있고 사용자별 격리 없음.
- **`max_tokens` 미설정** — 일부 SDK 기본값이 큼 → 비용 폭발.
- **이력(history) 무제한 누적** — 매 요청마다 전체 대화 이력 재전송, 토큰 비용이 N² 증가.
- **RAG `top_k` 외부 제어** — 사용자가 큰 값으로 호출 가능.
- **에이전트 `max_iterations` 미설정** — 도구 호출 무한 루프 가능.
- **PDF/긴 문서 자동 요약** — 길이 제한 없이 전체를 프롬프트로 투입.
- **OOM/대형 입력**으로 임베딩 endpoint 트리거.
- **모델 추출 시나리오** — 학습용 입력을 자동 변형하여 응답을 수집, surrogate 학습.
- **임베딩 인덱싱 endpoint**가 인증 없이 노출되어 임의 대량 텍스트 인덱싱.
- **스트림 응답 + 비용 미계측** — stream 모드에서 토큰 카운트 누락.
- **테넌트/사용자별 budget 격리 부재** — 단일 사용자가 회사 전체 한도 소진.
- **캐시 미사용** — 동일 쿼리 반복 요청을 매번 모델 호출.

## 안전 패턴 (FP Guard)

- 사용자/세션/IP/테넌트별 rate limit + 동시성 제한.
- 입력·출력 토큰 상한 명시(`max_tokens`/`max_output_tokens`/`max_new_tokens`).
- 이력 길이/슬라이딩 윈도/요약 압축.
- RAG `top_k`·에이전트 `max_iterations`·tool 호출 깊이 서버측 강제.
- 사용자/테넌트별 비용 쿼터·일/월 한도 + 한도 도달 시 차단·과금 분리.
- 캐시·디덕션 적용으로 동일 입력 재호출 감소.
- 임베딩 endpoint 인증·쿼터.
- 모델 추출 방어: 응답 변동성(노이즈) 추가, 비정상 쿼리 패턴 탐지, 단일 IP/계정의 대량 쿼리 모니터링.

## 우회 가능 패턴

| 방어 | 우회 가능성 | 우회 방식 |
|---|---|---|
| 전역 rate limit만 | 가능 | 다수 계정·IP 분산 — 사용자/세션 단위 격리 필요 |
| IP 기반만 | 가능 | 프록시·VPN·세션 토큰 회전 — 계정/테넌트 식별자 결합 필요 |
| `max_tokens`만 | 부분 | 호출 횟수·fan-out·이력 누적이 별도 제한 없으면 비용 폭발 가능 |
| 단일 단계 한도만 | 가능 | 에이전트 step·도구 호출 재귀 깊이 별도 제한 필요 |
| 동기 호출만 미터링 | 가능 | 스트림/배치 호출은 별도 계측 필요 |
| 캐시 키가 입력 평문 | 부분 | 입력에 미세 변형으로 캐시 미스 강제 — 정규화 후 캐싱 필요 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 호출 가능한 LLM endpoint + 사용자/세션 단위 rate limit 없음 | 후보 (라벨: `NO_RATE_LIMIT`) |
| `max_tokens`/출력 상한 미설정 | 후보 (라벨: `NO_OUTPUT_CAP`) |
| 입력 길이·이력 누적 제한 없음 | 후보 (라벨: `NO_INPUT_CAP`) |
| RAG `top_k`·에이전트 step·tool 호출 재귀가 외부 제어 가능 | 후보 (라벨: `FANOUT`) |
| 임베딩/인덱싱 endpoint 인증·쿼터 부재 | 후보 (라벨: `EMBEDDING_ABUSE`) |
| 단일 사용자가 전체 budget 소진 가능 (테넌트 격리 부재) | 후보 (라벨: `NO_TENANT_BUDGET`) |
| 모델 추출 시나리오 — 응답이 결정적이고 쿼리 한도 없음 | 후보 (라벨: `MODEL_EXTRACTION`) |
| 응답 시간만 지연되고 외부 입력으로 자원 증폭 불가 | 제외 |
| 정적·캐시된 응답 + 호출 횟수 제한 확인 | 제외 |

## 후보 판정 제한

- 비용·자원 증폭이 외부 입력으로 실제 가능해야 한다. 내부 잡(cron)만 호출하는 경로는 후보 아님.
- 단순한 응답 지연은 가용성 영향이 분명할 때만 별도 분류.
- 모델 추출은 응답 결정성·쿼리 한도·노이즈 정책을 함께 평가 — 한 조건만으로 판정하지 않는다.
