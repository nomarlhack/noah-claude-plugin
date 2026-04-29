# 카카오 카나나 (Kanana in KakaoTalk) — 시스템 흐름도

## 1. 전체 아키텍처

```mermaid
flowchart LR
    User["📱 사용자<br/>(카카오톡 인앱 WebView)"]

    subgraph Frontend["프론트엔드 (thanos-develop)"]
        SSR["Express 5 SSR"]
        React["React 19 + Zustand"]
        Native["window.kanana<br/>Native Bridge"]
    end

    subgraph Gateway["외부 API 게이트웨이"]
        MCQ["mcqueen-develop<br/>(Spring Boot/Kotlin)"]
    end

    subgraph Internal["내부 마이크로서비스"]
        CHO["choonsik-develop<br/>(리마인더/넛지/메타)"]
        NAR["naruto-develop<br/>(대화/공유)"]
        SIE["sietch-develop<br/>(결제 이벤트)"]
    end

    subgraph External["외부 시스템"]
        OAUTH["카카오 OAuth<br/>(kauth.kakao.com)"]
        ONDEV["aai-ondevice-api<br/>(모델 메타/CDN)"]
        KAFKA["Kafka Broker"]
    end

    DB[("MongoDB Reactive<br/>+ Redis")]

    User -->|HTTPS| SSR
    SSR --> React
    React -.->|JSON REST| MCQ
    React -.->|STOMP WebSocket| MCQ
    Native -.->|모델 다운로드| ONDEV

    MCQ --> OAUTH
    MCQ --> ONDEV
    MCQ --> CHO
    MCQ --> NAR
    MCQ --> SIE
    MCQ --> KAFKA

    CHO --> DB
    NAR --> DB
    SIE --> DB
    MCQ --> DB
```

---

## 2. 모델 자동 다운로드 흐름

```mermaid
sequenceDiagram
    participant U as 사용자 (WebView)
    participant T as thanos<br/>(AppModelManager)
    participant N as Native<br/>(window.kanana)
    participant M as mcqueen
    participant O as aai-ondevice-api

    Note over U,O: 진입: ?downloadModel=true 또는 다운로드 버튼 클릭
    U->>T: useAutoDownloadModel useEffect
    T->>M: POST /open/api/v1/models/new<br/>{device 정보}
    M->>O: GET /api/v1/models/availability (HTTP 평문)
    O-->>M: {downloadUrl, files[].checksum, cooldownSeconds}
    M-->>T: GetNewKananaModelResponse

    Note over T: bannerStatus='availableDownload' 확인
    T->>N: window.kanana.downloadModel({url, name, version, size})
    N->>O: 모델 바이너리 다운로드
    N-->>T: window.thanos.downloadProgress(N%) 콜백
    N-->>T: result.data (성공 시)

    T->>T: useDownloadStore.completeDownload()
    T->>M: POST /api/v1/models<br/>{modelName, modelVersion}
    M->>M: saveOnDeviceModel(talkUserId, model)
    M-->>T: 204 No Content
    T->>N: activate() 호출
```

---

## 3. 카카오 OAuth 가입 흐름

```mermaid
sequenceDiagram
    participant U as 사용자
    participant K as 카카오톡 본체
    participant OAUTH as 카카오 OAuth
    participant M as mcqueen<br/>AuthCallbackController
    participant CHO as choonsik

    U->>K: 카나나 가입 요청
    K->>OAUTH: Authorization Code Grant
    U->>OAUTH: 로그인 + 동의
    OAUTH-->>M: GET /auth/{domain}/kakaosync<br/>?code=...&continue=...

    M->>OAUTH: code → access_token 교환
    OAUTH-->>M: access_token + id_token + _kawlt 쿠키

    Note over M: ⚠ Host 헤더로 redirect_uri 동적 구성
    Note over M: ⚠ continue 파라미터 무검증
    Note over M: ⚠ _kawlt 쿠키 평문 INFO 로깅

    M->>M: KakaoAuthAgent.kauthJwtValidate
    M->>CHO: 카나나 사용자 등록
    CHO-->>M: OK
    M-->>U: response.sendRedirect(continue)
```

---

## 4. WebChat 실시간 추론 흐름

```mermaid
sequenceDiagram
    participant U as 사용자
    participant T as thanos React
    participant M as mcqueen<br/>(STOMP)
    participant N as naruto

    U->>T: 카나나에게 메시지 입력
    T->>M: WebSocket /handshake<br/>(KA-ACCOUNT-ID, KA-CHECKSUM, Origin)

    M->>M: WebsocketAuthHandShakeInterceptor<br/>인증 + Origin 화이트리스트
    M-->>T: 핸드셰이크 성공

    T->>M: SEND /app/v1/chat/{conversationId}<br/>{utterance, serviceData, extra}
    M->>M: SecureChannelInterceptor<br/>ACL 검증 (accountId 기준)

    M->>N: 추론 요청 (서비스 간 호출)
    N-->>M: 토큰 스트리밍 응답

    loop 토큰 단위 스트리밍
        M-->>T: SUBSCRIBE /user/{accountId}/queue/chat<br/>토큰 청크
    end

    T->>T: useChatStore 메시지 누적
    T-->>U: 화면 렌더링
```

---

## 5. 리마인더 / 넛지 / 공유 대화 흐름

```mermaid
flowchart TB
    Start([사용자가 카나나에게<br/>대화 분석 요청])

    Start --> Analyze[mcqueen → naruto<br/>대화 컨텍스트 추출]

    Analyze --> Branch{추출 결과 유형}

    Branch -->|약속/일정/할일| Reminder[리마인더 등록]
    Branch -->|행동 추천| Nudge[넛지 메타 저장]
    Branch -->|대화 요약| Share[공유 카드 생성]

    Reminder --> CHO1[choonsik<br/>ReminderRepository]
    Nudge --> CHO2[choonsik<br/>InternalController<br/>nudgeFeedback]
    Share --> NAR1[naruto<br/>ShareConversationCreate]

    CHO1 --> DB[(MongoDB)]
    CHO2 --> DB
    NAR1 --> DB

    Reminder -.알림 푸시.-> User1([사용자])
    Nudge -.화면 노출.-> User1
    Share -.카톡으로 전달.-> User1
```

---

## 6. 인증 헤더 전파 흐름

```mermaid
flowchart LR
    GW["🛡 외부 게이트웨이<br/>(KA-ACCOUNT-ID 부여)"]

    GW -->|KA-ACCOUNT-ID<br/>KA-CHECKSUM<br/>Domain| MCQ[mcqueen<br/>MvcSecurityFilter]

    MCQ -->|nullity 검사만| Validate{KA-CHECKSUM<br/>서명 검증?}
    Validate -.없음.-> Pass[그대로 통과]

    Pass --> Auth["@AuthenticationPrincipal<br/>kananaUserInfo"]
    Auth --> Handler[컨트롤러 핸들러]

    Handler -->|talkUserId 전달| Internal[choonsik / naruto / sietch]
    Internal -.인증 검증 없이.-> DB[(자원 접근)]

    style Validate fill:#fff3cd,stroke:#856404
    style Pass fill:#f8d7da,stroke:#721c24
```

---

## 7. 결제 이벤트 (선물) 처리 흐름

```mermaid
sequenceDiagram
    participant Talk as 카카오톡 선물
    participant Kafka as Kafka Broker
    participant SIE as sietch<br/>OrderEventConsumer
    participant Mongo as MongoDB
    participant CHO as choonsik

    Talk->>Kafka: 결제 완료 이벤트 publish
    Kafka-->>SIE: OrderEvent consume
    SIE->>SIE: OrderEventService<br/>이벤트 파싱·검증
    SIE->>Mongo: 결제 메타 저장
    SIE->>CHO: 카나나 추천 메타 갱신 트리거
    CHO->>Mongo: 친구탭 메타 업데이트
```

---

## 8. 다운로드 상태 머신 (UI)

```mermaid
stateDiagram-v2
    [*] --> Idle: 페이지 로드

    Idle --> CheckUpdate: useAppInitialization
    CheckUpdate --> ModelInstalled: 최신 버전 보유
    CheckUpdate --> AvailableDownload: 신규 모델 가용

    AvailableDownload --> Downloading: ?downloadModel=true<br/>또는 사용자 클릭
    Downloading --> Progress: 진행률 콜백
    Progress --> Progress: window.thanos.downloadProgress
    Progress --> Completed: result.data 성공
    Progress --> Failed: 에러 발생

    Failed --> Downloading: FailedUpdateBanner<br/>재시도 클릭
    Completed --> ModelInstalled: syncModelInfo<br/>+ activate()

    ModelInstalled --> [*]
```

---

## 9. 데이터 저장소 매핑

```mermaid
flowchart LR
    subgraph Services["서비스"]
        M[mcqueen]
        C[choonsik]
        N[naruto]
        S[sietch]
    end

    subgraph Storage["저장소"]
        Mongo[("MongoDB Reactive<br/>(영속 데이터)")]
        Redis[("Redis<br/>(세션·캐시·rate limit)")]
        KafkaQ[("Kafka<br/>(이벤트 스트림)")]
    end

    M --> Mongo
    M --> Redis
    M --> KafkaQ

    C --> Mongo
    C --> Redis

    N --> Mongo

    S --> Mongo
    S --> KafkaQ
```
