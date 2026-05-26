---
id_prefix: ANDROID_IPC
rules_dir: rules/
---

> ## 핵심 원칙: "외부 컴포넌트에서 들어온 Intent/extra는 attacker-controlled"
>
> 다른 앱이 보낸 Intent를 그대로 재실행하거나(Intent redirection), 가변 PendingIntent를 외부에 넘기거나, 동적 리시버를 노출하면 권한 상승·내부 컴포넌트 임의 호출·하이재킹으로 이어진다.

## Sink 의미론

| 라벨 | sink | 위험 조건 |
|---|---|---|
| `INTENT_REDIRECT` | `startActivity(intent.getParcelableExtra<Intent>(...))`, `Intent.parseUri(extra)` → `startActivity` | 외부에서 받은 Intent/URI를 검증 없이 재실행 → 내부 비exported 컴포넌트 임의 기동 |
| `PENDING_INTENT_HIJACK` | `PendingIntent.getActivity/getBroadcast/getService(..., FLAG_MUTABLE)` | `FLAG_MUTABLE` + 빈/암묵 base Intent를 외부에 전달 → 공격자가 채워 하이재킹. (pre-S 기본 가변도 위험) |
| `RECEIVER_EXPORTED` | `registerReceiver(...)` | API 33+에서 `RECEIVER_NOT_EXPORTED` 플래그 누락 시 암묵 노출 |
| `IMPLICIT_BROADCAST_LEAK` | `sendBroadcast(intent)`, `sendOrderedBroadcast` | 민감 데이터를 권한 없이 암묵 브로드캐스트 → 도청 |

## 안전 격하 신호 (정탐 아님)

- 받은 Intent를 재실행 전에 `setPackage`/`setComponent`(명시적)로 고정하거나, 컴포넌트/액션 화이트리스트 검증
- PendingIntent에 `FLAG_IMMUTABLE` 사용 + 명시적 base Intent
- `registerReceiver(..., RECEIVER_NOT_EXPORTED)` (API 33+) 또는 권한 지정
- 브로드캐스트에 수신 권한(`sendBroadcast(intent, permission)`) 지정 또는 `LocalBroadcastManager`

## Source-first 추가 패턴

```kotlin
// 위험: Intent redirection
val forwarded = intent.getParcelableExtra<Intent>("next")
startActivity(forwarded)                       // 검증 없이 재실행

// 위험: 가변 PendingIntent
PendingIntent.getActivity(ctx, 0, Intent(), PendingIntent.FLAG_MUTABLE)

// 안전: 불변 + 명시적
PendingIntent.getActivity(ctx, 0, explicitIntent, PendingIntent.FLAG_IMMUTABLE)
```
