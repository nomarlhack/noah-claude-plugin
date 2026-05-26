---
id_prefix: ANDROID_MANIFEST
rules_dir: rules/
---

> ## 핵심 원칙: "AndroidManifest의 하드닝 플래그는 앱 전체 공격면을 결정한다"
>
> `debuggable`/`allowBackup`/`usesCleartextTraffic`/무권한 `exported` 등은 단일 속성으로 데이터 탈취·디버거 부착·평문 통신·컴포넌트 임의 호출을 가능하게 한다. 릴리스 빌드 매니페스트(병합 결과 포함)를 기준으로 판정한다.

## Sink 의미론

| 라벨 | 속성 | 위험 |
|---|---|---|
| `DEBUGGABLE` | `android:debuggable="true"` | 릴리스에서 디버거 부착·메모리 덤프. (보통 빌드타입으로 자동 설정 — 릴리스 매니페스트에 박혀 있으면 위험) |
| `BACKUP_ENABLED` | `android:allowBackup="true"` | `adb backup`으로 앱 프라이빗 데이터 추출 (기본 true이므로 명시 false 권장) |
| `CLEARTEXT_TRAFFIC` | `android:usesCleartextTraffic="true"` | 평문 HTTP 허용 → MITM |
| `EXPORTED_NO_PERM` | `android:exported="true"` | `<intent-filter>` 보유 또는 권한 없는 노출 컴포넌트 → 타 앱이 임의 호출 (deeplink 진입은 android-deeplink-scanner와 cross-ref) |
| `GRANT_URI_BROAD` | `android:grantUriPermissions="true"` | 프로바이더 URI 권한 과대 부여 |
| `WEAK_PERM` | `android:protectionLevel="normal"` | 민감 커스텀 권한이 normal → 타 앱이 무조건 획득 |
| `TEST_ONLY` | `android:testOnly="true"` | 릴리스에 테스트 전용 플래그 잔존 |

## 안전 격하 신호 (정탐 아님)

- `exported="true"`라도 `android:permission`(signature 등 강한 protectionLevel)으로 보호되거나, intent-filter 없는 명시적 내부 호출 전용
- `debuggable`/`testOnly`가 debug 빌드 변형(`src/debug/AndroidManifest.xml`)에만 존재하고 릴리스 병합 결과엔 없음
- `allowBackup="false"` 명시 또는 `android:fullBackupContent`로 민감 항목 제외
- `usesCleartextTraffic`이 network_security_config로 도메인 한정

## 비고

릴리스/디버그 flavor 매니페스트가 분리된 프로젝트(예: `src/debug/AndroidManifest.xml`)는 매치 위치의 소스셋을 확인해 debug 전용 여부를 판정한다. debug 전용이면 "안전(정적 분석 범위 외)".
