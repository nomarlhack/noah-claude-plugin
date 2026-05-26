### IPC/Intent 동적 검증 cheat sheet

> adb + device/emulator + 대상 APK 필요. 미충족 시 `[환경 제한]`. (공통 환경 점검은 android-deeplink-scanner/phase2.md 참조)

#### INTENT_REDIRECT
- 외부에서 redirect 대상 컴포넌트를 가리키는 Intent를 extra로 실어 진입점에 전달:
  ```bash
  adb shell am start -n <pkg>/<entry> --es next "<intent-uri or extra>"
  ```
- 내부 비exported 컴포넌트(설정/계정 화면 등)가 기동되면 redirection 성립.

#### PENDING_INTENT_HIJACK
- Frida로 PendingIntent 생성 인자 hook하여 `FLAG_MUTABLE` + 빈 base Intent 여부 확인.
- 공격 앱에서 해당 PendingIntent를 받아 `fillIn`으로 component를 채워 재전송 시 내부 권한으로 실행되는지 관찰.

#### RECEIVER_EXPORTED / IMPLICIT_BROADCAST_LEAK
- `adb shell dumpsys activity broadcasts`로 동적 리시버 노출 확인.
- 공격 앱에서 동일 action 브로드캐스트를 전송하거나, 민감 브로드캐스트를 수신 가능한지 테스트.

판정: 트리거 확인 시 "확인됨", 방어(명시적 component/권한/immutable) 입증 시 "안전", 환경 미충족 시 "후보".
