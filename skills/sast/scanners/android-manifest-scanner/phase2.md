### 매니페스트 하드닝 동적 검증 cheat sheet

> 매니페스트 결함은 대부분 정적으로 확정되며, 동적 확인은 보조적이다. adb 필요 시 미충족이면 `[환경 제한]`.

#### BACKUP_ENABLED
```bash
adb backup -f out.ab <pkg>   # 데이터 추출 성공 시 확인됨
```

#### DEBUGGABLE
```bash
adb shell run-as <pkg> ls    # debuggable=true면 프라이빗 디렉토리 접근 성공
```

#### EXPORTED_NO_PERM
```bash
adb shell dumpsys package <pkg> | grep -A2 -i exported   # 노출 컴포넌트 확인
adb shell am start -n <pkg>/<exported.component>          # 권한 없이 기동되면 확인됨
```

#### CLEARTEXT_TRAFFIC
- MITM 프록시로 평문 HTTP 트래픽이 관측되면 확인됨.

판정: 추출/기동/평문 관측 성공 시 "확인됨", 권한/network config로 차단 입증 시 "안전", 환경 미충족 시 "후보".
