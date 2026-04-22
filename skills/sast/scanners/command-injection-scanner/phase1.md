---
id_prefix: CMDI
grep_patterns:
  - "child_process"
  - "exec\\s*\\("
  - "execSync\\s*\\("
  - "execFile\\s*\\("
  - "spawn\\s*\\("
  - "spawnSync\\s*\\("
  - "os\\.system\\s*\\("
  - "os\\.popen\\s*\\("
  - "subprocess\\.call\\s*\\("
  - "subprocess\\.run\\s*\\("
  - "subprocess\\.Popen\\s*\\("
  - "subprocess\\.check_output\\s*\\("
  - "commands\\.getoutput\\s*\\("
  - "Runtime\\.getRuntime"
  - "ProcessBuilder"
  - "%x{"
  - "shell\\s*:\\s*true"
  - "shell\\s*=\\s*True"
  - "shell_exec\\s*\\("
  - "passthru\\s*\\("
  - "\\bsystem\\s*\\("
  - "popen\\s*\\("
  - "proc_open\\s*\\("
  - "pcntl_exec\\s*\\("
  - "IO\\.popen"
  - "Open3\\.capture3"
  - "Kernel\\.system"
  - "Runtime\\.exec\\s*\\("
  - "bash\\s+-c"
  - "/bin/sh\\s+-c"
  - "execa\\s*\\("
  - "execaSync"
  - "execaCommand"
  - "shelljs"
  - "\\$\\s*`"
  - "exec\\.Command\\s*\\("
  - "@RequestParam"
  - "@RequestBody"
  - "req\\.query"
  - "req\\.body"
---

> ## 핵심 원칙: "추가 명령어가 실행되지 않으면 취약점이 아니다"
>
> `exec(userInput)`이 있다고 바로 Command Injection으로 보고하지 않는다. 사용자 입력에 `;`/`|`/`&&`/`` ` ``/`$()` 등 셸 메타문자를 삽입하여 추가 명령어가 실제로 실행되어야 취약점이다.

## Sink 의미론

Command Injection sink는 "사용자 입력이 셸(`/bin/sh -c`, `cmd.exe /c`)에 의해 파싱되는 지점"이다. 핵심 구분: **셸을 거치는가**. 셸을 거치지 않는 `execFile`/`spawn(cmd, [args])`/`subprocess.run([...])`은 인자가 그대로 argv로 전달되어 sink가 아니다.

| 언어 | 위험 (셸 경유) | 안전 (셸 미경유) |
|---|---|---|
| Node.js | `child_process.exec`, `execSync`, `spawn(..., {shell:true})`, `spawnSync(..., {shell:true})` | `execFile`, `spawn(cmd, [args])` (기본 shell:false) |
| Python | `os.system`, `os.popen`, `subprocess.* (shell=True)`, `commands.getoutput` | `subprocess.run([...])`, `subprocess.Popen([...])` (기본 shell=False) |
| Java | `Runtime.exec(String)` (단일 문자열, 내부적으로 토큰화하지만 메타문자 처리 안 함), `Runtime.exec("sh -c ...")` | `ProcessBuilder(List<String>)`, `Runtime.exec(String[])` |
| Ruby | `` `cmd` ``, `%x{cmd}`, `system("string")`, `exec("string")`, `IO.popen("string")` | `system("cmd", "arg1", "arg2")`, `Open3.capture3("cmd", "arg")` |
| PHP | `exec`, `system`, `passthru`, `shell_exec`, `` `cmd` ``, `proc_open("string")`, `popen` | `proc_open(array)` (PHP 7.4+) |
| Go | `exec.Command("sh", "-c", x)` | `exec.Command("cmd", "arg1", "arg2")` |
| Rust | `Command::new("sh").arg("-c").arg(x)` | `Command::new("cmd").args(&[arg1, arg2])` |
| C#/.NET | `Process.Start("cmd.exe", "/c " + x)`, `Process.Start(new ProcessStartInfo { Arguments = "..." + x })` | `ProcessStartInfo { FileName="cmd", ArgumentList=[x] }` (.NET Core 2.1+) |
| PowerShell | `Invoke-Expression $x`, `iex $x` | argv 기반 cmdlet 호출 (`Get-ChildItem -Path $x` 등) |

## Source-first 추가 패턴

- 파일 업로드의 원본 파일명이 ImageMagick/ffmpeg/pdftotext 인자로 흘러가는 경로 (`originalname`)
- 아카이브 내 파일명 (zip/tar entry)
- DNS lookup/ping 기능의 호스트명 입력
- Git 클론 URL/브랜치명 입력
- Webhook payload의 필드가 변환 스크립트로 흘러가는 경로
- 메일/SMS 발송의 sender 필드
- 정적 자산 변환 파이프라인(npm scripts, webpack loader)에 사용자 데이터가 흘러가는 경우
- 문서 변환 도구 (`pandoc`, `calibre ebook-convert`, `libreoffice --convert-to`)에 파일명/옵션 전달
- 메시지 큐 페이로드(Kafka/SQS) 컨슈머가 외부 명령 호출에 사용

## 자주 놓치는 패턴 (Frequently Missed)

- **이미지/미디어 변환**: `ImageMagick`(convert), `ffmpeg`, `gs`(Ghostscript), `wkhtmltopdf` — 파일명/옵션에 사용자 입력. ImageTragick(CVE-2016-3714) 같은 형식 자체 RCE는 별개.
- **Git/SVN 명령**: `git clone ${url}`, `git checkout ${branch}` — 옵션 주입(`--upload-pack`)으로 RCE.
- **압축 도구**: `tar`/`unzip`/`7z`의 `-T`/`@filelist` 옵션 주입.
- **`spawn(cmd, args, {shell: true})`**: shell 옵션이 true로 명시된 경우. 기본값(false)이 아님에 주의.
- **Java `Runtime.exec(String)`**: 단일 문자열 형태는 공백으로 토큰화만 하고 셸 메타문자는 처리 안 함. `;`는 안 통하지만 `cmd1\ncmd2`나 인자 주입은 가능.
- **`subprocess.run("ls " + path, shell=True)`**: f-string과 함께 자주 등장.
- **인자 주입 (메타문자 없이도)**: `tar -xzf ${file}`에서 `file=--checkpoint=1 --checkpoint-action=exec=sh`. shell=False여도 옵션 시작 문자(`-`/`--`)를 차단 안 하면 위험. `--` 구분자나 `./` prefix로 방어.
- **환경변수 경유**: `LD_PRELOAD`/`PATH`를 사용자 입력으로 설정한 후 외부 명령 실행.
- **셸 스크립트 wrapping**: 코드는 `execFile`인데 호출 대상이 셸 스크립트이고 그 스크립트 내부에서 인자를 unquoted로 사용.
- **NodeJS `child_process.fork(modulePath)`**: modulePath가 사용자 입력이면 임의 JS 실행.
- **Bash Process Substitution**: `cmd <(echo $x)`, `cmd >(...)` — bash 4+ 기능. 메타문자 필터에 자주 누락.
- **`xp_cmdshell` (MSSQL) / `pg_read_server_files`**: SQLi와 결합 시 DB→OS 명령 실행. SQLi 후보 우선이지만 OS 영향도 라벨링.
- **PowerShell `Invoke-Expression` (IEX)**: 문자열을 코드로 평가. 동적 cmdlet 구성 모두 위험.
- **Python `os.execvp` 인자 주입**: 셸 미경유지만 `--option=value` 형태 인자 주입 가능.

## 안전 패턴 (FP Guard)

- **`execFile`/`spawn(cmd, [args])` (shell:false 명시 또는 기본값)**: 인자 배열로 전달, 메타문자 무력화. 단, 인자 주입(`-`로 시작) 가능성은 별도 확인.
- **`subprocess.run([...], shell=False)`** (Python).
- **`ProcessBuilder(List<String>)`** (Java).
- **`escapeshellarg($x)` + `escapeshellcmd($cmd)`** (PHP) 두 함수 모두 호출되고 결과를 그대로 사용.
- **`shlex.quote(x)`** (Python) 사용.
- **엄격 화이트리스트 검증**: 정규식 `/^[a-zA-Z0-9._-]+$/`처럼 메타문자/공백/`-` prefix 차단.
- **고정 명령 + 고정 인자**: 사용자 입력이 인자가 아닌 환경변수나 stdin으로 전달되고, 호출 대상 프로그램이 stdin을 옵션으로 해석하지 않음.
- **절대 경로 + `--` 옵션 종료자**: `tar xzf -- ${file}` 형태로 옵션 파싱 종료. 화이트리스트와 함께 사용.
- **샌드박스 격리 (seccomp/AppArmor/컨테이너 read-only rootfs)**: 영향도 감소만, 후보 자체는 유지하고 라벨링.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `escapeshellarg` 단독 (PHP, `escapeshellcmd` 미동반) | 가능 | 인자 주입 (옵션 시작 `-`/`--`) 또는 `escapeshellcmd` 미적용 시 컨텍스트 우회 |
| 메타문자 블랙리스트 (`;`, `\|` 차단) | 가능 | `` ` ``(backtick), `$()`, `\n`(newline), `\0`(NUL byte), `&` (백그라운드) 누락 시 우회 |
| 화이트리스트가 옵션 시작 문자(`-`/`--`) 미차단 | 가능 | `--checkpoint=1 --checkpoint-action=exec=sh` 같은 인자 주입 (tar/ImageMagick 류) |
| 공백 차단 | 가능 | `${IFS}` 환경변수 (`cat${IFS}/etc/passwd`), `<` redirection, brace expansion |
| ASCII 메타문자만 검증 (Unicode 미정규화) | 환경 의존 | 일부 시스템에서 `；` (fullwidth) 또는 IFS 변형으로 우회 |
| 첫 인자만 검증 후 나머지 concat | 가능 | `validInput; id` — 검증 통과 후 concat 시점에 메타문자 삽입 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → 셸 경유 sink (위 표 좌측) + 메타문자 필터 없음 | 후보 |
| 사용자 입력 → 셸 미경유 sink (`execFile` 등) + 인자 주입 차단 없음 (`-` prefix 가능) | 후보 (라벨: `ARG_INJECTION`) |
| 사용자 입력이 화이트리스트 정규식(`^[a-z0-9_-]+$` 등) 통과 후 사용 | 제외 |
| `escapeshellarg` 또는 `shlex.quote` 적용 확인 | 제외 |
| 빌드 스크립트/CI/개발 도구 컨텍스트 (런타임 미적용) | 제외 |
| 명령 wrapper가 셸 스크립트이고 내부 unquoted 사용 의심 | 후보 (라벨: `WRAPPER_UNQUOTED`) |

## 후보 판정 제한

사용자 HTTP 입력이 명령어 인자에 도달하는 경우만 후보. 빌드 스크립트, 개발 도구, 마이그레이션 코드는 제외.
