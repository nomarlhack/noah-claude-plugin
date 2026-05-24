---
id_prefix: PATHTRV
rules_dir: rules/
---

> ## 핵심 원칙: "의도하지 않은 리소스에 접근하지 못하면 취약점이 아니다"
>
> `fs.readFile(userInput)`이 있다고 LFI가 아니다. `../` 등 경로 조작 문자를 삽입하여 의도하지 않은 파일이나 내부 API 엔드포인트에 실제로 접근할 수 있어야 취약점이다.

## Sink 의미론

Path Traversal sink는 두 종류:

1. **파일 시스템 sink**: 사용자 입력이 OS 파일 경로의 일부가 되는 지점
2. **내부 API path sink**: 사용자 입력이 백엔드 HTTP 클라이언트 URL의 path 세그먼트가 되는 지점 (게이트웨이/프록시 체인에서 `%2f`/`#`로 다른 API를 호출)

| 언어 | 파일 시스템 sink |
|---|---|
| Node.js | `fs.readFile/Sync`, `createReadStream`, `readdir`, `stat`, `access`, `require()`, `import()` (동적), `res.sendFile`, `res.download`, 템플릿 엔진 `renderFile` |
| Python | `open()`, Flask `send_file/send_from_directory`, Django/FastAPI `FileResponse`, `importlib.import_module`, `__import__` |
| Java | `new File()`, `Files.readAllBytes`, `FileInputStream`, `ClassLoader.getResource(As)Stream`, `RequestDispatcher.include/forward` |
| Ruby | `File.read/open`, `IO.read`, `send_file`, `render file:` |
| PHP | `include`, `require`, `include_once`, `require_once`, `file_get_contents`, `fopen`, `readfile` |
| Go | `os.Open`, `os.ReadFile`, `os.Create`, `ioutil.ReadFile`, `filepath.Join` (검증 없으면 위험) |
| Rust | `std::fs::read`, `std::fs::File::open`, `tokio::fs::read` |
| C#/.NET | `File.ReadAllText`, `File.OpenRead`, `Server.MapPath`, `Path.Combine` (절대경로 입력 시 base 무시 — 안전하지 않음) |

**내부 API path sink:**

- Spring `WebClient.get().uri("${host}/v2/bots/${botId}/...")`에 `@PathVariable`이 직접 들어가는 경우
- Node `axios.get(\`${host}/api/${id}/data\`)`에 `req.params.id` 직접
- Python `requests.get(f"{host}/api/{param}/data")` + path param
- 프록시 미들웨어 (`http-proxy-middleware`, nginx `proxy_pass`)에서 path 그대로 전달

## Source-first 추가 패턴

- HTTP 파라미터: `file`, `path`, `page`, `template`, `include`, `doc`, `folder`, `root`, `dir`, `name`, `filename`, `download`, `lang`, `locale`, `view`, `log`
- URL 동적 라우트 파라미터 (`/files/:name`, `@PathVariable`)
- 파일 업로드의 원본 파일명
- ZIP/TAR 아카이브 내부 entry 이름 (zipslip-scanner와 겹치지만 단일 파일 LFI는 여기)
- i18n locale 코드 (`/locales/{lang}.json`)
- theme 이름 (`/themes/{theme}/style.css`)
- 다국어 PO/MO 파일 경로 (`/locales/{lang}/messages.po`)
- 백업/복구 파일 경로 (`/admin/backups/{name}/restore`)
- 로그 조회 endpoint (`/admin/logs/{file}`)

## 자주 놓치는 패턴 (Frequently Missed)

- **`path.join(BASE, userInput)`만으로는 안전하지 않다**: `../`이 BASE를 벗어남. `path.resolve` 후 `startsWith(BASE)` 체크 필수.
- **Express `res.sendFile(userPath)`**: `root` 옵션 없이 절대경로 사용 시 디스크 임의 파일 노출.
- **null byte 우회** (구버전 PHP/Node, Java < 7u40): `file=secret.pdf%00.html`로 확장자 검증 우회.
- **URL 인코딩된 traversal**: `%2e%2e%2f`, `..%2f`, `%2e%2e/`. 검증 후 디코딩되는 더블 디코딩 케이스.
- **Windows 경로 분리자**: `..\\`, `..%5c`. `\` 검증 누락.
- **Java `new File("/safe", userInput)`**: userInput이 절대경로이면 `/safe`가 무시되고 절대경로가 사용됨.
- **`require(userInput)` (Node)**: `.js`/`.json`만 로드되지만 `/proc/self/environ` 같은 정보 노출 변형.
- **`importlib.import_module(userInput)` (Python)**: 모듈 트리 walk → `os.system` 호출 가능.
- **내부 API `%2f` 우회**: Spring `WebClient.uri(...)`에 `botId=foo%252fadmin%252fdelete` → 백엔드가 디코딩 후 다른 엔드포인트.
- **`#` fragment trick**: 경로 뒤에 `#`을 넣어 뒤쪽 경로 무효화. HTTP 클라이언트가 fragment를 서버로 보내지 않음을 악용.
- **심볼릭 링크 추적**: 업로드 디렉토리에 사용자가 심볼릭 링크 생성 가능한 경우.
- **압축 해제 시 절대 경로 entry**: `/etc/passwd`로 시작하는 entry name (zipslip).
- **`res.sendFile`/`render file:` 의 옵션 객체에서 입력값이 path가 되는 경우**.
- **Unicode/UTF-8 over-long 우회**: `．．／` (fullwidth), `..%c0%af` (UTF-8 over-long for `/`) — 일부 컨테이너/언어에서 정규화.
- **Tomcat `..;/` (path parameter)**: 세미콜론으로 normalization 우회. Jetty 등 다른 컨테이너도 파싱 차이.
- **`/proc/self/...` 정보 노출**: `/proc/self/environ`, `/proc/self/maps`, `/proc/self/cwd/` — 환경변수·메모리·경로 leak.
- **Java `URL.toString()` vs `Path.normalize()` 차이**: URL은 정규화 안 함. URL 단위로 검증 후 File API로 변환 시 우회.
- **Windows ADS (Alternate Data Stream)**: `file.txt::$DATA`, `file.txt:hidden` — 스트림 명으로 우회.

## 안전 패턴 (FP Guard)

- **`path.resolve(BASE, userInput)` + `resolved.startsWith(BASE + path.sep)` 검증**.
- **Python `os.path.commonpath([base, resolved]) == base`** 검증.
- **Java `Path.normalize().startsWith(basePath)`**.
- **허용 파일 화이트리스트** (`if (!['en','ko','ja'].includes(lang)) reject`).
- **`send_from_directory(safe_dir, filename)`** (Flask) — 내부적으로 escape 검증. 단 `filename`이 절대경로면 무시되는 케이스 확인.
- **확장자 + 정규식 화이트리스트** (`/^[a-z0-9_-]+\.pdf$/`).
- **DB ID로만 파일 찾기**: 사용자 입력이 DB primary key, 실제 경로는 서버가 매핑.
- **chroot/jail/컨테이너 격리**: 프로세스가 base dir 외 접근 자체 불가 — 영향도 감소 (코드 검증과 별개).
- **Java `Path.toRealPath()` + `startsWith(basePath.toRealPath())`**: 심볼릭 링크 해결 후 비교 — symlink 우회 차단.
- **Go `filepath.Clean` + `filepath.Rel` 음수 검증**: `Rel`이 `..`로 시작하면 base 외부.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `..` 단일 문자열 차단 (`replace("..", "")`) | 가능 | `....//` (chained replace 후 `..`로 복원), `..\..\`, `..%2f`, `....\\` |
| URL 디코딩 후 `..` 검증 | 가능 | Double encoding `%252e%252e%252f` — 디코딩이 한 번만 적용되면 검증 통과 |
| 확장자 화이트리스트 (`.pdf`만 허용) | 가능 | Null byte `file.php%00.pdf` (구버전 PHP/Node), 이중 확장자 `file.php.pdf` (Apache mod_mime), Windows ADS `file.pdf::$DATA` |
| `path.resolve()` 후 `startsWith(BASE)` 검증 | 부분 가능 | Symlink 추가(공격자가 base 안에 외부로 가는 symlink 생성 가능 시), TOCTOU race |
| 절대경로 차단 (첫 글자 `/` 검증) | 가능 | Windows에서 `\path` (single backslash), UNC `\\server\share`, 환경변수 `%SYSTEMROOT%` |
| Path normalization 후 검증 | 환경 의존 | Tomcat `..;/`, Jetty `..%5c`, IIS `..\..\..` 컨테이너별 파싱 차이 — 컨테이너가 정규화 후 다른 경로 |
| Unicode 정규화 누락 | 가능 | `．．／` (fullwidth), `..%c0%af` (UTF-8 over-long) — 일부 OS/언어에서 `..`로 해석 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → 파일 sink + traversal 검증 없음 | 후보 |
| `path.resolve` 후 prefix check 확인됨 | 제외 |
| `send_file(absolute_user_path)` 또는 root 옵션 없음 | 후보 |
| 절대경로 차단 없음 (Java `new File(base, x)` 형태) | 후보 (라벨: `ABS_PATH`) |
| 내부 HTTP 클라이언트 URL에 path param 직접 삽입 + 인코딩 검증 없음 | 후보 (라벨: `INTERNAL_API_TRAVERSAL`) |
| `require(userInput)` 동적 import | 후보 (라벨: `DYNAMIC_IMPORT`) |
| 화이트리스트 또는 DB ID 매핑 확인 | 제외 |

## 후보 판정 제한

사용자 입력이 파일 시스템 경로나 내부 API 경로에 문자열 연결로 삽입되는 경우만 후보. 프레임워크 URI 템플릿이나 정수 타입 변수는 제외.
