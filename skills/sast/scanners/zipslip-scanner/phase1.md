---
id_prefix: ZIPSLIP
rules_dir: rules/
---

> ## 핵심 원칙: "의도하지 않은 경로에 파일이 생성되지 않으면 취약점이 아니다"
>
> 압축 해제 기능 자체는 취약점이 아니다. `../../../etc/cron.d/x` 같은 경로 entry가 든 악성 압축 파일로 대상 디렉토리 밖에 파일이 실제로 생성되어야 한다.

## Sink 의미론

ZipSlip sink는 "압축 entry name이 검증 없이 OS 파일 경로로 사용되어 traversal 또는 절대경로로 대상 디렉토리를 벗어날 수 있는 지점"이다.

| 언어/라이브러리 | sink/위험도 |
|---|---|
| Node `adm-zip` | `extractAllTo`, `extractEntryTo` (v0.5.10+ 패치) |
| Node `unzipper`, `unzip-stream` | 개발자 책임 |
| Node `yauzl` | 안전한 API (entry 이름만 반환) |
| Node `tar`, `tar-stream`, `decompress` | 옵션에 따라 다름 |
| Python `zipfile.extractall` | 3.12+ `filter='data'` 적용 시 안전 |
| Python `zipfile.extract` | 항상 검증 필요 |
| Python `tarfile.extractall` | 3.12+ 기본 방어, 이전은 취약 |
| Python `shutil.unpack_archive` | 내부 zipfile/tarfile 의존 |
| Java `java.util.zip.ZipInputStream/ZipFile` | 항상 개발자 책임 |
| Java `java.util.jar.JarInputStream` | 동일 |
| Java Apache Commons Compress | 동일 |
| Ruby `rubyzip` | v1.3.0+ 기본 방어 |
| Ruby `minitar` | 개발자 책임 |
| PHP `ZipArchive::extractTo` | 항상 검증 필요 |
| PHP `PharData::extractTo` | 동일 |
| Go `archive/zip`, `archive/tar` | 개발자 책임 |
| .NET `ZipFile.ExtractToDirectory` | .NET 4.5.1+ 기본 검증, 이전은 취약 |

## Source-first 추가 패턴

- 파일 업로드 (ZIP/TAR/JAR/WAR/APK/IPA)
- 패키지/플러그인/테마 설치
- 데이터 임포트 (CSV ZIP, 백업 파일)
- CI/CD 아티팩트 배포
- 이메일 첨부 파일 처리
- Docker 이미지 layer 처리
- npm/pip/gem 패키지 메타 처리
- OOXML (XLSX/DOCX/PPTX) 파일 처리

## 자주 놓치는 패턴 (Frequently Missed)

- **절대경로 entry**: `/etc/passwd`로 시작 — `path.join`은 절대경로면 base 무시. Java `new File(base, "/etc/x")`도 base 무시.
- **Windows 경로 분리자**: entry `..\\..\\etc\\x`. Linux 코드는 `/`만 검증.
- **심볼릭 링크 entry**: tar는 심볼릭 링크를 entry로 표현 가능. 압축 해제 시 심볼릭 링크 생성 → 후속 쓰기가 임의 경로로.
- **Hard link entry** (tar): 심볼릭 링크와 유사.
- **`canonicalPath` 미검증**: `new File(base, name).getPath()`만 검증, `getCanonicalPath()` 미사용 → `..` 정규화 미적용.
- **prefix check 시 separator 누락**: `canonicalPath.startsWith("/safe")`는 `/safe-evil`도 통과. `"/safe/"` 또는 `"/safe" + File.separator` 필요.
- **유니코드 정규화**: entry name 인코딩 (UTF-8 vs CP437).
- **Long path (Windows MAX_PATH 우회)**: `\\?\` prefix.
- **Zip in zip**: 외부 zip은 안전하게 풀었지만 내부 zip을 다른 코드가 처리.
- **압축 해제 라이브러리 자체 CVE** (rubyzip, adm-zip, Apache Commons Compress).
- **메모리 폭탄 (zip bomb, 42.zip)**: ZipSlip은 아니지만 동시 점검.
- **Python `tarfile`의 device 파일 entry**: `/dev/...` entry로 디바이스 노드 생성.
- **OOXML/JAR/APK 처리 코드**: 개발자가 "신뢰된 형식"이라 검증 생략하는 경향.
- **tar PAX header**: UTF-8 path 또는 긴 이름을 PAX extended header에 저장 → 일부 구현이 PAX 경로 검증 누락.
- **tar GNU long name/link name**: GNU tar의 `L`/`K` type 확장 — 구현에 따라 검증 누락.
- **Python `tarfile` `ReadError`/`HeaderError` catch 후 skip**: 악성 entry만 skip하고 다음 entry 처리 → race 조건.
- **`uncompressedSize` 신뢰 (ZIP bomb 방어)**: 압축 메타데이터의 원본 크기를 신뢰 — 실제 압축 해제 크기가 다를 수 있음.
- **.NET `ZipArchive` 스트림 모드**: `Entry.Open()` 후 수동으로 경로 조합 시 검증 책임 개발자에게 이전.

## 안전 패턴 (FP Guard)

- **Java**: `canonicalPath` 추출 후 `targetCanonical + File.separator`로 prefix 검증.
- **Python 3.12+**: `extractall(target, filter='data')`.
- **Python < 3.12**: 수동으로 `os.path.realpath` + `commonpath` 검증.
- **Go**: `filepath.Clean` 후 `strings.HasPrefix(cleaned, base+string(os.PathSeparator))`.
- **Node**: `path.resolve(base, name).startsWith(path.resolve(base) + path.sep)`.
- **rubyzip 1.3.0+** 기본 사용.
- **adm-zip 0.5.10+** + `extractAllTo`.
- **심볼릭 링크 entry skip**: tar 처리 시 `entry.type !== 'symlink'` 필터.
- **절대경로 차단**: `if (path.isAbsolute(name)) reject`.
- **샌드박스 디렉토리** + chroot/namespace 격리.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `startsWith(base)` (separator 누락) | 가능 | entry name이 `/safe-evil/x`로 해결되어 prefix 통과 |
| `..` 단일 문자열 차단 | 가능 | Windows `..\\`, URL-encoded `%2e%2e%2f`, 중첩 `....//`, overlong UTF-8 |
| 절대경로만 차단 (`path.isAbsolute`) | 부분 가능 | 상대 `../` traversal은 통과. Windows drive letter (`C:\\`) 또는 UNC (`\\\\server\\share`) 별도 |
| canonical path 검증 후 해제 | 가능 | TOCTOU race — 검증 시점과 쓰기 시점 사이 symlink 생성 가능 |
| symlink entry skip | 부분 가능 | hard link, tar PAX header 우회 구현별 차이 |
| 압축 해제 전 검증 루프 | 가능 | 검증 후 실제 해제가 별도 library 호출이면 구현 차이 — 한쪽은 통과, 다른 쪽은 다른 해석 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 업로드 압축 + 위 표 위험 sink + canonical path 검증 없음 | 후보 |
| Java `new File(target, entry.getName())` + getCanonicalPath 검증 없음 | 후보 |
| prefix check 있으나 separator 누락 (`startsWith("/safe")`) | 후보 (라벨: `PREFIX_BYPASS`) |
| 절대경로 entry 검증 없음 | 후보 (라벨: `ABS_PATH`) |
| 심볼릭 링크 entry 처리 (tar) + skip 없음 | 후보 (라벨: `SYMLINK`) |
| Python 3.12+ `filter='data'` 확인 | 제외 |
| rubyzip 1.3.0+ / adm-zip 0.5.10+ + 안전 API | 제외 |
| canonical path + separator prefix 정확 검증 | 제외 |

## 후보 판정 제한

사용자 업로드 파일을 압축 해제하는 코드가 있는 경우만 후보.
