---
id_prefix: UPLOAD
rules_dir: rules/
---

> ## 핵심 원칙: "악성 파일이 업로드되고 접근 가능하지 않으면 취약점이 아니다"
>
> 파일 업로드 기능 자체는 취약점이 아니다. (1) 위험한 파일이 업로드되고, (2) 업로드된 파일에 접근 가능하며, (3) 서버에서 실행되거나 다른 사용자에게 서빙되어야 한다. "확장자 검증이 없다"만 보고하는 것은 부족 — 저장 위치와 서빙 방식까지 추적해야 한다.

## Sink 의미론

File Upload sink는 "사용자가 제공한 바이트가 디스크/스토리지에 기록되고, 그 결과물이 서버 실행/타인 다운로드의 입력이 되는 지점"이다. 단순 디스크 기록(`fs.writeFile`) 자체는 sink가 아니고, 그 결과가 어떻게 노출되는지가 핵심.

| 언어/라이브러리 | 업로드 처리 |
|---|---|
| Node.js | `multer`, `formidable`, `busboy`, `multiparty`, `express-fileupload` |
| Python | Django `FileField`/`ImageField`, Flask `request.files`, FastAPI `UploadFile` |
| Java | Spring `MultipartFile`, Apache Commons FileUpload |
| Ruby | Rails `ActiveStorage`, CarrierWave, Shrine |
| PHP | `$_FILES`, `move_uploaded_file()` |
| Go | `r.FormFile`, `multipart.Reader` |
| C#/.NET | `IFormFile`, `Request.Form.Files`, `MultipartReader` |
| Rust | `actix-multipart`, `axum::extract::Multipart`, `rocket::data::Data` |

**검증 차원:**
1. 파일 유형 (Content-Type/확장자/매직 바이트)
2. 파일명 처리 (traversal, null byte, 이중 확장자)
3. 저장 위치 (웹루트 안/밖, 클라우드)
4. 서빙 방식 (Content-Type, Disposition, nosniff)
5. 크기/요청 수 제한

## Source-first 추가 패턴

- `multipart/form-data` 처리 라우트
- 프론트엔드 `FormData` 전송 코드 → 매핑되는 서버 라우트
- 프로필 이미지 업로드
- 첨부 파일 업로드
- 임포트 기능 (CSV/Excel/ZIP)
- 아바타/배경 업로드
- 리치 에디터 이미지 paste 업로드
- API gateway에서 multipart 통과 라우트
- drag-and-drop 또는 paste 이벤트 (clipboard image) 후 자동 업로드
- WebSocket binary frame 수신 후 디스크/스토리지 저장
- WebDAV `PUT` 업로드 활성화 라우트

## 자주 놓치는 패턴 (Frequently Missed)

- **이중 확장자 (`shell.php.jpg`)**: Apache `mod_mime` `AddHandler` 설정에 따라 `.php`로 실행. nginx도 `\0`/null byte 잔존 케이스.
- **Content-Type만 검증, 확장자 미검증**: 클라이언트가 Content-Type 위조 → 서버는 통과 → 파일명에 `.php` → 웹서버가 확장자로 실행 결정.
- **확장자 검증, 매직바이트 미검증**: PNG로 위장한 PHP 웹셸. `<?php` 코드 + GIF 헤더.
- **SVG XSS**: SVG는 XML + JavaScript 실행 가능. 이미지로 취급되지만 브라우저에서 열면 XSS.
- **HTML/SVG가 same-origin으로 서빙**: `Content-Disposition: attachment` 없이 `inline` 서빙 + 사용자 도메인이면 XSS.
- **Path traversal in filename**: `filename: "../../etc/cron.d/x"`.
- **Null byte (`shell.php\0.jpg`)**: 일부 레거시 환경에서 `\0` 이후 무시.
- **`.htaccess` 업로드**: Apache 환경에서 업로드된 디렉토리에 `.htaccess`를 두면 처리 규칙 변경.
- **`.config`/`web.config`** (IIS): 동일 효과.
- **ZIP/TAR 폭탄 (decompression bomb)**: 작은 파일이 압축 해제 시 디스크 가득 채움.
- **이미지 처리 라이브러리 RCE** (ImageMagick `ImageTragick`, libwebp, libvips): 파일 변환 자체가 sink.
- **EXIF/XMP 메타데이터 노출**: GPS 좌표 등 PII.
- **클라우드 스토리지 ACL**: S3 bucket public-read 또는 presigned URL 만료 미설정.
- **CDN 캐시 + 동일 파일명 덮어쓰기**: 사용자 A 파일이 사용자 B에게 캐시 응답.
- **`Content-Type: image/jpeg`로 강제 서빙해도 `X-Content-Type-Options: nosniff` 없으면 IE/구버전이 sniff**.
- **Polyglot 파일**: GIF + JS 동시 valid → `<script src="image.gif">` 로 JS 실행.
- **파일명에 RTL 유니코드** (`evil\u202Egpj.exe`): UI에서 `evilexe.jpg`로 보임.
- **Concurrent upload race**: 임시 파일 → 검증 → 이동의 race window.
- **CRLF in filename → Content-Disposition 인젝션**: `filename="x\r\nSet-Cookie: ..."` — HTTP 응답 헤더 분리.
- **AWS S3 metadata 인젝션**: 사용자 입력을 `x-amz-meta-*` 헤더로 전달 시 CRLF/제어 문자.
- **Markdown 이미지 임베드 (`![](url)`)**: 외부 이미지 URL 자동 fetch → SSRF/XSS 변환.
- **HTTP/2 multipart 파서 차이**: 일부 서버 구현이 boundary/Content-Type 처리 다름 — 동일 페이로드 다른 결과.
- **Symbolic link 업로드 → ZIP/TAR 해제 시**: 일부 환경에서 symlink follow → 시스템 파일 덮어쓰기 (zipslip-scanner와 연계).

## 안전 패턴 (FP Guard)

- **랜덤 파일명 생성** (UUID) + 원본 확장자 무시 또는 매핑 테이블.
- **웹루트 외부 저장** + API 통한 서빙 (Content-Type/Disposition 강제).
- **클라우드 스토리지 (S3 등) + private bucket** + presigned URL 만료.
- **매직 바이트 검증** (`file-type` 라이브러리, `python-magic`).
- **이미지 재인코딩** (sharp/Pillow re-save) — 메타데이터 제거 + 악성 페이로드 무력화.
- **`Content-Disposition: attachment`** 강제.
- **`X-Content-Type-Options: nosniff`** 헤더.
- **확장자 화이트리스트** + 케이스 정규화 + 다중 확장자 차단 (`if (filename.split('.').length > 2) reject`).
- **크기 제한** + rate limit.
- **별도 도메인에서 서빙** (`usercontent.example.com`) — same-origin XSS 차단.
- **CSP `sandbox`/`Content-Security-Policy: sandbox`**.
- **이미지 재인코딩 + max dimensions + strip metadata** (sharp/Pillow): 메타데이터/EXIF 제거, 폴리글랏 무력화.
- **AntiVirus 통합 (ClamAV/VirusTotal API)**: 업로드 시점 또는 비동기 스캔 후 격리.
- **Sandboxed iframe + CSP `script-src 'none'` for upload domain**: 업로드 전용 origin에서 스크립트 자체 실행 불가.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| 확장자 블랙리스트 (`.php` 차단) | 가능 | `.phtml`, `.php5`, `.php7`, `.phar`, `.pht`, `.phps` 우회 (Apache `AddHandler` 설정 의존) |
| 매직바이트 검증만 (확장자 미검증) | 가능 | Polyglot 파일 — GIF89a 헤더 + PHP 코드 → `.php`로 저장되면 실행 |
| Content-Type 헤더만 검증 | 가능 | 클라이언트가 `image/jpeg`로 위조 + 실제 내용은 PHP/JSP |
| 첫 청크 매직바이트만 검증 (스트리밍) | 가능 | 첫 N바이트만 매직바이트 일치, 이후 청크에 악성 페이로드 |
| 확장자 정규식 `\.(jpg\|png)$` | 환경 의존 | URL fragment 트릭 `image.jpg#.php` (특정 reverse proxy/CDN 설정), null byte `image.jpg%00.php` |
| ZIP 검증 후 추출 (TOCTOU) | 가능 | 검증 시점 entry와 추출 시점 entry 사이 race — 다른 프로세스가 ZIP 교체 |
| 이미지 재인코딩 (보안 효과 가정) | 부분 가능 | ImageMagick/libvips/libwebp 자체 RCE (ImageTragick CVE-2016-3714, libwebp CVE-2023-4863) — 재인코딩 자체가 sink |
| 파일명 sanitize (path traversal 차단) | 가능 | RTL 유니코드 `\u202E` 또는 zero-width space로 UI 위장, Windows ADS `file.jpg::$DATA` |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 확장자 검증 없음 + 웹루트 저장 + 원본 Content-Type 서빙 | 후보 (라벨: `RCE_RISK`) |
| 확장자 화이트리스트 있으나 SVG/HTML 허용 + 같은 도메인 서빙 | 후보 (라벨: `STORED_XSS`) |
| 매직바이트 검증 + 재인코딩 + 클라우드 저장 | 제외 |
| 별도 도메인 + Content-Disposition attachment | 제외 |
| 파일명을 그대로 디스크 경로로 사용 (UUID 미적용) | 후보 (라벨: `PATH_TRAVERSAL`) |
| 이미지 처리 라이브러리 직접 호출 + 버전 미패치 (ImageMagick/libvips) | 후보 (라벨: `IMAGE_LIB_RCE`) |
| 압축 해제 후 처리 (ZIP/TAR) | zipslip-scanner와 연계 |
| 크기 제한 없음 + 동기 처리 | 후보 (라벨: `DOS`) |

## 후보 판정 제한

파일 업로드를 파라미터로 받는 엔드포인트가 있는 경우만 후보. import만 있고 호출부가 없으면 제외.
