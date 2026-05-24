---
id_prefix: SRCMAP
rules_dir: rules/
---

> ## 핵심 원칙: "민감한 정보가 노출되어야 영향이 있다"
>
> Source Map 다운로드 가능 자체가 후보지만, 영향도는 포함된 내용에 따라 다르다. API 키/시크릿/내부 API 경로/주석 내 자격증명이 노출되면 심각도 격상.

## Sink 의미론

Sourcemap sink는 "프로덕션 빌드 산출물에 `.map` 파일이 포함되거나 `//# sourceMappingURL` 주석이 남아 클라이언트가 원본 소스를 복원할 수 있는 지점"이다. 빌드 설정과 배포 산출물 양쪽을 점검해야 한다.

| 빌드 도구 | 설정 |
|---|---|
| Webpack | `devtool` (`source-map`/`hidden-source-map`/`nosources-source-map`/`false`) |
| Vite | `build.sourcemap` (`true`/`false`/`'hidden'`/`'inline'`) |
| Next.js | `next.config.js` `productionBrowserSourceMaps` |
| Create React App | `GENERATE_SOURCEMAP` 환경변수 |
| Vue CLI | `vue.config.js` `productionSourceMap` |
| Rollup | `output.sourcemap` |
| esbuild | `--sourcemap`/`sourcemap` 옵션 |
| Parcel | `--no-source-maps` 플래그 부재 |
| Angular CLI | `angular.json` `sourceMap` |
| Nuxt | `sourcemap` (`build.sourcemap`/`server.sourcemap`/`client.sourcemap`) |
| TypeScript `tsc` | `tsconfig.json` `sourceMap` |

## Source-first 추가 패턴

- 환경별 빌드 설정 분리 (dev/prod)
- CI/CD 빌드 명령 (`NODE_ENV=production`)
- Dockerfile 빌드 단계
- `.env.production`
- artifacts.zip / dist 폴더 구조
- CDN 캐시 정책 (`.map` 파일 캐시)
- Sentry/Datadog 등 에러 모니터링 통합 (sourcemap upload + clean)

## 자주 놓치는 패턴 (Frequently Missed)

- **`hidden-source-map`이 안전하다는 오해**: hidden은 `.map` 파일을 만들지만 `sourceMappingURL` 주석을 안 남길 뿐. `.map` 파일이 동일 경로에 배포되면 그대로 다운로드 가능. **추측 가능한 이름**(`bundle.js.map`)이면 무용지물.
- **`.map.gz` / `.map.br`**: gzip/brotli 압축본 잔존.
- **인라인 sourcemap (`data:application/json;base64,...`)**: 번들 파일 안에 통째로 포함. 더 큰 노출.
- **Sentry/Datadog upload + 미삭제**: 에러 모니터링용으로 업로드 후 배포물에서 삭제 안 함.
- **`.css.map`**: JS만 점검하고 CSS 누락.
- **third-party 라이브러리 sourcemap**: 본인 코드는 삭제했지만 vendor sourcemap 잔존.
- **service worker (`sw.js.map`)**.
- **API 키 하드코딩이 sourcemap으로 노출**: 코드는 minify되어 grep 어려운데, sourcemap의 원본 코드에서 평문 발견.
- **내부 API 엔드포인트 노출**: `internal-api.example.com/admin/...` 같은 경로.
- **주석에 자격증명**: 개발자가 임시 작성한 주석.
- **TypeScript 타입 정의 누설**: DB 스키마/내부 데이터 모델.
- **Webpack `__webpack_require__` 모듈 트리**: 모든 모듈 이름/경로 노출.
- **Source map의 `sourcesContent` 필드**: 원본 소스 그대로 임베드.
- **dev 설정이 prod로 빌드되는 잘못된 NODE_ENV**.
- **Docker multi-stage build의 stage 누락**: dev 산출물이 prod 이미지로.
- **`.next/static/chunks/*.map`** (Next.js): `productionBrowserSourceMaps: false`라도 서버 sourcemap은 별도.
- **CI artifact가 public**: GitHub Actions artifact가 public repo.
- **CDN 디렉토리 listing**: `.map` 파일 enumeration.
- **Cloud storage (S3/GCS) public bucket**: 배포 artifact를 bucket에 업로드하고 `.map`도 함께 public.
- **Sourcemap embedded in 주석 블록 (`/*# sourceMappingURL=...*/`)**: 주석 기반 sourcemap이 잔존하면 `//#`과 별개로 탐지 필요.
- **Webpack `output.devtoolNamespace` 변경 미적용**: 기본 네임스페이스면 모듈 경로 명확.
- **Vite `build.minify: false` 운영 빌드**: minification 없이 배포되면 sourcemap 없이도 원본 수준 정보 노출.

## 안전 패턴 (FP Guard)

- **`devtool: false`** (Webpack) 또는 미설정.
- **`productionSourceMap: false`** (Vue CLI).
- **`productionBrowserSourceMaps: false`** (Next.js, 기본값).
- **`GENERATE_SOURCEMAP=false`** (CRA).
- **빌드 후 `.map` 파일 명시 삭제** (CI 단계).
- **Sourcemap을 별도 private 스토리지로 upload + 배포물에서 제거** (Sentry CLI `--no-rewrite` + post-build clean).
- **CDN에서 `.map` 확장자 차단** (path filter).
- **인증 보호된 sourcemap 서버** (Sentry symbolicator 등).

## 우회 가능 패턴

방어 처리가 보이지만 sourcemap이 여전히 노출되는 경우.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| CI에서 `*.map` 삭제 | 가능 | `*.map.gz`/`*.map.br` 압축본 잔존, `.css.map` 누락, `sw.js.map`/`service-worker.js.map` 누락 |
| CDN path filter (`.map` 확장자 차단) | 가능 | path traversal `/js/../..//bundle.js.map`, query parameter 추가로 filter 우회 |
| `hidden-source-map` | 가능 | 파일은 있고 주석만 없음 — 추측 가능한 이름(`bundle.js.map`, `main.[contenthash].js.map`)이면 enumeration |
| Sentry upload 후 삭제 | 부분 가능 | Sentry public release artifact가 권한 설정에 따라 조회 가능할 수 있음 |
| 인증된 sourcemap server | 부분 가능 | 인증 토큰이 클라이언트 번들에 하드코딩 또는 예측 가능 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 빌드 설정이 prod에서도 sourcemap 활성 (`devtool: 'source-map'`/`productionSourceMap: true`) | 후보 (Phase 2: 실제 다운로드 확인) |
| `hidden-source-map` + `.map` 파일 동일 경로 배포 | 후보 (라벨: `HIDDEN_BUT_EXPOSED`) |
| 인라인 sourcemap (`devtool: 'inline-source-map'`) | 후보 (라벨: `INLINE`) |
| Sentry upload + 배포 clean step 누락 | 후보 (라벨: `SENTRY_LEFTOVER`) |
| `devtool: false` + CI에 `.map` 삭제 step 확인 | 제외 |
| `productionBrowserSourceMaps: false` (Next.js) + 서버 sourcemap 별도 처리 | 제외 |
| Phase 2에서 실제 다운로드 시도 + 200 응답 + sourcesContent 포함 | 확정 |

## 후보 판정 제한

프로덕션 빌드 산출물에 sourcemap 노출 가능성이 있는 설정/배포 구조만 후보. 결정적 판정은 Phase 2의 실제 HTTP fetch.
