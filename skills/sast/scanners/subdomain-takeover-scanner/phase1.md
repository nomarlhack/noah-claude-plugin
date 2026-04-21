---
id_prefix: SUBTO
grep_patterns:
  - "\\.github\\.io"
  - "\\.s3\\.amazonaws\\.com"
  - "\\.s3-website"
  - "\\.herokuapp\\.com"
  - "\\.herokudns\\.com"
  - "\\.azurewebsites\\.net"
  - "\\.cloudapp\\.azure\\.com"
  - "\\.blob\\.core\\.windows\\.net"
  - "\\.cloudfront\\.net"
  - "aws_route53_record"
  - "cloudflare_record"
  - "CNAME"
  - "github\\.io"
---

> ## 핵심 원칙: "공격자가 서브도메인을 장악할 수 없으면 취약점이 아니다"
>
> CNAME이 외부 서비스를 가리키는 것 자체가 취약점이 아니다. 외부 서비스에서 리소스가 해제/삭제되어 있고 공격자가 같은 이름으로 리소스를 생성해 콘텐츠를 제어할 수 있어야 한다.

## Sink 의미론

Subdomain Takeover sink는 "프로젝트 소유 도메인의 DNS 레코드(주로 CNAME)가 외부 SaaS의 호스트네임을 가리키는데, 그 호스트네임이 미사용/해제 상태가 될 수 있는 지점"이다. 코드 sink가 아닌 **인프라/설정 sink**.

| 카테고리 | 설정 위치 |
|---|---|
| Terraform | `aws_route53_record`, `cloudflare_record`, `google_dns_record_set` |
| CloudFormation | `AWS::Route53::RecordSet` |
| Kubernetes | `Ingress.spec.rules[].host` |
| nginx | `server_name`, `proxy_pass` |
| docker-compose | 외부 서비스 hostname |
| DNS zone 파일 | `.zone`, BIND |

**위험 외부 서비스 (대표):**
- AWS S3 (`s3-website-*.amazonaws.com`)
- AWS CloudFront (`*.cloudfront.net`)
- AWS Elastic Beanstalk (`*.elasticbeanstalk.com`)
- Azure (`*.azurewebsites.net`, `*.cloudapp.net`, `*.trafficmanager.net`)
- GitHub Pages (`*.github.io`)
- GitLab Pages
- Heroku (`*.herokuapp.com`)
- Shopify (`*.myshopify.com`)
- Tumblr (`*.tumblr.com`)
- WordPress.com
- Fastly
- Pantheon
- Zendesk (`*.zendesk.com`)
- Surge.sh
- Bitbucket Pages
- Webflow
- Tilda
- Cargo Collective
- Tictail
- Helpjuice / Helpscout
- Statuspage.io
- Unbounce
- Strikingly
- Acquia
- Netlify (현재는 보호됨)
- Vercel (현재는 보호됨)

각 서비스마다 "fingerprint" 응답이 다름 (예: S3 `NoSuchBucket`, GitHub `There isn't a GitHub Pages site here.`).

## Source-first 추가 패턴

- IaC 저장소 전체 grep
- 환경변수에서 외부 서비스 호스트
- 프론트엔드 환경변수 (`NEXT_PUBLIC_API_URL` 등)
- README/문서에 언급된 서브도메인
- CI/CD 배포 대상 도메인
- 이메일 서비스 (`*.sendgrid.net`, `*.mailgun.org`) — DKIM/SPF/CNAME
- CDN 설정의 origin 호스트
- 마케팅 페이지 (`landing.example.com`)
- 인수합병 후 잔존 도메인
- 임시/스테이징 (`staging-*`, `*-old`, `*-legacy`)

## 자주 놓치는 패턴 (Frequently Missed)

- **테스트/스테이징/이전 환경**: `staging-2019.example.com`, `old-app.example.com` — 보통 보안 점검 대상에서 누락.
- **인수 도메인 잔존**: 회사 합병 후 사용하지 않는 도메인.
- **마케팅 캠페인 임시 도메인**: 캠페인 종료 후 외부 서비스 해지하지만 DNS 레코드 잔존.
- **CDN edge 변경 잔존**: CloudFront distribution 삭제했는데 CNAME 잔존.
- **Heroku 앱 삭제 후 DNS 잔존**.
- **GitHub Pages 리포지토리 삭제 후**.
- **Shopify 스토어 닫은 후**.
- **Helpdesk/Support 페이지 (Zendesk/Helpjuice)**: 서비스 변경 시.
- **이메일 서비스 변경 (Sendgrid/Mailgun)**: DKIM CNAME 잔존 → 이메일 스푸핑.
- **NS Takeover**: NS 레코드가 비활성 nameserver 가리킴.
- **Wildcard CNAME**: `*.dev.example.com` → 외부 서비스 → 모든 서브도메인 takeover.
- **MX 레코드 takeover**: 외부 메일 서비스 미사용.
- **`SPF include:` 외부 도메인**: include 대상 도메인이 만료되면 SPF 우회.
- **Route 53 + CloudFront alias**: alias가 삭제된 distribution.
- **Vanity URL 제공자** (`bit.ly` 커스텀 도메인 등).
- **Storage CNAME** (Google Cloud Storage `c.storage.googleapis.com`).
- **App Engine version 삭제 후 custom domain 잔존**.
- **Azure Resource Group 전체 삭제 후 DNS 잔존**.
- **Multi-region failover의 secondary** 미사용.
- **Kubernetes `ExternalName` Service**: 외부 hostname 변경 후 cluster 내부 참조 잔존 — 클러스터 내부 SSRF 변형.
- **Cloud CDN origin 그룹의 fallback origin**: primary 삭제 후 fallback이 takeover 가능 서비스.
- **Tracking pixel 서비스** (`track.example.com` → 제3자): 분석 도구 해지 후 픽셀 URL이 잔존하여 stored XSS 변형.
- **Shortened URL 서비스 연계**: `go.example.com` → Bitly 커스텀 도메인 — 해지 시 takeover.

## 안전 패턴 (FP Guard)

- **CNAME이 자체 인프라**: `app.example.com` → `app-lb.example.com` (자체 LB).
- **A 레코드 (CNAME 아님)** + 자체 IP.
- **외부 서비스가 takeover 보호 활성화** (Netlify, Vercel 최신은 도메인 검증 필수).
- **DNS 모니터링** (DNS twist, dangling DNS 자동 탐지) 운영 확인.
- **사용 중인 외부 서비스가 active** (정기 audit 결과).

## 우회 가능 패턴

방어 처리가 있지만 takeover가 여전히 가능한 경우.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| 외부 서비스 domain verification (TXT 레코드) | 부분 가능 | 과거 레코드 해지 후 재활성화 없음 — 공격자가 verification 재설정 후 리소스 생성 |
| DNS 모니터링 (dangling CNAME 탐지) | 부분 가능 | 모니터링 주기 사이 공백, 또는 서비스별 fingerprint 누락 |
| 자체 CDN origin 사용 | 부분 가능 | CDN edge/worker가 외부 서비스 fallback 호출하면 여전히 takeover 체인 |
| `_dmarc` / SPF / DKIM 검증 | 부분 가능 | SPF include 체인의 외부 도메인이 dangling — spoof 가능 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| CNAME → 위 위험 서비스 호스트네임 | 후보 (Phase 2: HTTP fingerprint 확인) |
| `staging-*`/`old-*`/`legacy-*` 패턴 | 후보 (라벨: `STALE_ENV`) |
| Wildcard CNAME → 외부 서비스 | 후보 (라벨: `WILDCARD`) |
| MX/NS 레코드 → 외부 서비스 | 후보 (라벨: `MX_TAKEOVER`/`NS_TAKEOVER`) |
| SPF include → 외부 도메인 | 후보 (라벨: `SPF_INCLUDE`) |
| CNAME → 자체 인프라 | 제외 |
| 외부 서비스 takeover 보호 활성화 확인 | 제외 |
| 주석/문서 내 참조 (실제 DNS 레코드 아님) | 제외 |

## 후보 판정 제한

프로젝트 소유 도메인의 DNS 레코드가 외부 서비스를 가리키는 경우만 후보. 주석 내 참조 링크는 제외. 결정적 판정은 Phase 2 fingerprint 확인.
