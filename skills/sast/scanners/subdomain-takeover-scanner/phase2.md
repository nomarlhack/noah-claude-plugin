### 정찰 페이로드

**DNS 레코드 수집:**
```bash
# CNAME 체인
dig CNAME blog.target.com +short
dig CNAME blog.target.com +trace

# 다수 서브도메인 일괄
for sub in blog docs api staging admin old legacy support help status mail; do
  echo -n "$sub.target.com → "
  dig CNAME "$sub.target.com" +short
done

# NS, MX 레코드
dig NS blog.target.com +short
dig MX target.com +short
dig TXT target.com +short

# Wildcard 확인
dig A random-$(date +%s).target.com +short
```

**서브도메인 enumeration (외부 도구):**
```bash
# subfinder/amass/assetfinder 같은 패시브 도구
subfinder -d target.com -silent
amass enum -passive -d target.com
assetfinder target.com

# crt.sh (Certificate Transparency)
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# DNS brute force (SecLists)
# subbrute/dnsx 등
```

---

### 기본 페이로드

**서비스별 fingerprint 확인:**
```bash
# HTTP 응답으로 미사용 확인
curl -sI "https://blog.target.com" | head -5
curl -s "https://blog.target.com" | head -30
```

**대표 fingerprint:**

| 서비스 | Fingerprint |
|---|---|
| GitHub Pages | `There isn't a GitHub Pages site here.` |
| AWS S3 | `<Code>NoSuchBucket</Code>` |
| AWS CloudFront | `Bad request. ERROR: The request could not be satisfied` |
| Heroku | `No such app`, `herokucdn.com/error-pages/no-such-app.html` |
| Azure Web | `404 Web Site not found` |
| Azure Storage | `<Code>BlobNotFound</Code>` |
| Shopify | `Sorry, this shop is currently unavailable` |
| Zendesk | `Help Center Closed` |
| Fastly | `Fastly error: unknown domain` |
| Unbounce | `The requested URL was not found on this server` |
| Tumblr | `Whatever you were looking for doesn't currently exist` |
| Surge.sh | `project not found` |
| Pantheon | `The gods are wise, but do not know of the site which you seek.` |
| Cargo | `The page you were looking for does not exist.` |
| Tilda | `Please renew your subscription` |
| WordPress.com | `Do you want to register *.wordpress.com?` |
| Bitbucket | `Repository not found` |
| Helpjuice | `We could not find what you're looking for.` |
| Statuspage.io | `You are being redirected.` |
| Strikingly | `PAGE NOT FOUND.` |

**서비스별 상세 검증:**
```bash
# S3 bucket 존재 확인 + 생성 가능 여부
curl -s "http://BUCKET.s3.amazonaws.com/" | grep -E "NoSuchBucket|<Code>"
aws s3 ls "s3://BUCKET/" --no-sign-request 2>&1
aws s3api head-bucket --bucket BUCKET --no-sign-request 2>&1

# GitHub Pages repo 확인
curl -s "https://api.github.com/repos/OWNER/REPO" | jq .message

# Azure: NXDOMAIN이면 takeover 가능
dig A SUBDOMAIN +short
nslookup SUBDOMAIN
```

**MX/NS takeover** (`MX_TAKEOVER`/`NS_TAKEOVER` 라벨):
```bash
# MX → 외부 메일 서비스 + 계정 해지
dig MX target.com +short
# mail.target.com → 해지된 Zoho/Sendgrid

# NS → 비활성 nameserver
dig NS blog.target.com +short
```

**SPF include** (`SPF_INCLUDE` 라벨):
```bash
dig TXT target.com +short | grep spf
# include:external-service.com — 만료된 도메인 포함 시 SPF 우회
```

**자동화 도구:**
```bash
# subjack/takeover/SubOver 등 (외부 도구)
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json
```

---

**우회 페이로드 (방어 있어도 takeover 가능):**

| 방어 | 페이로드 |
|---|---|
| 외부 서비스 domain verification (TXT) | 과거 TXT 레코드 해지 후 재등록 없음 → 공격자 재설정 후 리소스 생성 |
| DNS 모니터링 | 모니터링 주기 사이 공백, 서비스별 fingerprint 누락 |
| 자체 CDN origin | CDN edge/worker가 외부 fallback 호출 시 체인 |
| DMARC/SPF/DKIM 검증 | SPF include 체인의 외부 도메인 dangling 시 spoof |
| Wildcard 차단 | 명시 등록된 서브도메인만 점검 — 이전 캠페인 잔존 누락 |

---

### 참고사항

- 가장 흔한 패턴: 마케팅 캠페인 종료 후 외부 서비스 해지하지만 DNS 잔존
- `staging-*`, `old-*`, `legacy-*`, `cbt-*` 접두사가 가장 위험 — 일반 보안 점검에서 누락
- GitHub Pages takeover는 repo fork + Pages 활성화로 가장 쉬움
- Heroku/Shopify는 계정 등록으로 takeover
- MX takeover는 이메일 스푸핑으로 영향도 매우 높음 — DKIM/SPF 결합 시 심각
- Subdomain takeover PoC는 실제 서비스 리소스 생성이 필요 — sandbox/승인된 환경 한정
- 확인된 takeover는 XSS → cookie 탈취, phishing page 등으로 영향 확장
- Federation 메타데이터, SSO callback 도메인에 takeover 가능 서브도메인 있으면 심각
- 인수합병 후 도메인 잔존도 자주 발견 — 소스코드/문서에 레거시 도메인 언급 있으면 확인
- Netlify/Vercel은 최신 domain verification 강제 — 일반적 takeover 차단
- crt.sh는 CT 로그 기반 — 과거 발급 인증서로 미공개 서브도메인 enumeration 가능
- Kubernetes ExternalName Service 변경 후 cluster 내부 참조 잔존도 변형 — 클러스터 내부 SSRF
- CDN origin group의 fallback이 takeover 가능 서비스면 영향 확장
- Tracking pixel 서비스 (`track.example.com` → 제3자) 해지 후 잔존 → stored XSS 변형
- 단순 fingerprint 매칭만으론 false positive 가능 — 실제 리소스 생성 시도 필요 (sandbox)
