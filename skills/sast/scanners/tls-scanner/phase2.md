### Phase 2: 동적 테스트 (검증)

**도구 선택:** `openssl s_client` + curl. Playwright 미사용.

**기본 원칙:**
- 모든 판정은 **실제 TLS 핸드셰이크 결과** 기반
- 각 테스트는 `timeout 10` 적용
- HSTS는 Test 7에서 (전송 계층 보안)

---

## Test 1: 프로토콜 버전 (`TLS_WEAK_VERSION` / `TLS_DOWNGRADE`)

```bash
echo | timeout 10 openssl s_client -connect target:443 -ssl3 2>&1 | grep -E "Protocol|alert|handshake failure"
echo | timeout 10 openssl s_client -connect target:443 -tls1 2>&1 | grep -E "Protocol|alert|handshake failure"
echo | timeout 10 openssl s_client -connect target:443 -tls1_1 2>&1 | grep -E "Protocol|alert|handshake failure"
echo | timeout 10 openssl s_client -connect target:443 -tls1_2 2>&1 | grep -E "Protocol|Cipher"
echo | timeout 10 openssl s_client -connect target:443 -tls1_3 2>&1 | grep -E "Protocol|Cipher"
```

| 응답 | 판정 |
|---|---|
| SSLv3/TLS 1.0/TLS 1.1 핸드셰이크 성공 | 확인됨 |
| `alert protocol version` / `handshake failure` | 안전 (해당 프로토콜 거부) |

## Test 2: Cipher Suite (`TLS_WEAK_CIPHER` / `TLS_NO_PFS` / `TLS_PADDING_ORACLE`)

```bash
# NULL/익명
echo | timeout 10 openssl s_client -connect target:443 -cipher 'NULL:eNULL:aNULL' 2>&1 | grep -E "Cipher|alert|handshake failure"

# EXPORT
echo | timeout 10 openssl s_client -connect target:443 -cipher 'EXPORT' 2>&1 | grep -E "Cipher|alert|handshake failure"

# DES/3DES
echo | timeout 10 openssl s_client -connect target:443 -cipher 'DES:3DES' 2>&1 | grep -E "Cipher|alert|handshake failure"

# RC4
echo | timeout 10 openssl s_client -connect target:443 -cipher 'RC4' 2>&1 | grep -E "Cipher|alert|handshake failure"

# 현재 cipher
echo | timeout 10 openssl s_client -connect target:443 2>&1 | grep -E "Cipher    :|Protocol  :"

# CBC mode (padding oracle 가능성)
echo | timeout 10 openssl s_client -connect target:443 -cipher 'AES128-SHA:AES256-SHA' 2>&1 | grep Cipher
```

## Test 3: 인증서 체인 (`TLS_NO_CERT_VERIFY` / `TLS_TRUST_ALL` / `TLS_WEAK_KEY`)

```bash
echo | timeout 10 openssl s_client -connect target:443 -showcerts 2>&1 | grep -E "Verify return code|subject=|issuer=|notAfter"
echo | timeout 10 openssl s_client -connect target:443 2>&1 | openssl x509 -noout -text 2>&1 | grep -E "Public-Key:|ASN1 OID:|Signature Algorithm:|Not After"
```

| 응답 | 판정 |
|---|---|
| `Verify return code: 0 (ok)` | 정상 |
| `Verify return code: 18 (self-signed)` | 확인됨 (prod 서버) |
| `Verify return code: 10 (expired)` | 확인됨 |
| `Verify return code: 21 (incomplete chain)` | 확인됨 |
| `Public-Key: (1024 bit)` 이하 (RSA) | 확인됨 (`TLS_WEAK_KEY`) |
| `ASN1 OID: prime192v1` 이하 (ECDSA) | 확인됨 (`TLS_WEAK_KEY`) |

## Test 4: Heartbleed (`TLS_HEARTBLEED_VER`, CVE-2014-0160)

```bash
echo | timeout 10 openssl s_client -connect target:443 -tlsextdebug 2>&1 | grep -i "heartbeat"
echo | timeout 10 openssl s_client -connect target:443 2>&1 | grep -i "Server.*OpenSSL"
```

## Test 5: TLS 압축 (`TLS_COMPRESSION`, CRIME)

```bash
echo | timeout 10 openssl s_client -connect target:443 2>&1 | grep "Compression:"
```

| 응답 | 판정 |
|---|---|
| `Compression: zlib` 또는 NONE 외 | 확인됨 |

## Test 6: TLS Renegotiation

```bash
echo "R" | timeout 10 openssl s_client -connect target:443 2>&1 | grep -E "Secure Renegotiation|renegotiation"
```

| 응답 | 판정 |
|---|---|
| `Secure Renegotiation IS NOT supported` | 확인됨 |

## Test 7: SSL Stripping 방어 (HSTS + HTTP→HTTPS)

```bash
# HTTP→HTTPS 리다이렉트
curl -sI -o /dev/null -w "%{http_code} %{redirect_url}" "http://target/" 2>&1

# HSTS 헤더
curl -sI "https://target/" | grep -i '^strict-transport-security:'
```

| 응답 | 판정 |
|---|---|
| HTTP 리다이렉트 없음 + HSTS 없음 | 확인됨 (SSL 스트리핑 완전 노출) |
| HTTP 리다이렉트 + HSTS 없음 | 확인됨 (`HSTS_MISSING` — 리다이렉트만으론 sslstrip 방어 불가) |
| HSTS `max-age` < 31536000 | 확인됨 (`HSTS_SHORT_MAXAGE`) |
| HSTS `max-age` ≥ 31536000 | 안전 |

## TLS 1.3 0-RTT (early data)

```bash
echo | timeout 10 openssl s_client -connect target:443 -tls1_3 2>&1 | grep -i "early"
```

| 응답 | 판정 |
|---|---|
| Early data 활성 | 확인됨 (replay 가능 — 멱등 아닌 POST 위험) |

---

**참고사항:**

- `openssl s_client` 미설치 시 `[도구 한계]` — 설치 시도 금지
- 비표준 포트 (`:8443` 등)는 Phase 1에서 확인된 포트로 테스트
- SNI 요구 환경: `-servername <host>` 옵션 필수
- 로컬 openssl이 `-tls1_3` 미지원 시 해당 Test만 건너뛰고 사유 기재
- 공유 호스팅에서 SNI 누락 시 default certificate 반환 — 다른 사이트 인증서 노출
- OCSP stapling 미활성은 privacy/DoS 영향 — 필수는 아니나 권장
- HSTS `preload` directive는 브라우저 HSTS preload list 포함 요건 — 신규 도메인은 주의
- TLS 1.3 0-RTT (early data) + 멱등 아닌 POST는 replay 가능 — `ssl_early_data on` 설정 주의
- HPKP는 deprecated — 잘못된 pin은 접근 불능 유발
- CRIME/BEAST/POODLE 등 오래된 공격은 TLS 1.0/1.1 비활성화로 해결
- mTLS client cert 요구 환경은 `-cert client.pem -key client.key` 옵션 필요
- Heartbleed는 OpenSSL 1.0.1~1.0.1f 환경만 — 대부분 패치됨
- Managed TLS (AWS ALB, CloudFront, Cloudflare) 환경은 벤더별 지원 프로토콜/cipher 정책 확인
- testssl.sh / sslyze / nmap --script ssl-* 같은 도구로 일괄 점검 가능
- nmap script: `nmap --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed -p 443 target`
