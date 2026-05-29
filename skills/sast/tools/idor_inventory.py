#!/usr/bin/env python3
"""IDOR 검토 인벤토리 기계 생성.

두 가지 소스를 통합한다:

1. **taint 모드** (`--locindex`): idor-scanner의 locindex에서
   'missing-owner-gate-taint' 매치(외부입력→리소스접근 흐름이 dataflow로 확정된 위치)를
   전수 추출한다. semgrep taint 엔진이 처리한 고신뢰 신호.

2. **컨트롤러 스캔 모드** (`--project-root`): 프로젝트의 모든 `.java`/`.kt` 컨트롤러에서
   외부 식별자를 받는 진입점을 source-only로 전수 추출한다. taint flow 추적이
   엔진 한계(람다 클로저·체이닝·DTO 필드 등)로 실패하는 경우의 안전망(FN 방지).
   Spring Web 표준 외부 입력 어노테이션 7종을 source 표지로 사용한다:
     @PathVariable, @RequestParam, @RequestBody, @RequestHeader,
     @CookieValue, @ModelAttribute, @RequestPart.

둘 다 제공 시 합쳐서 dedup하고 출처를 표시한다. 어느 한쪽만 제공해도 동작한다.

에이전트 수기 인벤토리는 컨텍스트 한계로 대량 매치를 누락하므로(실측: 1150건 중 일부만 기록)
기계적 전수 보장이 목적이다. 소유권게이트 컬럼은 '[미확인]'으로 초기화 —
에이전트/사람이 코드 Read로 [검증]/[부재]/[부분]로 채운다. 이 인벤토리는 "외부 식별자를 받아 리소스에
접근하는 엔드포인트 중 안 본 것은 없다"의 백스톱이며 DAST 권한 diff의 입력 목록이 된다.

사용:
  python3 idor_inventory.py --locindex <path> [--out <md>]
  python3 idor_inventory.py --project-root <root> [--out <md>]
  python3 idor_inventory.py --locindex <path> --project-root <root> [--out <md>]

(하위 호환: 첫 번째 positional 인자도 locindex로 받음.)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Spring Web 매핑 어노테이션 (HTTP verb + path)
MAPPING_RE = re.compile(
    r'@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?"([^"]*)"'
)
# 매핑 어노테이션이 path 없이 클래스/메서드 레벨로 붙는 경우(컨트롤러 prefix 처리용).
MAPPING_NOARG_RE = re.compile(r'@(Get|Post|Put|Delete|Patch|Request)Mapping\b')

# 다중 마운트: @RequestMapping("/a","/b") 또는 value={"/a","/b"}에서 경로 리터럴 전수 추출용.
# produces/consumes/method/headers/params/name 등 비경로 명명인자 값은 제외.
_STR_LIT_RE = re.compile(r'"([^"]*)"')
_NON_PATH_ARG_RE = re.compile(r'\b(produces|consumes|method|headers|params|name)\s*=')


def _mapping_path_literals(annotation_line: str) -> list[str]:
    """@*Mapping 어노테이션 라인에서 경로 리터럴 전수 추출(다중 마운트 지원).

    `@RequestMapping("/a", "/b")`, `value = {"/a","/b"}` → ["/a", "/b"].
    value=/path= 외 명명인자(produces 등)의 문자열 값은 경로가 아니므로 잘라낸다.
    """
    paren = annotation_line.find("(")
    arg = annotation_line[paren + 1:] if paren != -1 else annotation_line
    cut = _NON_PATH_ARG_RE.search(arg)
    if cut:
        arg = arg[:cut.start()]
    return [s.strip().rstrip("/") for s in _STR_LIT_RE.findall(arg)]

# Spring Web 외부 입력 어노테이션 7종 — 신뢰 경계.
# 특정 이름(accountId 등) 카탈로그 금지: 어노테이션 자체가 외부 입력의 표지.
# 게이트웨이가 일부 헤더를 덮어쓰는 환경이면 인벤토리 검토 단계에서 안전 분기 처리한다
# ("게이트 호출 존재만으로 [검증] 금지 — 범위 적정성까지 확인").
EXTERNAL_INPUT_ANNOTATIONS = (
    "PathVariable",
    "RequestParam",
    "RequestBody",
    "RequestHeader",
    "CookieValue",
    "ModelAttribute",
    "RequestPart",
)
_ANNO_ALT = "|".join(EXTERNAL_INPUT_ANNOTATIONS)
# Java 파라미터: `@Anno [Anno(...)] [final] Type name [,)]`
PARAM_RE_JAVA = re.compile(
    rf'@({_ANNO_ALT})(?:\([^)]*\))?\s+'
    r'(?:final\s+)?([\w<>,\s\[\]?]+?)\s+(\w+)\s*[,)]'
)
# Kotlin 파라미터: `@Anno [Anno(...)] name: Type[,)]`
PARAM_RE_KOTLIN = re.compile(
    rf'@({_ANNO_ALT})(?:\([^)]*\))?\s+(\w+)\s*:\s*([\w<>,\s\[\]?]+?)\s*[,)]'
)

# 컨트롤러 마커
CONTROLLER_RE = re.compile(r'@(RestController|Controller)\b')
# 메서드 시그니처(Java/Kotlin 공통 휴리스틱) — 시그니처 끝의 `(` 위치 식별용
METHOD_HEAD_RE = re.compile(
    r'(?:public|private|protected|fun|suspend\s+fun|override\s+suspend\s+fun|override\s+fun)\s+'
    r'(?:[\w<>,\s\[\]?]+\s+)?(\w+)\s*\('
)

# 파일 인코딩 fallback
ENCODINGS = ("utf-8", "euc-kr", "cp949", "iso-8859-1")


def read_lines(path: str) -> list[str] | None:
    for enc in ENCODINGS:
        try:
            return Path(path).read_text(encoding=enc).splitlines()
        except (UnicodeDecodeError, OSError):
            continue
    return None


def _is_comment_line(ln: str) -> bool:
    """라우트 매치가 주석 줄에서 나온 경우(가짜 진입점) 판별.

    `#`(Python/Ruby), `//`(Java/Kotlin/JS/Go). 주석 처리된 옛 라우트가 실제
    진입점으로 오탐되는 것을 모든 어댑터에서 공통으로 막는다.
    """
    s = ln.lstrip()
    return s.startswith("#") or s.startswith("//")


# 미어노테이션 암묵 바인딩 파라미터 가시화 시 제외할 프레임워크/원시/표준 타입.
# 이 타입들은 입력 바인딩 대상이 아니거나(Model 등) 식별자 단일값은 1차에서 잡힌다.
_FRAMEWORK_PARAM_TYPES = frozenset({
    "Model", "ModelMap", "BindingResult", "Errors", "Pageable", "Sort", "Principal",
    "Authentication", "HttpServletRequest", "HttpServletResponse", "HttpSession",
    "ServerWebExchange", "ServerHttpRequest", "ServerHttpResponse", "WebRequest",
    "NativeWebRequest", "Locale", "TimeZone", "UriComponentsBuilder", "RedirectAttributes",
    "SessionStatus", "InputStream", "OutputStream", "Writer", "Reader", "MultipartFile",
    "RequestEntity", "HttpEntity", "HttpHeaders", "Device", "Continuation",
    # 원시/래퍼/표준 — 식별자 단일값은 어노테이션으로 이미 잡힘
    "String", "Long", "Integer", "Int", "Boolean", "Double", "Float", "Short", "Byte",
    "Char", "BigDecimal", "BigInteger", "UUID", "LocalDate", "LocalDateTime", "LocalTime",
    "Instant", "List", "Set", "Map", "Collection", "Optional", "Object", "Any", "Unit", "Void",
})


def _param_list_inner(sig_text: str) -> str:
    """시그니처 텍스트에서 첫 최상위 괄호쌍 안쪽(파라미터 목록)만 추출."""
    start = sig_text.find("(")
    if start == -1:
        return ""
    depth = 0
    for i in range(start, len(sig_text)):
        c = sig_text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return sig_text[start + 1:i]
    return sig_text[start + 1:]


def _split_params(inner: str) -> list[str]:
    """파라미터 목록을 최상위 콤마로 분할(제네릭<>·중첩()·배열[]·{} 내부 콤마는 무시)."""
    parts: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in inner:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


_KOTLIN_CMDOBJ_RE = re.compile(r'\b(\w+)\s*:\s*([A-Z]\w*)')
_JAVA_CMDOBJ_RE = re.compile(r'(?:@\w+(?:\([^)]*\))?\s+)*\b([A-Z]\w*)(?:<[^>]*>)?\s+(\w+)\b')


def _params_in_signature(sig_text: str, lang: str) -> list[str]:
    """메서드 시그니처 텍스트에서 외부 입력 파라미터 추출.

    1차: 외부 입력 어노테이션(@RequestParam 등) 보유 파라미터 → "name(@Anno Type)".
    2차: 어노테이션 없이 요청에서 암묵 바인딩되는 복합 타입 → "name(implicit-bind Type)".
         Spring은 미어노테이션 파라미터를 요청에서 바인딩한다(복합타입→커맨드객체,
         enum 등→타입 컨버터). 클라이언트가 채우는 이 값이 신원 식별자로 쓰일 수 있으므로(IDOR),
         에이전트가 타입을 열어 필드를 검토하도록 표지만 남긴다(라우트·라벨 불변, 가산적).
         원시/래퍼/프레임워크 타입은 stoplist로 제외(노이즈 억제).
    """
    out: list[str] = []
    if lang == "kotlin":
        for m in PARAM_RE_KOTLIN.finditer(sig_text):
            anno, name, typ = m.group(1), m.group(2), m.group(3).strip()
            out.append(f"{name}(@{anno} {typ})")
    else:  # java
        for m in PARAM_RE_JAVA.finditer(sig_text):
            anno, typ, name = m.group(1), m.group(2).strip(), m.group(3)
            out.append(f"{name}(@{anno} {typ})")

    # 2차: 어노테이션 없는 커맨드객체(복합 타입) 가시화.
    anno_alt_re = re.compile(rf'@({_ANNO_ALT})\b')
    seen = {p.split("(", 1)[0] for p in out}
    for chunk in _split_params(_param_list_inner(sig_text)):
        if anno_alt_re.search(chunk):
            continue  # 외부입력 어노테이션 보유 → 1차에서 캡처됨
        cm = _KOTLIN_CMDOBJ_RE.search(chunk) if lang == "kotlin" else _JAVA_CMDOBJ_RE.search(chunk)
        if not cm:
            continue
        if lang == "kotlin":
            name, typ = cm.group(1), cm.group(2)
        else:
            typ, name = cm.group(1), cm.group(2)
        if typ in _FRAMEWORK_PARAM_TYPES or name in seen:
            continue
        out.append(f"{name}(implicit-bind {typ})")
        seen.add(name)
    return out


def extract_context(path: str, line_no: int) -> dict:
    """taint 매치 라인에서 위로 스캔하여 가장 가까운 @*Mapping + 메서드 + 파라미터 추출."""
    lines = read_lines(path)
    if not lines or line_no < 1:
        return {"endpoint": "?", "params": []}
    start = max(0, line_no - 40)
    window = lines[start:line_no]
    endpoint = "?"
    http_verb = ""
    params: list[str] = []
    lang = "kotlin" if path.endswith(".kt") else "java"
    for i in range(len(window) - 1, -1, -1):
        ln = window[i]
        m = MAPPING_RE.search(ln)
        if m and endpoint == "?":
            http_verb = m.group(1).upper()
            endpoint = m.group(2).strip() or "/"
            # 시그니처는 매핑 아래 몇 줄. 멀티라인 시그니처를 충분히 캡처.
            sig_text = "\n".join(window[i:min(len(window), i + 16)])
            params = _params_in_signature(sig_text, lang)
            break
    return {"endpoint": f"{http_verb} {endpoint}".strip(), "params": params}


def _scan_controller_file(path: Path) -> list[dict]:
    """단일 컨트롤러 파일에서 외부 식별자 수용 진입점 전수 추출."""
    lines = read_lines(str(path))
    if not lines:
        return []
    text = "\n".join(lines)
    # 컨트롤러 클래스가 아니면 스킵 (@RestController/@Controller 미보유)
    if not CONTROLLER_RE.search(text):
        return []
    lang = "kotlin" if str(path).endswith(".kt") else "java"
    # 클래스 레벨 매핑(prefix). 다중 마운트(@RequestMapping("/a","/b"))는 모든 prefix를 열거한다.
    class_prefixes: list[str] = [""]
    for i, ln in enumerate(lines[:60]):
        if CONTROLLER_RE.search(ln):
            # 클래스 선언 위쪽 5줄 + 아래 5줄 윈도우에서 클래스레벨 @RequestMapping 검색
            ws = max(0, i - 5)
            we = min(len(lines), i + 5)
            for cl in lines[ws:we]:
                # 인자 형식 불문(@RequestMapping("/a","/b") / value={...} / {...} / noarg)
                # 클래스 레벨 @RequestMapping을 인식하고 경로 리터럴을 헬퍼로 추출.
                cm = MAPPING_NOARG_RE.search(cl)
                if cm and cm.group(1) == "Request":
                    lits = _mapping_path_literals(cl)
                    if lits:
                        class_prefixes = lits
                    break
            break

    rows: list[dict] = []
    # 파일을 메서드 단위로 분할: 매핑 어노테이션을 앵커로 사용
    for i, ln in enumerate(lines):
        m = MAPPING_RE.search(ln)
        if not m:
            continue
        if _is_comment_line(ln):  # 주석 처리된 매핑은 가짜 진입점
            continue
        verb = m.group(1)
        path_seg = m.group(2).strip()
        # 클래스 레벨 매핑 제외: 같은 라인 또는 다음 1-2줄에 `class` 선언이 있으면 클래스 레벨.
        cls_window = "\n".join(lines[i:min(len(lines), i + 3)])
        if re.search(r'\bclass\s+\w+', cls_window):
            continue
        # 메서드 시그니처가 매핑 아래 즉시(0~6줄) 와야 함. 클래스 레벨/다른 어노테이션 사이는 스킵.
        method_window = lines[i + 1:min(len(lines), i + 8)]
        sig_start = None
        for j, ml in enumerate(method_window):
            # 시그니처 시작: METHOD_HEAD_RE 매치 또는 다른 매핑 아닌 어노테이션 라인은 건너뛰고 메서드 도달
            if METHOD_HEAD_RE.search(ml):
                sig_start = i + 1 + j
                break
            # 같은 메서드의 다른 어노테이션(@Valid 등)은 통과
            stripped = ml.strip()
            if stripped.startswith("@") or stripped == "":
                continue
            # 다른 토큰이 먼저 나오면 메서드 시그니처 아님
            break
        if sig_start is None:
            continue
        # 시그니처 끝(닫는 ')')까지만 캡처 — 다음 메서드 침범 방지
        sig_lines: list[str] = []
        depth = 0
        started = False
        for sl in lines[sig_start:min(len(lines), sig_start + 30)]:
            sig_lines.append(sl)
            for ch in sl:
                if ch == "(":
                    depth += 1
                    started = True
                elif ch == ")":
                    depth -= 1
                    if started and depth == 0:
                        break
            if started and depth == 0:
                break
        sig_text = "\n".join(sig_lines)
        sig_params = _params_in_signature(sig_text, lang)
        verb_norm = verb.upper() if verb != "Request" else "REQUEST"
        # 다중 마운트: 클래스 레벨 @RequestMapping이 여러 경로를 가지면 마운트별로 행을 생성한다.
        # (인증 제외 라우트가 다른 마운트에 가려져 누락되던 문제 — auth_label이 마운트별로 평가됨)
        for prefix in class_prefixes:
            full_path = (prefix + ("/" if path_seg and not path_seg.startswith("/") else "") + path_seg) if prefix else path_seg
            full_path = full_path or "/"
            params = list(sig_params)
            # 경로변수({var})는 시그니처 어노테이션과 무관하게 외부 식별자 — 라우트에서 직접 추출.
            # (controller-scan은 입력 추출 성패가 아니라 '라우트 전수 열거'가 목적)
            existing = {p.split("(", 1)[0] for p in params}
            for pv in _PATH_VAR_RE.findall(full_path):
                if pv not in existing:
                    params.append(f"{pv}(path-var)")
                    existing.add(pv)
            if not params:
                continue  # 경로변수도 외부 입력도 없으면 IDOR 대상 아님 (예: 식별자 미수용 라우트)
            rows.append({
                "endpoint": f"{verb_norm} {full_path}".strip(),
                "params": params,
                "file": f"{path.name}:{i + 1}",
                "abspath": str(path),
                "source": "controller-scan",
            })
    return rows


# ─── FastAPI 어댑터 (controller-scan 모드의 Python 지원) ──────────────────
# 데코레이터+시그니처 구조라 Spring과 동일한 ①라우트 표지 ②시그니처 입력추출 전략을
# 재사용한다. 호출/본문접근형(Express/Django/Rails/Go)은 입력이 핸들러 '본문'의
# req.params/request.data 접근이라 추출 전략이 달라 미지원 — taint 모드(모드 1)와
# 에이전트 source-first 보완이 백스톱(phase1.md 프레임워크 확장 메타 원칙 참조).
FASTAPI_ROUTE_RE = re.compile(
    r'@(\w+)\.(get|post|put|delete|patch|head|options)\(\s*["\']([^"\']*)["\']'
)
# FastAPI 외부 입력 의존성 함수 (시그니처 기본값으로 사용됨)
FASTAPI_INPUT_FUNCS = ("Path", "Query", "Body", "Header", "Cookie", "Form", "File")
_FA_FUNC_ALT = "|".join(FASTAPI_INPUT_FUNCS)
# `name: Type = Query(...)` 형태의 명시적 외부 입력 파라미터
FASTAPI_PARAM_RE = re.compile(
    r'(\w+)\s*:\s*([\w\[\],. ]+?)\s*=\s*(' + _FA_FUNC_ALT + r')\s*\('
)
_PATH_VAR_RE = re.compile(r'\{(\w+)\}')
# APIRouter(prefix="/x") — 라우터 변수별 경로 prefix (라우트 경로에 합성)
APIROUTER_PREFIX_RE = re.compile(r'(\w+)\s*=\s*APIRouter\([^)]*\bprefix\s*=\s*["\']([^"\']*)["\']')


def _scan_fastapi_file(path: Path) -> list[dict]:
    """단일 FastAPI(.py) 파일에서 외부 식별자 수용 진입점 추출.

    ①라우트 데코레이터로 핸들러 위치 식별 -> ②함수 시그니처에서 외부 입력
    (Path/Query/Body/Header/Cookie/Form/File 의존성 + 경로 변수) 추출.
    Pydantic 본문 모델은 타입만으로 판별이 어려워 보수적으로 제외(오탐 방지);
    본문 모델로 들어오는 식별자는 taint 모드가 커버한다.
    """
    lines = read_lines(str(path))
    if not lines:
        return []
    text = "\n".join(lines)
    # FastAPI 식별: fastapi import + 라우트 데코레이터. @app.get은 Flask도 쓰므로
    # "fastapi" 마커로 Flask 파일과 구분한다(Flask는 _scan_flask_file이 처리).
    if "fastapi" not in text.lower() or not FASTAPI_ROUTE_RE.search(text):
        return []
    prefix_map = dict(APIROUTER_PREFIX_RE.findall(text))  # 라우터 변수 → prefix
    rows: list[dict] = []
    for i, ln in enumerate(lines):
        m = FASTAPI_ROUTE_RE.search(ln)
        if not m:
            continue
        if _is_comment_line(ln):  # 주석 처리된 데코레이터는 가짜 진입점
            continue
        router_var, verb, route_path = m.group(1), m.group(2), m.group(3)
        route_path = prefix_map.get(router_var, "") + route_path  # APIRouter prefix 합성
        # 데코레이터 아래 def/async def 시그니처 찾기 (스택된 데코레이터·빈 줄 통과)
        sig_start = None
        for j in range(i + 1, min(len(lines), i + 8)):
            s = lines[j].strip()
            if s.startswith("def ") or s.startswith("async def "):
                sig_start = j
                break
            if s.startswith("@") or s == "":
                continue
            break
        if sig_start is None:
            continue
        # 시그니처 끝(괄호 깊이 0)까지만 캡처 (멀티라인 대응)
        sig_lines: list[str] = []
        depth = 0
        started = False
        done = False
        for sl in lines[sig_start:min(len(lines), sig_start + 40)]:
            sig_lines.append(sl)
            for ch in sl:
                if ch == "(":
                    depth += 1
                    started = True
                elif ch == ")":
                    depth -= 1
                    if started and depth == 0:
                        done = True
                        break
            if done:
                break
        sig_text = "\n".join(sig_lines)
        params: list[str] = []
        seen: set[str] = set()
        for pm in FASTAPI_PARAM_RE.finditer(sig_text):
            pname, ptype, func = pm.group(1), pm.group(2).strip(), pm.group(3)
            params.append(f"{pname}({func} {ptype})")
            seen.add(pname)
        # 경로 변수({var})는 라우트에 명시된 외부 식별자 — 시그니처/Path() 확인 없이 등재.
        # (입력 추출 성패와 무관하게 라우트를 빠짐없이 열거하는 것이 목적)
        for pv in _PATH_VAR_RE.findall(route_path):
            if pv in seen:
                continue
            params.append(f"{pv}(path-param)")
            seen.add(pv)
        if not params:
            continue
        rows.append({
            "endpoint": f"{verb.upper()} {route_path or '/'}",
            "params": params,
            "file": f"{path.name}:{i + 1}",
            "abspath": str(path),
            "source": "controller-scan",
        })
    return rows


# ─── Express(Node.js) 어댑터 — 본문접근형 (라우트 전수 열거 + 입력 힌트) ──────
# Express는 라우트가 함수 호출(app.get('/x', h))이고 입력이 핸들러 '본문'의
# req.params/req.body 접근이라 시그니처 파싱이 안 통한다. 그래서 ①라우트+경로변수는
# 정확히 열거(완전성)하고 ②본문 입력은 best-effort 힌트로, 외부 핸들러(다른 파일)는
# '입력 미상'으로 등재해 에이전트가 핸들러를 Read하게 한다(taint 갭이 큰 영역).
EXPRESS_ROUTE_RE = re.compile(
    r"""(\w+)\.(get|post|put|delete|patch|all|head|options)\(\s*['"`](/[^'"`]*)['"`]"""
)
EXPRESS_PATH_VAR_RE = re.compile(r":(\w+)")
EXPRESS_INPUT_RE = re.compile(r"\breq(?:uest)?\.(params|query|body|headers|cookies)\b")


def _scan_express_file(path: Path) -> list[dict]:
    """단일 Express(.js/.ts) 파일에서 라우트를 전수 열거 (입력은 best-effort 힌트).

    경로변수(:var)는 라우트에서 정확히 추출(완전성). 인라인 핸들러 본문의 req.* 접근은
    입력 힌트로, 외부 핸들러(app.get('/x', ctrl.show))는 '입력 미상'으로 등재해
    에이전트가 핸들러를 Read하도록 유도한다.
    """
    lines = read_lines(str(path))
    if not lines:
        return []
    text = "\n".join(lines)
    if not EXPRESS_ROUTE_RE.search(text):
        return []
    rows: list[dict] = []
    for i, ln in enumerate(lines):
        m = EXPRESS_ROUTE_RE.search(ln)
        if not m:
            continue
        if _is_comment_line(ln):  # 주석 처리된 라우트는 가짜 진입점
            continue
        verb, route_path = m.group(2), m.group(3)
        params: list[str] = []
        seen: set[str] = set()
        # 경로변수(:var) — 확실한 외부 식별자 (라우트에서 직접 추출)
        for pv in EXPRESS_PATH_VAR_RE.findall(route_path):
            if pv not in seen:
                params.append(f"{pv}(path-var)")
                seen.add(pv)
        # 입력 힌트: 라우트 줄부터 다음 라우트 등록 전까지(최대 25줄) 본문 req.* 토큰
        end = min(len(lines), i + 25)
        for k in range(i + 1, end):
            if EXPRESS_ROUTE_RE.search(lines[k]):
                end = k
                break
        window = "\n".join(lines[i:end])
        for hit in sorted(set(EXPRESS_INPUT_RE.findall(window))):
            params.append(f"req.{hit}(input-hint)")
        # 인라인 핸들러 여부(라우트 호출 뒤에 화살표/function)
        rest = ln[m.end():]
        inline = ("=>" in rest) or ("function" in rest)
        if not params:
            if inline:
                continue  # 인라인인데 경로변수·입력 토큰 0 → 식별자 미수용(예: /health)
            params.append("<입력 미상 - 핸들러 Read>")  # 외부 핸들러 → 완전성 우선 등재
        rows.append({
            "endpoint": f"{verb.upper()} {route_path}",
            "params": params,
            "file": f"{path.name}:{i + 1}",
            "abspath": str(path),
            "source": "controller-scan",
        })
    return rows


# ─── Django 어댑터 — urls.py 라우트 열거 (핸들러는 views.py 분리라 입력 미상) ──
# Django는 라우트(urls.py)와 핸들러(views.py)가 분리되어 urls.py만으로는 입력을
# 알 수 없다(=항상 '외부 핸들러' 패턴). 그래서 라우트+경로변수만 전수 열거하고(완전성),
# 입력은 '미상'으로 등재해 에이전트가 view를 Read하게 한다. HTTP 메서드는 뷰가
# 결정하므로 ANY. DRF router(router.register)·CBV 자동 메서드는 미지원(taint+에이전트 백스톱).
DJANGO_ROUTE_RE = re.compile(r"""(?:\bpath|\bre_path|\burl)\(\s*r?['"]([^'"]*)['"]""")
DJANGO_PATH_VAR_RE = re.compile(r"<(?:\w+:)?(\w+)>")   # path('users/<int:id>/')
DJANGO_RE_VAR_RE = re.compile(r"\(\?P<(\w+)>")         # re_path(r'^users/(?P<id>\d+)/$')


def _scan_django_urls_file(path: Path) -> list[dict]:
    """Django urls.py에서 라우트를 전수 열거 (입력은 view에 있어 미상).

    path()/re_path()/url() 호출의 경로 + 경로변수(<int:id> / (?P<id>...))를 추출한다.
    include()는 sub-urls 마운트라 제외(해당 sub urls.py가 따로 스캔됨). 핸들러가
    views.py에 분리되어 입력은 '미상'으로 표시; HTTP 메서드는 뷰가 결정하므로 ANY.
    """
    lines = read_lines(str(path))
    if not lines:
        return []
    text = "\n".join(lines)
    # Django URLconf는 반드시 `urlpatterns = [...]` 할당을 가짐 — 이를 필수 마커로 사용.
    # 단순히 "urlpatterns" 단어 포함이나 path() 호출로 판별하면 일반 .py(주석/문자열에
    # urlpatterns를 언급하거나 소문자 path()를 호출하는 코드)를 오탐하므로 할당식으로 좁힌다.
    if not re.search(r"\burlpatterns\s*=", text):
        return []
    rows: list[dict] = []
    for i, ln in enumerate(lines):
        m = DJANGO_ROUTE_RE.search(ln)
        if not m:
            continue
        if _is_comment_line(ln):  # 주석 처리된 라우트는 가짜 진입점
            continue
        route = m.group(1).strip().lstrip("^").rstrip("$").strip("/")
        if "include(" in ln[m.end():]:  # sub-urls 마운트 → 라우트 아님
            continue
        params: list[str] = []
        seen: set[str] = set()
        for pv in DJANGO_PATH_VAR_RE.findall(route) + DJANGO_RE_VAR_RE.findall(route):
            if pv not in seen:
                params.append(f"{pv}(path-var)")
                seen.add(pv)
        if not params:
            params.append("<입력 미상 - view Read>")  # 핸들러가 views.py → 입력 미상
        rows.append({
            "endpoint": f"ANY /{route}",
            "params": params,
            "file": f"{path.name}:{i + 1}",
            "abspath": str(path),
            "source": "controller-scan",
        })
    return rows


# 빌드 산출물·서드파티·테스트 디렉토리 제외 (Java/Kotlin + Python + Node 공통)
# "test"(Java src/test 관례)·"tests"(Python 관례) 둘 다 제외 — 테스트 픽스처가
# 실제 진입점으로 오탐되는 것을 방지. dist/coverage는 Node 빌드 산출물.
_SCAN_EXCLUDE_DIRS = (
    "build", "out", "target", ".gradle", ".idea", "node_modules", "test", "tests",
    "venv", ".venv", "site-packages", "__pycache__", "dist", "coverage",
)

# ─── Flask 어댑터 — 하이브리드 (데코레이터 라우트 + 본문접근 입력) ──────────
# Flask는 라우트가 데코레이터(@app.route/@app.get)지만 입력은 핸들러 본문의
# request.args/form/json 접근이라 FastAPI(시그니처)와 Express(본문)의 혼합이다.
# 라우트+경로변수(<int:id>, Django와 같은 형식)는 정확히 열거하고, 입력은 본문
# request.* 토큰을 best-effort 힌트로 단다. 핸들러가 데코레이터 바로 아래 함수라
# 본문을 볼 수 있어 Express의 '외부 핸들러 미상'은 없다. (@app.get 충돌은 'flask' 마커로 구분)
FLASK_ROUTE_RE = re.compile(r"""@(\w+)\.(route|get|post|put|delete|patch)\(\s*['"](/[^'"]*)['"]""")
FLASK_METHODS_RE = re.compile(r"methods\s*=\s*\[([^\]]*)\]")
# Blueprint(url_prefix="/x") — 블루프린트 변수별 경로 prefix (라우트 경로에 합성)
BLUEPRINT_PREFIX_RE = re.compile(r"""(\w+)\s*=\s*Blueprint\([^)]*\burl_prefix\s*=\s*['"]([^'"]*)['"]""")
FLASK_INPUT_RE = re.compile(r"\brequest\.(args|form|json|values|data|cookies|headers)\b")


def _scan_flask_file(path: Path) -> list[dict]:
    """단일 Flask(.py) 파일에서 라우트를 전수 열거 (입력은 본문 request.* 힌트).

    @app.route/@app.get 데코레이터의 경로 + 경로변수(<int:id>)는 정확히 추출하고,
    HTTP 메서드는 route는 methods=[...]에서(없으면 GET), get/post 데코레이터는
    그 메서드로 잡는다. 입력은 핸들러 본문의 request.* 토큰을 best-effort 힌트로 단다.
    """
    lines = read_lines(str(path))
    if not lines:
        return []
    text = "\n".join(lines)
    # Flask 식별: flask import + 라우트 데코레이터 (FastAPI의 @app.get과 구분)
    if "flask" not in text.lower() or not FLASK_ROUTE_RE.search(text):
        return []
    prefix_map = dict(BLUEPRINT_PREFIX_RE.findall(text))  # Blueprint 변수 → url_prefix
    rows: list[dict] = []
    for i, ln in enumerate(lines):
        m = FLASK_ROUTE_RE.search(ln)
        if not m:
            continue
        if _is_comment_line(ln):  # 주석 처리된 데코레이터는 가짜 진입점
            continue
        bp_var, deco, route_path = m.group(1), m.group(2), m.group(3)
        route_path = prefix_map.get(bp_var, "") + route_path  # Blueprint url_prefix 합성
        if deco == "route":
            mm = FLASK_METHODS_RE.search(ln)
            if mm:
                methods = [x.strip().strip("'\"").upper() for x in mm.group(1).split(",") if x.strip()]
                verb = "/".join(methods) if methods else "GET"
            else:
                verb = "GET"
        else:
            verb = deco.upper()
        params: list[str] = []
        seen: set[str] = set()
        # 경로변수 <int:id> — Django와 같은 형식 (DJANGO_PATH_VAR_RE 재사용)
        for pv in DJANGO_PATH_VAR_RE.findall(route_path):
            if pv not in seen:
                params.append(f"{pv}(path-var)")
                seen.add(pv)
        # 입력 힌트 윈도: 다음 라우트 데코레이터 또는 다음 함수 def 전까지 (인접 핸들러 토큰 흡수 방지)
        end = min(len(lines), i + 25)
        for k in range(i + 1, end):
            if FLASK_ROUTE_RE.search(lines[k]) or (k > i + 1 and lines[k].lstrip().startswith(("def ", "async def "))):
                end = k
                break
        window = "\n".join(lines[i:end])
        for hit in sorted(set(FLASK_INPUT_RE.findall(window))):
            params.append(f"request.{hit}(input-hint)")
        if not params:
            continue  # 경로변수·입력 0 → 식별자 미수용 (핸들러 본문이 바로 아래라 미상 불필요)
        rows.append({
            "endpoint": f"{verb} {route_path}",
            "params": params,
            "file": f"{path.name}:{i + 1}",
            "abspath": str(path),
            "source": "controller-scan",
        })
    return rows


# ─── Rails 어댑터 — config/routes.rb DSL (핸들러는 app/controllers 분리라 입력 미상) ──
# Rails는 라우트(routes.rb DSL)와 핸들러(컨트롤러)가 분리된다(Django와 유사). get/post/
# put/patch/delete/match DSL의 경로 + 경로변수(:id, Express 형식)를 열거하고, 핸들러
# (to: 'ctrl#action')가 app/controllers에 분리되어 입력은 '미상'으로 등재한다.
# resources(RESTful 자동)는 표준 7액션으로 전개(only:/except: 존중). 블록 라우트·
# single resource·nested resources는 미지원(taint+에이전트 백스톱).
# routes.draw를 필수 마커로 사용(일반 .rb의 get/post 메서드 호출 오탐 방지).
RAILS_ROUTE_RE = re.compile(r"""\b(get|post|put|patch|delete|match)\s+['"]([^'"]+)['"]""")
RAILS_RESOURCES_RE = re.compile(r"\bresources\s+:(\w+)(.*)")
# RESTful 표준 액션 → (HTTP verb, 경로 suffix). :id 받는 액션(show/edit/update/destroy)이 IDOR 핵심.
_RESTFUL_ACTIONS = {
    "index": ("GET", ""),
    "create": ("POST", ""),
    "new": ("GET", "/new"),
    "show": ("GET", "/:id"),
    "edit": ("GET", "/:id/edit"),
    "update": ("PATCH", "/:id"),
    "destroy": ("DELETE", "/:id"),
}


def _scan_rails_routes_file(path: Path) -> list[dict]:
    """Rails config/routes.rb에서 라우트를 전수 열거 (입력은 컨트롤러에 있어 미상).

    get/post/put/patch/delete/match DSL의 경로 + 경로변수(:id)를 추출한다. 핸들러가
    app/controllers에 분리되어 경로변수가 없으면 '입력 미상'으로 등재; routes.draw를
    필수 마커로 사용한다. resources는 RESTful 표준 액션으로 전개(only:/except: 존중);
    블록 라우트·single resource·nested resources는 미지원.
    """
    lines = read_lines(str(path))
    if not lines:
        return []
    text = "\n".join(lines)
    if "routes.draw" not in text:  # Rails 라우트 DSL 마커
        return []
    rows: list[dict] = []
    for i, ln in enumerate(lines):
        if _is_comment_line(ln):  # 주석 처리된 라우트는 가짜 진입점
            continue
        # resources :name → RESTful 표준 액션 전개 (only:/except: 존중)
        rm = RAILS_RESOURCES_RE.search(ln)
        if rm:
            name, opts = rm.group(1), rm.group(2)
            actions = set(_RESTFUL_ACTIONS)
            only = re.search(r"only:\s*\[([^\]]*)\]", opts)
            exc = re.search(r"except:\s*\[([^\]]*)\]", opts)
            if only:
                actions = {a.strip().lstrip(":") for a in only.group(1).split(",") if a.strip()}
            elif exc:
                actions -= {a.strip().lstrip(":") for a in exc.group(1).split(",") if a.strip()}
            for action in sorted(actions):
                if action not in _RESTFUL_ACTIONS:
                    continue
                verb, suffix = _RESTFUL_ACTIONS[action]
                params = ["id(path-var)"] if ":id" in suffix else ["<입력 미상 - controller Read>"]
                rows.append({
                    "endpoint": f"{verb} /{name}{suffix}",
                    "params": params,
                    "file": f"{path.name}:{i + 1}",
                    "abspath": str(path),
                    "source": "controller-scan",
                })
            continue
        m = RAILS_ROUTE_RE.search(ln)
        if not m:
            continue
        verb, route = m.group(1), m.group(2)
        params: list[str] = []
        seen: set[str] = set()
        for pv in EXPRESS_PATH_VAR_RE.findall(route):  # :id (Express와 같은 형식)
            if pv not in seen:
                params.append(f"{pv}(path-var)")
                seen.add(pv)
        if not params:
            params.append("<입력 미상 - controller Read>")  # 핸들러가 app/controllers 분리
        rows.append({
            "endpoint": f"{verb.upper()} /{route.lstrip('/')}",
            "params": params,
            "file": f"{path.name}:{i + 1}",
            "abspath": str(path),
            "source": "controller-scan",
        })
    return rows


# ─── Go 어댑터 — 본문접근형 (Gin/Echo/chi/net-http: 라우트 전수 열거 + 입력 힌트) ──
# Go는 라우트가 함수 호출(r.GET("/x", h))이고 입력이 핸들러 본문의 c.Param/c.Query
# 접근이라 Express와 유사하다. 라우트+경로변수(:id Gin/Echo, {id} chi/gorilla)는 정확히
# 열거하고, 입력은 본문 c.Param/c.Query/mux.Vars 토큰을 best-effort 힌트로, 외부 핸들러는
# '입력 미상'으로 등재한다. HandleFunc(net/http)는 메서드 미지정이라 ANY로 표기.
GO_ROUTE_RE = re.compile(
    r'\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Get|Post|Put|Delete|Patch|Handle|HandleFunc)\(\s*"((?:[A-Z]+ )?/[^"]*)"'
)
GO_INPUT_RE = re.compile(
    r'\bc\.(?:Param|Query|DefaultQuery|PostForm|GetHeader|Cookie)\b|\bmux\.Vars\b|\br\.(?:FormValue|PostFormValue)\b'
)


def _scan_go_file(path: Path) -> list[dict]:
    """단일 Go(.go) 파일에서 라우트를 전수 열거 (입력은 best-effort 힌트).

    Gin/Echo `.GET(...)`·chi `.Get(...)`·net-http `.HandleFunc(...)` 호출의 경로 +
    경로변수(:id / {id})를 정확히 추출하고, 입력은 본문 c.Param/c.Query/mux.Vars 토큰을
    힌트로 단다. 외부 핸들러는 '입력 미상'으로 등재. HandleFunc는 메서드 미지정 → ANY.
    """
    lines = read_lines(str(path))
    if not lines:
        return []
    text = "\n".join(lines)
    if not GO_ROUTE_RE.search(text):
        return []
    rows: list[dict] = []
    for i, ln in enumerate(lines):
        m = GO_ROUTE_RE.search(ln)
        if not m:
            continue
        if _is_comment_line(ln):  # 주석 처리된 라우트는 가짜 진입점
            continue
        method, raw = m.group(1), m.group(2)
        mp = re.match(r"([A-Z]+)\s+(/.*)", raw)  # Go 1.22 "GET /users/{id}" (메서드+패턴 라우팅)
        if mp:
            verb, route = mp.group(1), mp.group(2)
        elif method in ("Handle", "HandleFunc"):
            verb, route = "ANY", raw
        else:
            verb, route = method.upper(), raw
        params: list[str] = []
        seen: set[str] = set()
        # 경로변수 :id(Gin/Echo) 와 {id}(chi/gorilla) 둘 다
        for pv in EXPRESS_PATH_VAR_RE.findall(route) + _PATH_VAR_RE.findall(route):
            if pv not in seen:
                params.append(f"{pv}(path-var)")
                seen.add(pv)
        # 입력 힌트: 본문(다음 라우트 등록 전까지, 최대 25줄) c.Param/c.Query/mux.Vars 토큰
        end = min(len(lines), i + 25)
        for k in range(i + 1, end):
            if GO_ROUTE_RE.search(lines[k]):
                end = k
                break
        window = "\n".join(lines[i:end])
        for hit in sorted(set(mm.group(0) for mm in GO_INPUT_RE.finditer(window))):
            params.append(f"{hit}(input-hint)")
        # 인라인 핸들러 여부 (라우트 호출 뒤 func(...))
        rest = ln[m.end():]
        inline = "func(" in rest or "func (" in rest
        if not params:
            if inline:
                continue  # 인라인인데 경로변수·입력 토큰 0 → 식별자 미수용
            params.append("<입력 미상 - 핸들러 Read>")  # 외부 핸들러 → 완전성 우선 등재
        rows.append({
            "endpoint": f"{verb} {route}",
            "params": params,
            "file": f"{path.name}:{i + 1}",
            "abspath": str(path),
            "source": "controller-scan",
        })
    return rows


# 스캐너 도구 자신(이 스킬)의 디렉토리. project_root 안에 스킬이 복사돼 있어도
# 도구 코드(주석/문자열의 라우트 예시 등)가 분석 대상으로 오탐되지 않도록 제외한다.
# 일반 환경(스킬이 project_root 밖)에서는 매칭되지 않아 무영향.
_SKILL_ROOT = Path(__file__).resolve().parents[1]


def scan_controllers(project_root: Path) -> list[dict]:
    """프로젝트 루트의 컨트롤러 파일을 source-only로 스캔 (Spring Java/Kotlin + FastAPI Python + Express Node)."""
    rows: list[dict] = []
    for p in project_root.rglob("*"):
        if p.suffix not in (".java", ".kt", ".py", ".js", ".ts", ".mjs", ".cjs", ".rb", ".go"):
            continue
        parts = set(p.parts)
        if any(x in parts for x in _SCAN_EXCLUDE_DIRS):
            continue
        if _SKILL_ROOT in p.resolve().parents:  # 스캐너 도구 자신(스킬) 제외 — 자기참조 오탐 방지
            continue
        try:
            if p.suffix == ".py":
                # .py는 FastAPI·Flask·Django 모두 시도 — 각자 프레임워크 마커로 스킵
                rows.extend(_scan_fastapi_file(p))
                rows.extend(_scan_flask_file(p))
                rows.extend(_scan_django_urls_file(p))
            elif p.suffix in (".js", ".ts", ".mjs", ".cjs"):
                rows.extend(_scan_express_file(p))
            elif p.suffix == ".rb":
                rows.extend(_scan_rails_routes_file(p))
            elif p.suffix == ".go":
                rows.extend(_scan_go_file(p))
            else:
                rows.extend(_scan_controller_file(p))
        except Exception:
            continue
    return rows


def collect_taint_rows(locindex_path: Path) -> tuple[list[dict], dict]:
    try:
        d = json.loads(locindex_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"ERROR: locindex 읽기 실패: {e}", file=sys.stderr)
        return [], {}
    locations = d.get("locations", {})
    sc = d.get("_scanner", {})
    taint_locs = {
        loc: meta for loc, meta in locations.items()
        if meta.get("tier") == "taint" or any("taint" in r for r in meta.get("rule_ids", []))
    }
    rows: list[dict] = []
    for loc in sorted(taint_locs):
        path, _, line_s = loc.rpartition(":")
        try:
            line_no = int(line_s)
        except ValueError:
            continue
        ctx = extract_context(path, line_no)
        rows.append({
            "endpoint": ctx["endpoint"],
            "params": ctx["params"] or [],
            "file": f"{Path(path).name}:{line_no}",
            "abspath": path,
            "source": "taint",
        })
    return rows, {"taint_count": len(taint_locs), "scanner_meta": sc}


# ─── 인증 게이트 미경유 경로 탐지 (auth 컬럼) ───────────────────────────
# 인증 인터셉터/시큐리티가 인증 대상에서 제외한 경로 패턴을 수집해, 각 진입점이
# 인증 게이트를 거치지 않는지(=phase1.md "[미확인] 종결 금지" 우선 대상) 표시한다.
# 어댑터 방식: 현재 Spring 인터셉터 `excludePathPatterns(...)`만 지원.
# 미지원 프레임워크/미발견 시 auth 컬럼은 '[미상]'으로 남고, 판정은 phase1.md 정책이 백스톱.
_EXCLUDE_BLOCK_RE = re.compile(r"excludePathPatterns\s*\((.*?)\)", re.S)
_STRING_LIT_RE = re.compile(r'"([^"]*)"')


def collect_auth_excluded_patterns(root: Path) -> list[str]:
    """프로젝트 전체에서 인증 인터셉터가 제외한 경로 패턴 리터럴을 수집."""
    pats: set[str] = set()
    for ext in ("*.java", "*.kt"):
        for f in root.rglob(ext):
            sp = str(f)
            if "/build/" in sp or "/.gradle/" in sp:
                continue
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "excludePathPatterns" not in txt:
                continue
            for block in _EXCLUDE_BLOCK_RE.findall(txt):
                pats.update(_STRING_LIT_RE.findall(block))
    return sorted(pats)


def _ant_to_regex(pat: str) -> "re.Pattern[str]":
    """Spring Ant 경로 패턴 → 정규식. `**`=임의(슬래시 포함), `*`=세그먼트 내, `{var}`=단일 세그먼트."""
    pat = re.sub(r"\{[^}]+\}", "*", pat)
    esc = re.escape(pat)
    esc = esc.replace(r"\*\*", "\x00").replace(r"\*", "[^/]*").replace("\x00", ".*")
    return re.compile("^" + esc + r"/?$")


def _norm_path(endpoint: str) -> str:
    """'GET /a/b' → '/a/b' (verb 제거, 선행 슬래시 보정)."""
    parts = endpoint.split(None, 1)
    p = parts[1] if len(parts) == 2 else endpoint
    return p if p.startswith("/") else "/" + p


def auth_label(endpoint: str, exclude_regexes: list) -> str:
    """진입점이 인증 게이트를 거치는지 표시. 제외 패턴 미수집 시 '[미상]'."""
    if not exclude_regexes:
        return "[미상]"
    return "[제외]" if any(rx.match(_norm_path(endpoint)) for rx in exclude_regexes) else "[적용]"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("locindex_positional", nargs="?", help="(deprecated) locindex 경로 — --locindex 사용 권장")
    ap.add_argument("--locindex", default=None, help="idor-scanner.locindex.json 경로 (taint 모드)")
    ap.add_argument("--project-root", default=None, help="프로젝트 루트 (컨트롤러 source-only 스캔 모드)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    locindex = args.locindex or args.locindex_positional
    if not locindex and not args.project_root:
        print("ERROR: --locindex 또는 --project-root 중 하나는 필수.", file=sys.stderr)
        return 1

    taint_rows: list[dict] = []
    taint_meta: dict = {}
    if locindex:
        taint_rows, taint_meta = collect_taint_rows(Path(locindex))

    scan_rows: list[dict] = []
    if args.project_root:
        scan_rows = scan_controllers(Path(args.project_root))

    # dedup: (endpoint, params) 키로. taint 우선(고신뢰), scan 보완.
    by_key: dict[tuple, dict] = {}
    for r in taint_rows + scan_rows:
        key = (r["endpoint"], tuple(r["params"]))
        if key in by_key:
            # 이미 taint로 들어왔으면 유지. scan은 보완(source 합산).
            existing = by_key[key]
            if existing["source"] != r["source"]:
                existing["source"] = "taint+scan"
        else:
            by_key[key] = dict(r)
    rows = list(by_key.values())

    # 인증 게이트 미경유 경로 표시 (project-root 있을 때만; 미발견 시 '[미상]')
    exclude_regexes: list = []
    if args.project_root:
        exclude_regexes = [_ant_to_regex(p) for p in collect_auth_excluded_patterns(Path(args.project_root))]
    for r in rows:
        r["auth"] = auth_label(r["endpoint"], exclude_regexes)

    # 정렬: 인증 미경유(제외) 먼저 → 출처(taint 먼저) → 엔드포인트
    rows.sort(key=lambda x: (0 if x.get("auth") == "[제외]" else 1,
                             0 if "taint" in x["source"] else 1,
                             x["endpoint"]))

    # MD 출력
    sc = taint_meta.get("scanner_meta", {})
    header = "### IDOR 검토 인벤토리 (기계 생성)"
    summary_parts = []
    if locindex:
        summary_parts.append(
            f"taint 매치 {taint_meta.get('taint_count', 0)}건"
            f"(has_taint={sc.get('has_taint')}, tier_counts={sc.get('tier_counts')})"
        )
    if args.project_root:
        summary_parts.append(f"컨트롤러 source-only 스캔 {len(scan_rows)}건")
    summary_parts.append(f"→ dedup 후 {len(rows)} 엔드포인트")

    out_lines = [
        header,
        "",
        " | ".join(summary_parts) + ".",
        "",
        "> **소유권게이트 컬럼은 `[미확인]`으로 초기화됨.** 에이전트/사람이 각 엔드포인트의 "
        "service·AOP 계층을 Read하여 다음 형식으로 채운다:",
        "> - `[검증] <service>.<method>():<line>` (완전 검증 — 호출된 게이트 함수의 파일·라인 인용 필수)",
        "> - `[부재]` (게이트 없음 — service Read 후 명시)",
        "> - `[부분]: <이유>` (부분 게이트·우회 가능 — 우회 경로 명시)",
        ">",
        "> **금지**: 게이트 함수가 같은 컨트롤러/모듈에 있다고 추정해 다른 항목의 게이트를 복사 붙여넣지 말 것. "
        "각 항목은 해당 service를 직접 Read해 채워야 한다. **게이트 호출 존재만으로 [검증] 금지 — 범위 적정성까지 확인**(phase1.md).",
        ">",
        "> **출처**: `taint`=dataflow 확정(고신뢰), `controller-scan`=source-only 진입점(taint flow 추적 실패 안전망, "
        "DTO/람다/체이닝 우회분 포함), `taint+scan`=양쪽 모두.",
        ">",
        "> **인증**: `[제외]`=인증 인터셉터/시큐리티가 명시적으로 제외한 경로(인증 미경유 — phase1.md '인증 게이트 미경유 진입점은 [미확인]로 종결 금지' 우선 검토 대상), "
        "`[적용]`=그 외(단정 아님), `[미상]`=도구가 인증 설정을 못 찾음/미지원 프레임워크. `[제외]` 행이 표 상단에 정렬된다.",
        ">",
        "> 이 표는 '외부 식별자 수용 엔드포인트 중 안 본 것은 없다'의 백스톱이며 DAST 권한 diff 입력이다.",
        "",
        "| # | 엔드포인트 | 외부입력(파라미터) | 위치 | 출처 | 인증 | 소유권게이트 |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(rows, 1):
        out_lines.append(
            f"| {i} | {r['endpoint']} | {', '.join(r['params']) or '?'} | {r['file']} | "
            f"{r['source']} | {r.get('auth', '[미상]')} | [미확인] |"
        )
    out_lines.append("")
    md = "\n".join(out_lines)

    if args.out:
        Path(args.out).write_text(md + "\n", encoding="utf-8")
        print(f"인벤토리 저장: {args.out} ({len(rows)} 엔드포인트; "
              f"taint={len(taint_rows)}, scan={len(scan_rows)})")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
