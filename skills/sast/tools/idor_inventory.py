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


def _params_in_signature(sig_text: str, lang: str) -> list[str]:
    """메서드 시그니처 텍스트에서 외부 입력 어노테이션 파라미터 추출.

    반환: ["name(@Anno Type)", ...]
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
    # 클래스 레벨 매핑(prefix). 첫 번째 매칭만 사용(다중 prefix는 첫 prefix로 표시).
    class_prefix = ""
    for i, ln in enumerate(lines[:60]):
        if CONTROLLER_RE.search(ln):
            # 클래스 선언 위쪽 5줄 + 아래 5줄 윈도우에서 클래스레벨 @RequestMapping 검색
            ws = max(0, i - 5)
            we = min(len(lines), i + 5)
            for cl in lines[ws:we]:
                cm = MAPPING_RE.search(cl)
                if cm and cm.group(1) == "Request":
                    class_prefix = cm.group(2).strip().rstrip("/")
                    break
            break

    rows: list[dict] = []
    # 파일을 메서드 단위로 분할: 매핑 어노테이션을 앵커로 사용
    for i, ln in enumerate(lines):
        m = MAPPING_RE.search(ln)
        if not m:
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
        params = _params_in_signature(sig_text, lang)
        if not params:
            continue  # 외부 입력 어노테이션 없는 메서드는 IDOR 인벤토리 대상 아님
        full_path = (class_prefix + ("/" if path_seg and not path_seg.startswith("/") else "") + path_seg) if class_prefix else path_seg
        full_path = full_path or "/"
        verb_norm = verb.upper() if verb != "Request" else "REQUEST"
        rows.append({
            "endpoint": f"{verb_norm} {full_path}".strip(),
            "params": params,
            "file": f"{path.name}:{i + 1}",
            "abspath": str(path),
            "source": "controller-scan",
        })
    return rows


def scan_controllers(project_root: Path) -> list[dict]:
    """프로젝트 루트의 모든 컨트롤러 파일을 source-only로 스캔."""
    rows: list[dict] = []
    for p in project_root.rglob("*"):
        if p.suffix not in (".java", ".kt"):
            continue
        # node_modules / 빌드 산출물 / 테스트 제외
        parts = set(p.parts)
        if any(x in parts for x in ("build", "out", "target", ".gradle", ".idea", "node_modules", "test")):
            continue
        try:
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
# 미지원 프레임워크/미발견 시 auth 컬럼은 '미상'(미상)으로 남고, 판정은 phase1.md 정책이 백스톱.
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
    """진입점이 인증 게이트를 거치는지 표시. 제외 패턴 미수집 시 '미상'(미상)."""
    if not exclude_regexes:
        return "미상"
    return "제외" if any(rx.match(_norm_path(endpoint)) for rx in exclude_regexes) else "적용"


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

    # 인증 게이트 미경유 경로 표시 (project-root 있을 때만; 미발견 시 '미상')
    exclude_regexes: list = []
    if args.project_root:
        exclude_regexes = [_ant_to_regex(p) for p in collect_auth_excluded_patterns(Path(args.project_root))]
    for r in rows:
        r["auth"] = auth_label(r["endpoint"], exclude_regexes)

    # 정렬: 인증 미경유(제외) 먼저 → 출처(taint 먼저) → 엔드포인트
    rows.sort(key=lambda x: (0 if x.get("auth") == "제외" else 1,
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
        "> **인증**: `제외`=인증 인터셉터/시큐리티가 명시적으로 제외한 경로(인증 미경유 — phase1.md '인증 게이트 미경유 진입점은 [미확인]로 종결 금지' 우선 검토 대상), "
        "`적용`=그 외(단정 아님), `미상`=도구가 인증 설정을 못 찾음/미지원 프레임워크. `제외` 행이 표 상단에 정렬된다.",
        ">",
        "> 이 표는 '외부 식별자 수용 엔드포인트 중 안 본 것은 없다'의 백스톱이며 DAST 권한 diff 입력이다.",
        "",
        "| # | 엔드포인트 | 외부입력(파라미터) | 위치 | 출처 | 인증 | 소유권게이트 |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(rows, 1):
        out_lines.append(
            f"| {i} | {r['endpoint']} | {', '.join(r['params']) or '?'} | {r['file']} | "
            f"{r['source']} | {r.get('auth', '미상')} | [미확인] |"
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
