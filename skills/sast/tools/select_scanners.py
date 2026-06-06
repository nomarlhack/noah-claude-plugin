#!/usr/bin/env python3
"""select_scanners.py — 패턴 인덱스 + 프로젝트 파일 기반 49개 스캐너 자동 선별.

Usage:
    python3 select_scanners.py <PATTERN_INDEX_DIR> <PROJECT_ROOT> \
      [--write-expected-file=PATH] [--phase1-dir=PHASE1_RESULTS_DIR]

Options:
    --write-expected-file=PATH  적용 스캐너 목록을 JSON 파일로 저장 (phase1_build_master_list.py가 읽음)
    --phase1-dir=PATH           PHASE1_RESULTS_DIR 명시. 본 옵션이 주어지면 auth-boundary.json
                                lint sentinel을 검증한 후에만 진행한다 (Step 4 입력 의존성 강제).
                                미명시 시 lint 게이트 비활성 — 신규 호출은 항상 본 옵션 전달 권고.

Output:
    - 적용/제외 판정 테이블 (매치 히트 건수 + 사유 포함)
    - 적용 스캐너 목록
    - 그룹 편성
"""
import json, os, re, sys, glob
from pathlib import Path

if len(sys.argv) < 3:
    print("Usage: python3 select_scanners.py <PATTERN_INDEX_DIR> <PROJECT_ROOT>")
    sys.exit(1)

INDEX_DIR = sys.argv[1]
PROJECT_ROOT = sys.argv[2]

# === [v11 강제 게이트] auth-boundary.json sentinel 검증 ===
# --phase1-dir 옵션이 주어지면 lint sentinel 검증 후에만 진행.
# select_scanners는 Step 4 진입점이므로 본 게이트가 메인 에이전트의 lint 우회를 차단한다.
# (--write-expected-file 인자의 부모 디렉터리에서 PHASE1_RESULTS_DIR 자동 추출도 fallback으로 지원.)
_phase1_dir_arg: str | None = None
for _arg in sys.argv[3:]:
    if _arg.startswith("--phase1-dir="):
        _phase1_dir_arg = _arg.split("=", 1)[1]
        break
if _phase1_dir_arg is None:
    for _arg in sys.argv[3:]:
        if _arg.startswith("--write-expected-file="):
            _phase1_dir_arg = str(Path(_arg.split("=", 1)[1]).parent)
            break

if _phase1_dir_arg:
    _phase1_dir = Path(_phase1_dir_arg)
    _TOOLS_DIR = Path(__file__).resolve().parent
    if str(_TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(_TOOLS_DIR))
    try:
        from _validate_auth_boundary import check_sentinel as _check_auth_sentinel
        _AUTH_BOUNDARY_PATH = _phase1_dir / "auth-boundary.json"
        _AUTH_SENTINEL_PATH = _phase1_dir / "auth-boundary.lint-passed"
        _ok, _msg = _check_auth_sentinel(_AUTH_BOUNDARY_PATH, _AUTH_SENTINEL_PATH)
        if not _ok:
            print(
                f"ERROR: auth-boundary.json lint sentinel 검증 실패 — {_msg}\n"
                f"  → Step 3-1 절차 (SKILL.md)를 재수행하고 다음을 실행하라:\n"
                f"    python3 {_TOOLS_DIR}/lint_auth_boundary.py {_AUTH_BOUNDARY_PATH}\n"
                f"  → lint PASS 후 sentinel({_AUTH_SENTINEL_PATH})이 발급되어야 Step 4 진입 가능",
                file=sys.stderr,
            )
            sys.exit(1)
    except ImportError:
        print(
            "WARNING: _validate_auth_boundary 모듈을 import할 수 없음. "
            "lint 강제 게이트 비활성 — SAST 스킬 설치 상태 점검 필요.",
            file=sys.stderr,
        )

# --- Helper: 프로젝트 파일 존재 여부 ---
def has_file(*patterns):
    for p in patterns:
        if glob.glob(os.path.join(PROJECT_ROOT, p)) or glob.glob(os.path.join(PROJECT_ROOT, "**", p), recursive=True):
            return True
    return False

def read_pkg_json():
    pkg_path = os.path.join(PROJECT_ROOT, "package.json")
    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"WARNING: package.json 파싱 실패 ({e}), 건너뜁니다", file=sys.stderr)
    return {}

def has_dependency(pkg, *names):
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    return any(n in deps for n in names)

# --- 패턴 인덱스 읽기 ---
def read_index(scanner_name):
    path = os.path.join(INDEX_DIR, f"{scanner_name}.json")
    if not os.path.exists(path):
        return {}, 0
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"WARNING: {scanner_name}.json 파싱 실패 ({e}), 건너뜁니다", file=sys.stderr)
        return {}, 0
    total = sum(len(v) for v in data.values())
    return data, total

# --- 스캐너 제외 조건 (매치 0건일 때만 적용) ---
SCANNERS = [
    "xss-scanner", "dom-xss-scanner", "ssrf-scanner", "open-redirect-scanner",
    "crlf-injection-scanner", "csrf-scanner", "path-traversal-scanner",
    "file-upload-scanner", "command-injection-scanner", "code-injection-scanner", "sqli-scanner",
    "http-method-tampering-scanner", "xxe-scanner", "deserialization-scanner",
    "ssti-scanner", "jwt-scanner", "oauth-scanner", "nosqli-scanner",
    "ldap-injection-scanner", "host-header-scanner", "xslt-injection-scanner",
    "css-injection-scanner", "xpath-injection-scanner", "soapaction-spoofing-scanner",
    "redos-scanner", "pdf-generation-scanner", "saml-scanner",
    "http-smuggling-scanner", "zipslip-scanner", "graphql-scanner",
    "sourcemap-scanner", "csv-injection-scanner", "prototype-pollution-scanner",
    "websocket-scanner", "subdomain-takeover-scanner", "idor-scanner",
    "business-logic-scanner", "security-headers-scanner",
    "springboot-hardening-scanner", "cookie-security-scanner",
    "tls-scanner", "validation-logic-scanner",
    "prompt-injection-scanner", "system-prompt-leakage-scanner",
    "insecure-output-handling-scanner", "unbounded-consumption-scanner",
    "android-deeplink-scanner", "android-webview-scanner",
    "android-ipc-scanner", "android-manifest-scanner",
    "android-accountmanager-scanner",
    "hardcoded-secrets-scanner", "log-injection-scanner",
    "ios-webview-scanner", "ios-storage-scanner", "ios-crypto-scanner",
]

pkg = read_pkg_json()
has_requirements = has_file("requirements.txt", "Pipfile", "pyproject.toml")
has_gemfile = has_file("Gemfile")
has_pom = has_file("pom.xml", "build.gradle")
has_ios = has_file("*.xcodeproj", "*.xcworkspace", "Podfile", "Package.swift", "Info.plist")

# --- Python 의존성 파싱 ---
def read_python_deps():
    """requirements.txt, Pipfile, pyproject.toml에서 패키지명 추출."""
    deps = set()
    # requirements.txt (+ requirements/*.txt)
    req_files = glob.glob(os.path.join(PROJECT_ROOT, "requirements*.txt"))
    req_files += glob.glob(os.path.join(PROJECT_ROOT, "requirements", "*.txt"))
    for rf in req_files:
        try:
            with open(rf, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    name = re.split(r"[>=<!\[;]", line)[0].strip().lower()
                    if name:
                        deps.add(name)
        except (OSError, UnicodeDecodeError):
            pass
    # Pipfile
    pipfile = os.path.join(PROJECT_ROOT, "Pipfile")
    if os.path.exists(pipfile):
        try:
            in_packages = False
            with open(pipfile, encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("[") and "packages" in stripped.lower():
                        in_packages = True
                        continue
                    if stripped.startswith("["):
                        in_packages = False
                        continue
                    if in_packages and "=" in stripped:
                        name = stripped.split("=")[0].strip().strip('"').strip("'").lower()
                        if name:
                            deps.add(name)
        except (OSError, UnicodeDecodeError):
            pass
    # pyproject.toml (PEP 621 dependencies)
    pyproject = os.path.join(PROJECT_ROOT, "pyproject.toml")
    if os.path.exists(pyproject):
        try:
            with open(pyproject, encoding="utf-8") as f:
                content = f.read()
            # PEP 621 dependencies + optional-dependencies 섹션만 파싱
            in_deps = False
            for line in content.split("\n"):
                stripped = line.strip()
                if re.match(r"^(dependencies|optional-dependencies)\s*=", stripped) or re.match(r"^\[project\.optional-dependencies", stripped):
                    in_deps = True
                    continue
                if stripped.startswith("[") and "dependencies" not in stripped.lower():
                    in_deps = False
                    continue
                if in_deps:
                    for m in re.finditer(r'"([a-zA-Z0-9_-]+)', stripped):
                        deps.add(m.group(1).lower())
        except (OSError, UnicodeDecodeError):
            pass
    return deps

# --- Ruby 의존성 파싱 ---
def read_ruby_deps():
    """Gemfile에서 gem 패키지명 추출."""
    deps = set()
    gemfile = os.path.join(PROJECT_ROOT, "Gemfile")
    if os.path.exists(gemfile):
        try:
            with open(gemfile, encoding="utf-8") as f:
                for line in f:
                    m = re.match(r"""^\s*gem\s+['"]([a-zA-Z0-9_-]+)['"]""", line)
                    if m:
                        deps.add(m.group(1).lower())
        except (OSError, UnicodeDecodeError):
            pass
    return deps

# --- Java 의존성 파싱 ---
def read_java_deps():
    """pom.xml의 artifactId, build.gradle의 의존성 추출."""
    deps = set()
    pom_files = glob.glob(os.path.join(PROJECT_ROOT, "pom.xml"))
    pom_files += glob.glob(os.path.join(PROJECT_ROOT, "**/pom.xml"), recursive=True)
    for pf in pom_files[:5]:  # 최대 5개 pom 파싱
        try:
            with open(pf, encoding="utf-8") as f:
                content = f.read()
            for m in re.finditer(r"<artifactId>\s*([^<]+?)\s*</artifactId>", content):
                deps.add(m.group(1).lower())
        except (OSError, UnicodeDecodeError):
            pass
    gradle_files = glob.glob(os.path.join(PROJECT_ROOT, "build.gradle"))
    gradle_files += glob.glob(os.path.join(PROJECT_ROOT, "**/build.gradle"), recursive=True)
    gradle_files += glob.glob(os.path.join(PROJECT_ROOT, "build.gradle.kts"))
    gradle_files += glob.glob(os.path.join(PROJECT_ROOT, "**/build.gradle.kts"), recursive=True)
    for gf in gradle_files[:5]:
        try:
            with open(gf, encoding="utf-8") as f:
                for line in f:
                    m = re.match(r"""\s*(?:implementation|compile|api|runtimeOnly|testImplementation)\s*[\('"]\s*['"]?([^:'"]+):([^:'"]+)""", line)
                    if m:
                        deps.add(m.group(2).lower())
        except (OSError, UnicodeDecodeError):
            pass
    return deps

# --- 통합 의존성 검색 ---
_py_deps = None
_rb_deps = None
_java_deps = None

def _get_py_deps():
    global _py_deps
    if _py_deps is None:
        _py_deps = read_python_deps()
    return _py_deps

def _get_rb_deps():
    global _rb_deps
    if _rb_deps is None:
        _rb_deps = read_ruby_deps()
    return _rb_deps

def _get_java_deps():
    global _java_deps
    if _java_deps is None:
        _java_deps = read_java_deps()
    return _java_deps

def has_dep_any(*names):
    """Node.js, Python, Ruby, Java 모든 매니페스트에서 의존성 검색."""
    lower_names = [n.lower() for n in names]
    # Node.js
    if has_dependency(pkg, *names):
        return True
    # Python
    py = _get_py_deps()
    if any(n in py for n in lower_names):
        return True
    # Ruby
    rb = _get_rb_deps()
    if any(n in rb for n in lower_names):
        return True
    # Java
    java = _get_java_deps()
    if any(n in java for n in lower_names):
        return True
    return False

# --- 소스/설정 레벨 LLM 통합 시그널 ---
# 표준 SDK(openai/anthropic/langchain ...) 의존성이 없어도, 내부/사내 LLM 인프라
# (예: 카카오 Jarvis Agent Builder A2A API)를 커스텀 HTTP 클라이언트로 호출하는
# 프로젝트는 매니페스트만으로 LLM 통합을 알 수 없다. 이 경우 소스/설정에 남는
# 강한 LLM 시그널(엔드포인트 경로·요청 시그니처·system prompt·사내 플랫폼명)을 보고
# LLM 그룹 스캐너를 활성화한다. 과활성화돼도 매치가 0이면 '이상 없음'으로 끝나므로,
# 미탐(취약점 누락)보다 비용이 낮다 — recall 우선.
_LLM_SOURCE_RE = re.compile(
    # 'messages.create/stream' 은 DB/ORM(repo.messages.create)·메시징과 충돌하여
    # 제외한다(표준 SDK 의 messages.create 는 의존성 매니페스트로 이미 잡힘).
    r"chat/completions|/v1/chat\b|chatcompletion|generatecontent"
    r"|system[_-]?prompt|system[_-]?instruction"
    r"|prompttemplate|systemmessage"
    # 사내/에이전트 플랫폼의 실제 호출 구조 (Jarvis A2A 등).
    # 'jarvis'/'kanana' 같은 플랫폼명 단독은 제외 — 그 플랫폼의 데이터 모델
    # (예: KananaOrder)만 다루는 다운스트림 서비스까지 오탐하기 때문. LLM을 직접
    # 호출하는 클라이언트/요청 타입/엔드포인트 시그니처만 시그널로 인정한다.
    r"|jarvisclient|a2amessage|/api/agents/|/v1/message:(?:stream|send)",
    re.IGNORECASE,
)
_LLM_SOURCE_EXTS = (
    ".kt", ".java", ".py", ".ts", ".js", ".scala", ".go", ".rb", ".php", ".cs",
    ".yaml", ".yml", ".properties", ".conf", ".gradle", ".kts",
)
_LLM_SKIP_DIRS = {
    ".git", "node_modules", "build", "target", ".gradle", "dist", "out",
    "vendor", "__pycache__", ".idea", ".venv", "venv",
}
_llm_source_signal = None
def has_llm_source_signal():
    """소스/설정 파일에 내부 LLM 통합 시그널이 있으면 True (매니페스트 무관)."""
    global _llm_source_signal
    if _llm_source_signal is not None:
        return _llm_source_signal
    checked = 0
    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in _LLM_SKIP_DIRS]
        for fn in files:
            if not fn.endswith(_LLM_SOURCE_EXTS):
                continue
            checked += 1
            if checked > 8000:  # 안전 상한
                _llm_source_signal = False
                return False
            try:
                with open(os.path.join(root, fn), encoding="utf-8", errors="ignore") as f:
                    if _LLM_SOURCE_RE.search(f.read()):
                        _llm_source_signal = True
                        return True
            except OSError:
                pass
    _llm_source_signal = False
    return False

# --- prereq_group 동적 로드 (스캐너 frontmatter의 단일 진실 원천) ---
# 각 스캐너의 phase1.md frontmatter에 `prereq_group: <name>`이 선언된 경우,
# 그 스캐너는 사전 단계가 필요한 특수 그룹에 속한다. check_exclude의 그룹별
# 의존성 게이트도 본 캐시를 참조한다.

_PREREQ_GROUP_RE = re.compile(r"^prereq_group:\s*([a-z][a-z0-9_-]*)\s*$", re.M)


def _load_declared_prereq_groups():
    """scanners/*/phase1.md frontmatter에서 prereq_group을 수집하여
    {group_name: [scanner_name, ...]} 형태로 반환."""
    result: dict[str, list[str]] = {}
    scanners_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scanners")
    if not os.path.isdir(scanners_dir):
        return result
    for entry in sorted(os.listdir(scanners_dir)):
        phase1 = os.path.join(scanners_dir, entry, "phase1.md")
        if not os.path.isfile(phase1):
            continue
        try:
            with open(phase1, encoding="utf-8") as f:
                head = f.read(4096)  # frontmatter는 파일 상단
        except OSError:
            continue
        m = _PREREQ_GROUP_RE.search(head)
        if not m:
            continue
        grp = m.group(1)
        result.setdefault(grp, []).append(entry)
    return result


_declared_prereq_groups = _load_declared_prereq_groups()
# reverse map: scanner_name → group_name. check_exclude에서 그룹별 게이트 분기에 사용.
_scanner_prereq_group: dict[str, str] = {
    s: g for g, members in _declared_prereq_groups.items() for s in members
}


def check_exclude(scanner):
    """매치 0건일 때 아키텍처 조건으로 제외 가능한지 확인. 제외 시 사유 반환, 포함 시 None."""
    if scanner == "xss-scanner":
        if not has_file("*.html", "*.erb", "*.slim", "*.jsx", "*.tsx", "*.vue"):
            return "HTML 출력이 전혀 없는 프로젝트"
    elif scanner == "dom-xss-scanner":
        if not has_file("*.js", "*.jsx", "*.ts", "*.tsx", "*.vue"):
            return "프론트엔드 JS 코드 없음"
    elif scanner == "ssrf-scanner":
        if not has_dep_any(
            # Node.js
            "axios", "node-fetch", "got", "request",
            # Python
            "requests", "urllib3", "httpx", "aiohttp",
            # Ruby
            "httparty", "faraday", "rest-client", "typhoeus",
            # Java
            "httpclient", "okhttp", "retrofit", "spring-web",
        ):
            return "서버사이드 HTTP 요청 라이브러리 없음"
    elif scanner == "csrf-scanner":
        if has_dep_any("jsonwebtoken", "jose", "pyjwt", "ruby-jwt") and not has_file("*.erb", "*.html"):
            return "쿠키 기반 인증 아님 (토큰 전용 API)"
    elif scanner == "file-upload-scanner":
        if not has_dep_any(
            # Node.js
            "multer", "busboy", "formidable", "multiparty",
            # Python
            "flask", "django", "fastapi", "flask-uploads",
            # Ruby
            "carrierwave", "shrine", "paperclip", "active_storage",
        ):
            return "파일 업로드 엔드포인트 없음"
    elif scanner == "command-injection-scanner":
        pass  # 매치가 0이면 exec/system 호출 없으므로 안전
    elif scanner == "code-injection-scanner":
        pass  # 매치가 0이면 eval/assert/create_function 등 코드 실행 sink 없으므로 안전
    elif scanner == "sqli-scanner":
        if not has_dep_any(
            # Node.js
            "mysql", "mysql2", "pg", "better-sqlite3", "sequelize", "knex", "typeorm", "prisma",
            # Python
            "psycopg2", "psycopg2-binary", "pymysql", "sqlalchemy", "django", "peewee", "asyncpg",
            # Ruby
            "activerecord", "sequel", "pg", "mysql2", "sqlite3",
            # Java
            "mybatis", "hibernate-core", "spring-jdbc", "jooq",
        ):
            return "SQL 라이브러리/ORM 없음"
    elif scanner == "xxe-scanner":
        if not has_dep_any(
            # Node.js
            "xml2js", "fast-xml-parser", "libxmljs", "sax", "xmldom",
            # Python
            "lxml", "defusedxml", "xml",
            # Ruby
            "nokogiri", "rexml",
            # Java
            "jaxb-api", "jackson-dataformat-xml", "dom4j", "xercesimpl",
        ):
            return "XML 파싱 라이브러리 없음"
    elif scanner == "deserialization-scanner":
        pass  # 매치가 0이면 역직렬화 함수 호출 없음
    elif scanner == "ssti-scanner":
        if not has_dep_any(
            # Node.js
            "ejs", "pug", "handlebars", "nunjucks", "mustache",
            # Python
            "jinja2", "mako", "django",
            # Ruby
            "erb", "slim", "haml", "liquid",
        ):
            return "서버사이드 템플릿 엔진 없음"
    elif scanner == "jwt-scanner":
        if not has_dep_any(
            # Node.js
            "jsonwebtoken", "jose", "jwt-decode", "jwks-rsa",
            # Python
            "pyjwt", "python-jose", "authlib",
            # Ruby
            "ruby-jwt", "jwt",
            # Java
            "jjwt", "nimbus-jose-jwt", "java-jwt",
        ):
            return "JWT 라이브러리 없음"
    elif scanner == "oauth-scanner":
        if not has_dep_any(
            # Node.js
            "passport", "passport-oauth2", "openid-client", "oauth", "grant",
            # Python
            "authlib", "oauthlib", "social-auth-core", "django-allauth",
            # Ruby
            "omniauth", "doorkeeper", "oauth2",
            # Java
            "spring-security-oauth2",
        ):
            return "OAuth/OIDC 라이브러리 없음"
    elif scanner == "nosqli-scanner":
        if not has_dep_any(
            # Node.js
            "mongoose", "mongodb", "mongoist",
            # Python
            "pymongo", "mongoengine", "motor",
            # Ruby
            "mongoid", "mongo",
            # Java
            "mongo-java-driver", "spring-data-mongodb",
        ):
            return "NoSQL 라이브러리 없음"
    elif scanner == "ldap-injection-scanner":
        if not has_dep_any(
            # Node.js
            "ldapjs", "ldap-authentication", "activedirectory",
            # Python
            "python-ldap", "ldap3",
            # Ruby
            "net-ldap",
            # Java
            "unboundid-ldapsdk",
        ):
            return "LDAP 라이브러리 없음"
    elif scanner == "xslt-injection-scanner":
        if not has_dep_any(
            # Node.js
            "xslt", "saxon", "libxslt",
            # Python
            "lxml",
            # Java
            "saxon-he", "xalan",
        ):
            return "XSLT 라이브러리 없음"
    elif scanner == "xpath-injection-scanner":
        if not has_dep_any(
            # Node.js
            "xpath", "xmldom", "libxmljs",
            # Python
            "lxml",
            # Ruby
            "nokogiri",
        ):
            return "XPath 라이브러리 없음"
    elif scanner == "soapaction-spoofing-scanner":
        if not has_dep_any(
            # Node.js
            "soap", "strong-soap",
            # Python
            "zeep", "suds",
            # Java
            "cxf-rt-frontend-jaxws", "axis2",
        ):
            if not has_file("*.wsdl"):
                return "SOAP 라이브러리/WSDL 없음"
    elif scanner == "pdf-generation-scanner":
        if not has_dep_any(
            # Node.js
            "puppeteer", "wkhtmltopdf", "pdfkit", "html-pdf", "playwright",
            # Python
            "weasyprint", "reportlab", "xhtml2pdf", "pdfkit",
            # Ruby
            "wicked_pdf", "prawn", "grover",
            # Java
            "flying-saucer-pdf", "openhtmltopdf", "itext",
        ):
            return "PDF 생성 라이브러리 없음"
    elif scanner == "saml-scanner":
        if not has_dep_any(
            # Node.js
            "saml2-js", "passport-saml", "samlify", "node-saml",
            # Python
            "python3-saml", "djangosaml2",
            # Ruby
            "ruby-saml",
            # Java
            "opensaml", "spring-security-saml2-service-provider",
        ):
            return "SAML 라이브러리 없음"
    elif scanner == "zipslip-scanner":
        if not has_dep_any(
            # Node.js
            "adm-zip", "unzipper", "yauzl", "tar", "archiver",
            # Python
            "zipfile", "tarfile",
            # Ruby
            "rubyzip",
            # Java
            "commons-compress", "zip4j",
        ):
            return "압축 해제 라이브러리 없음"
    elif scanner == "graphql-scanner":
        if not has_dep_any(
            # Node.js
            "graphql", "apollo-server", "express-graphql", "mercurius",
            # Python
            "graphene", "strawberry-graphql", "ariadne",
            # Ruby
            "graphql-ruby",
            # Java
            "graphql-java", "graphql-spring-boot-starter",
        ):
            return "GraphQL 라이브러리 없음"
    elif scanner == "sourcemap-scanner":
        if not has_dep_any("webpack", "vite", "esbuild", "rollup", "parcel"):
            return "프론트엔드 빌드 도구 없음"
    elif scanner == "csv-injection-scanner":
        if not has_dep_any(
            # Node.js
            "csv-writer", "csv-stringify", "exceljs", "xlsx", "papaparse",
            # Python
            "openpyxl", "xlsxwriter", "pandas",
            # Ruby
            "csv", "axlsx", "roo",
            # Java
            "poi", "opencsv",
        ):
            return "CSV/Excel 라이브러리 없음"
    elif scanner == "prototype-pollution-scanner":
        if not has_file("*.js", "*.ts", "*.mjs"):
            return "JavaScript/Node.js 프로젝트 아님"
    elif scanner == "websocket-scanner":
        if not has_dep_any(
            # Node.js
            "ws", "socket.io", "sockjs", "faye-websocket",
            # Python
            "websockets", "channels", "flask-socketio",
            # Ruby
            "faye-websocket", "actioncable",
            # Java
            "spring-websocket", "tyrus",
        ):
            return "WebSocket 라이브러리 없음"
    elif scanner == "subdomain-takeover-scanner":
        if not has_file("*.tf", "CNAME", "dns*"):
            return "DNS/인프라 설정 없음"
    elif scanner == "business-logic-scanner":
        pass  # grep-less 스캐너: 항상 포함 (AI가 라우트 전수 조사)
    elif scanner == "security-headers-scanner":
        pass  # 보안 헤더는 모든 웹 프로젝트에 해당
    elif scanner == "springboot-hardening-scanner":
        if not has_pom:
            return "Spring Boot 프로젝트 아님 (pom.xml/build.gradle 없음)"
    elif scanner == "cookie-security-scanner":
        pass  # 쿠키는 모든 웹 프로젝트에 해당
    elif scanner == "tls-scanner":
        pass  # TLS 설정은 모든 웹 프로젝트에 해당
    elif scanner == "validation-logic-scanner":
        pass  # 유효성 검사 로직은 모든 웹 프로젝트에 해당
    elif scanner in ("android-deeplink-scanner", "android-webview-scanner", "android-ipc-scanner", "android-manifest-scanner", "android-accountmanager-scanner"):
        if not has_file(
            "AndroidManifest.xml",
            "*.kt", "*.kts",
            "*.java",
            "build.gradle", "build.gradle.kts",
        ):
            return "Android 프로젝트 아님 (AndroidManifest.xml/Kotlin/Java/Gradle 없음)"
    elif scanner == "hardcoded-secrets-scanner":
        pass  # 하드코딩 비밀값은 모든 프로젝트에 해당
    elif scanner == "log-injection-scanner":
        pass  # 로그 인젝션은 모든 웹 프로젝트에 해당
    elif scanner in ("ios-webview-scanner", "ios-storage-scanner", "ios-crypto-scanner"):
        if not has_ios:
            return "iOS 프로젝트 아님 (*.xcodeproj/Podfile/Package.swift/Info.plist 없음)"
    elif _scanner_prereq_group.get(scanner) == "llm":
        if not has_dep_any(
            # Python
            "openai", "anthropic", "google-generativeai", "google-genai",
            "vertexai", "google-cloud-aiplatform", "cohere", "mistralai",
            "replicate", "together", "groq", "litellm", "ollama",
            "huggingface-hub", "transformers", "langchain", "langchain-core",
            "langchain-openai", "langchain-anthropic", "langgraph",
            "llama-index", "llama-index-core", "haystack-ai", "semantic-kernel",
            # Node.js
            "openai", "@anthropic-ai/sdk", "@google/generative-ai",
            "@google-cloud/vertexai", "cohere-ai", "@mistralai/mistralai",
            "replicate", "together-ai", "groq-sdk", "litellm", "ollama",
            "@huggingface/inference", "langchain", "@langchain/core",
            "@langchain/openai", "@langchain/anthropic", "llamaindex",
        ) and not has_llm_source_signal():
            return "LLM SDK/프레임워크 의존성 없음 (소스 LLM 시그널도 없음)"
    # open-redirect, crlf, path-traversal, http-method-tampering, host-header,
    # css-injection, redos, http-smuggling, idor: 아키텍처만으로 제외하기 어려움 → 포함
    return None

# --- 선별 실행 ---
included = []
excluded = []

print("=" * 60)
print("스캐너 선별 결과")
print("=" * 60)
print()
print("| 스캐너 | 매치 히트 | 판정 | 사유 |")
print("|--------|----------|------|------|")

for scanner in SCANNERS:
    _, count = read_index(scanner)
    if count > 0:
        included.append((scanner, count))
        print(f"| {scanner} | {count} | ✅ 포함 | 매치 히트 {count}건 |")
    else:
        reason = check_exclude(scanner)
        if reason:
            excluded.append((scanner, reason))
            print(f"| {scanner} | 0 | ❌ 제외 | {reason} |")
        else:
            included.append((scanner, 0))
            print(f"| {scanner} | 0 | ✅ 포함 | 아키텍처 제외 조건 미충족 |")

print()
print(f"적용: {len(included)}개 / 제외: {len(excluded)}개 / 전체: {len(SCANNERS)}개")
print()
print("--- 적용 스캐너 목록 ---")
for s, c in included:
    print(s)

# --- Tier 분류 (Phase 2 실행 시 인증 컨텍스트 기반 병렬화) ---

# Tier A: 인증 불요 (헤더/설정 검사). Tier 내 순차, 다른 Tier와 병렬
TIER_A = {
    "security-headers-scanner", "http-smuggling-scanner", "host-header-scanner",
    "http-method-tampering-scanner", "crlf-injection-scanner", "sourcemap-scanner",
    "subdomain-takeover-scanner", "tls-scanner",
}
# Tier C: 독립 인증 컨텍스트. Tier 내 순차, Tier B와 병렬
TIER_C = {"oauth-scanner", "saml-scanner", "jwt-scanner"}
# Tier B: 공유 세션 (Tier A/C가 아닌 모든 스캐너)


def tier_of(scanner: str) -> str:
    if scanner in TIER_A:
        return "A"
    if scanner in TIER_C:
        return "C"
    return "B"


# --- 그룹 리밸런싱 ---

# 기본 그룹 정의 (의미적 연관성 기반)
BASE_GROUPS = {
    "url-navigation": ["xss-scanner", "dom-xss-scanner", "open-redirect-scanner"],
    "response-header": ["crlf-injection-scanner", "host-header-scanner", "http-method-tampering-scanner"],
    "db-query": ["sqli-scanner", "nosqli-scanner"],
    "process-execution": ["command-injection-scanner", "code-injection-scanner", "ssti-scanner"],
    "server-request": ["ssrf-scanner", "pdf-generation-scanner"],
    "file-system": ["path-traversal-scanner", "file-upload-scanner", "zipslip-scanner"],
    "xml-serialization": ["xxe-scanner", "xslt-injection-scanner", "deserialization-scanner"],
    "auth-protocol": ["jwt-scanner", "oauth-scanner", "saml-scanner", "csrf-scanner", "idor-scanner", "cookie-security-scanner"],
    "client-rendering": ["redos-scanner", "css-injection-scanner", "prototype-pollution-scanner"],
    "infra-config": ["http-smuggling-scanner", "sourcemap-scanner", "subdomain-takeover-scanner", "security-headers-scanner", "springboot-hardening-scanner", "tls-scanner"],
    "data-export": ["csv-injection-scanner"],
    "protocol-check": ["graphql-scanner", "websocket-scanner", "soapaction-spoofing-scanner", "ldap-injection-scanner", "xpath-injection-scanner"],
    "business-logic": ["business-logic-scanner", "validation-logic-scanner"],
    "mobile": ["android-deeplink-scanner", "android-webview-scanner", "android-ipc-scanner", "android-manifest-scanner", "android-accountmanager-scanner"],
    "ios": ["ios-webview-scanner", "ios-storage-scanner", "ios-crypto-scanner"],
    "secrets-logging": ["hardcoded-secrets-scanner", "log-injection-scanner"],
}


# 선언된 prereq_group을 BASE_GROUPS에 합성. 동일 키가 있으면 덮어쓰지 않고 경고만.
# (함수 정의는 모듈 상단에서 check_exclude보다 먼저 호출되어 _scanner_prereq_group를 채움)
for _grp, _members in _declared_prereq_groups.items():
    if _grp in BASE_GROUPS:
        print(
            f"WARNING: prereq_group '{_grp}'이 BASE_GROUPS에 이미 존재합니다. "
            f"frontmatter 선언과 dict 정의가 충돌 — frontmatter 선언을 무시합니다.",
            file=sys.stderr,
        )
        continue
    BASE_GROUPS[_grp] = sorted(_members)

# 의미적 서브그룹 (과부하 그룹 분할 시 사용)
SPLIT_HINTS = {
    "auth-protocol": [
        ["jwt-scanner", "oauth-scanner", "saml-scanner"],  # 토큰/프로토콜 인증
        ["csrf-scanner", "idor-scanner", "cookie-security-scanner"],  # 요청 위조/권한/쿠키
    ],
    "infra-config": [
        ["http-smuggling-scanner", "security-headers-scanner", "springboot-hardening-scanner", "tls-scanner"],
        ["sourcemap-scanner", "subdomain-takeover-scanner"],
    ],
    "protocol-check": [
        ["graphql-scanner", "websocket-scanner", "xpath-injection-scanner"],
        ["soapaction-spoofing-scanner", "ldap-injection-scanner"],
    ],
    "mobile": [
        ["android-webview-scanner", "android-deeplink-scanner"],
        ["android-ipc-scanner", "android-manifest-scanner"],
        ["android-accountmanager-scanner"],
    ],
}

MAX_GROUP_WORKLOAD = 150  # 그룹당 최대 매치 히트 합계
MAX_GROUP_SIZE = 4        # 그룹당 최대 스캐너 수

included_set = {s for s, _ in included}
included_hits = {s: c for s, c in included}


def rebalance_groups():
    """적용 스캐너만으로 그룹을 재편성한다. 과부하 그룹은 분할, 빈 그룹은 제거."""
    groups = {}

    for group_name, members in BASE_GROUPS.items():
        active = [s for s in members if s in included_set]
        if not active:
            continue

        total_hits = sum(included_hits.get(s, 0) for s in active)

        # 분할 필요 여부 판단
        if (total_hits > MAX_GROUP_WORKLOAD or len(active) > MAX_GROUP_SIZE) and group_name in SPLIT_HINTS:
            hints = SPLIT_HINTS[group_name]
            for i, hint_members in enumerate(hints):
                sub_active = [s for s in hint_members if s in included_set]
                if sub_active:
                    sub_name = f"{group_name}-{i+1}"
                    groups[sub_name] = sub_active
        else:
            groups[group_name] = active

    return groups


balanced_groups = rebalance_groups()

print()
print("--- 그룹 편성 ---")
for gname, members in balanced_groups.items():
    tiers = {tier_of(s) for s in members}
    tier_label = "/".join(sorted(tiers)) if len(tiers) > 1 else next(iter(tiers))
    member_strs = [f"{s}({included_hits.get(s, 0)})" for s in members]
    total = sum(included_hits.get(s, 0) for s in members)
    print(f"Group ({gname}, Tier {tier_label}): {', '.join(member_strs)} [총 {total}건]")

# --- Tier 요약 (Phase 2 병렬 실행 지침) ---
tier_buckets: dict[str, list[str]] = {"A": [], "B": [], "C": []}
for scanner in included_set:
    tier_buckets[tier_of(scanner)].append(scanner)

print()
print("--- Tier 요약 (Phase 2 실행) ---")
print(f"Tier A: {len(tier_buckets['A'])}개 (인증 불요. Tier 내 순차, 다른 Tier와 병렬)")
for s in sorted(tier_buckets["A"]):
    print(f"  - {s}")
print(f"Tier B: {len(tier_buckets['B'])}개 (공유 세션. Tier 내 순차)")
for s in sorted(tier_buckets["B"]):
    print(f"  - {s}")
print(f"Tier C: {len(tier_buckets['C'])}개 (독립 인증. Tier 내 순차, Tier B와 병렬)")
for s in sorted(tier_buckets["C"]):
    print(f"  - {s}")
print()
print("실행 규칙: Tier A/B/C를 동시에 시작. 각 Tier 내부는 순차. 모든 Tier 완료 후 Step 10 진행.")

# 선택적: 적용 스캐너 목록을 JSON 파일로 저장
for arg in sys.argv[3:]:
    if arg.startswith("--write-expected-file="):
        wef_path = Path(arg.split("=", 1)[1])
        wef_path.parent.mkdir(parents=True, exist_ok=True)
        wef_path.write_text(
            json.dumps([s for s, _ in included], ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"\n적용 스캐너 목록 저장: {wef_path}")
        break
