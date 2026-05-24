#!/usr/bin/env bash
# Noah SAST — Claude Code 취약점 스캐너 플러그인 설치 스크립트
#
# 설치 방법:
#   curl -fsSL https://raw.githubusercontent.com/nomarlhack/noah-8719/main/install.sh | bash
#   git clone ... && cd noah-8719 && ./install.sh
#
# 업데이트:
#   ~/.claude/skills/noah-8719/install.sh --update

set -euo pipefail

# ─── 색상 ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

REPO_URL="https://github.com/nomarlhack/noah-claude-plugin.git"
INSTALL_DIR="$HOME/.claude/skills/noah-8719"

info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$1"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; exit 1; }

# pipe 모드(curl | bash)에서도 사용자 입력을 받을 수 있도록 /dev/tty 사용
# 주의: $(ask ...) subshell에서 호출되므로 프롬프트는 반드시 stderr나 tty로 출력해야 한다
ask() {
  local prompt="$1" default="${2:-N}"
  if [ -t 0 ]; then
    printf "%s " "$prompt" >&2
    read -r answer
  elif [ -e /dev/tty ]; then
    printf "%s " "$prompt" >/dev/tty
    read -r answer </dev/tty
  else
    answer="$default"
  fi
  echo "$answer"
}

# ─── 인자 파싱 ───
UPDATE_MODE=false
for arg in "$@"; do
  case "$arg" in
    --update|-u) UPDATE_MODE=true ;;
    --help|-h)
      echo "Usage: install.sh [--update]"
      echo "  --update, -u    기존 설치를 최신 버전으로 업데이트"
      echo "  --help, -h      도움말 출력"
      exit 0
      ;;
  esac
done

# ─── 버전 표시 ───
# 로컬 소스에 VERSION 파일이 있으면 해당 버전을, 없으면 기본값 사용
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/VERSION" ]; then
  VERSION=$(cat "$SCRIPT_DIR/VERSION" | tr -d '[:space:]')
elif [ -f "$INSTALL_DIR/VERSION" ]; then
  VERSION=$(cat "$INSTALL_DIR/VERSION" | tr -d '[:space:]')
else
  VERSION="latest"
fi

echo ""
printf "${BOLD}${CYAN}╔══════════════════════════════════════╗${NC}\n"
printf "${BOLD}${CYAN}║     Noah SAST Installer v%-11s ║${NC}\n" "$VERSION"
printf "${BOLD}${CYAN}╚══════════════════════════════════════╝${NC}\n"
echo ""

# ─── 업데이트 모드 ───
if $UPDATE_MODE; then
  if [ ! -d "$INSTALL_DIR" ]; then
    error "기존 설치를 찾을 수 없습니다. 먼저 설치해 주세요."
  fi
  if [ -d "$INSTALL_DIR/.git" ]; then
    info "git pull로 업데이트합니다..."
    git -C "$INSTALL_DIR" pull --ff-only origin main
    NEW_VER=$(cat "$INSTALL_DIR/VERSION" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
    ok "업데이트 완료 (v$NEW_VER)"
  else
    warn "git 저장소가 아닙니다. 재설치가 필요합니다."
    warn "실행: curl -fsSL https://raw.githubusercontent.com/nomarlhack/noah-8719/main/install.sh | bash"
  fi
  exit 0
fi

# ─── 사전 조건 확인 ───

# Git 확인
command -v git >/dev/null 2>&1 || error "git이 설치되어 있지 않습니다."
ok "git 확인"

# Python 3 확인
if command -v python3 >/dev/null 2>&1; then
  PY_VER=$(python3 --version 2>&1)
  ok "Python 확인 ($PY_VER)"
else
  warn "python3이 없습니다. 보고서 생성 기능이 제한될 수 있습니다."
fi

# LLM 채널 어댑터 의존성 (websocket-client, requests)
# tools/llm_channel_probe.py가 ws-stomp/ws-raw/sse 등 채널 검증에 사용
if command -v python3 >/dev/null 2>&1; then
  info "LLM 채널 어댑터 의존성 설치 (websocket-client, requests)..."
  if python3 -m pip install --user --quiet websocket-client requests 2>/dev/null; then
    ok "LLM 채널 어댑터 의존성 설치 완료"
  else
    warn "websocket-client/requests 설치 실패. LLM 그룹 동적 검증이 제한될 수 있습니다."
    warn "수동 설치: python3 -m pip install --user websocket-client requests"
  fi
fi

# semgrep 확인 — `rules/` 디렉토리를 가진 스캐너의 Phase 1 인덱싱에 사용
# (현재 sqli-scanner가 semgrep 룰 기반. 나머지 스캐너는 grep 패턴 사용 — semgrep 없어도 동작)
if command -v semgrep >/dev/null 2>&1; then
  SEMGREP_VER=$(semgrep --version 2>/dev/null | head -1 | tr -d '[:space:]')
  ok "semgrep 확인 (v$SEMGREP_VER)"
else
  warn "semgrep이 없습니다. semgrep 룰 기반 스캐너(sqli 등)의 Phase 1 인덱싱이 비활성화됩니다."
  warn "설치: brew install semgrep   또는   python3 -m pip install --user semgrep"
fi

# Claude Code 확인
if [ ! -d "$HOME/.claude" ]; then
  error "\$HOME/.claude 디렉토리가 없습니다. Claude Code가 설치되어 있는지 확인하세요."
fi
ok "Claude Code 디렉토리 확인"

# ─── 기존 설치 확인 ───
if [ -d "$INSTALL_DIR" ]; then
  INSTALLED_VER=$(cat "$INSTALL_DIR/VERSION" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
  warn "기존 설치가 감지되었습니다: $INSTALL_DIR (v$INSTALLED_VER)"
  answer=$(ask "  덮어쓰시겠습니까? [y/N]" "N")
  case "$answer" in
    [yY]|[yY][eE][sS])
      info "기존 설치를 백업합니다..."
      BACKUP_DIR="${INSTALL_DIR}.backup.$(date +%Y%m%d%H%M%S)"
      mv "$INSTALL_DIR" "$BACKUP_DIR"
      ok "백업 완료: $BACKUP_DIR"
      ;;
    *)
      info "설치를 취소합니다."
      exit 0
      ;;
  esac
fi

# ─── 설치 ───
mkdir -p "$HOME/.claude/skills"

# 이미 repo 내부에서 실행 중인지 확인 (단, 설치 대상 경로와 동일하면 git clone 사용)
IS_LOCAL_SOURCE=false
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/.claude-plugin/plugin.json" ] && [ -d "$SCRIPT_DIR/skills/sast/scanners" ]; then
  # 자기 자신에게 복사하는 루프 방지: SCRIPT_DIR과 INSTALL_DIR이 같으면 clone 모드로 전환
  RESOLVED_SCRIPT=$(cd "$SCRIPT_DIR" && pwd -P)
  RESOLVED_INSTALL=$(mkdir -p "$INSTALL_DIR" 2>/dev/null && cd "$INSTALL_DIR" && pwd -P 2>/dev/null || echo "$INSTALL_DIR")
  # 방금 mkdir로 만든 빈 디렉토리 정리
  rmdir "$INSTALL_DIR" 2>/dev/null || true
  if [ "$RESOLVED_SCRIPT" != "$RESOLVED_INSTALL" ]; then
    IS_LOCAL_SOURCE=true
  fi
fi

if $IS_LOCAL_SOURCE; then
  info "로컬 소스에서 설치합니다..."
  cp -R "$SCRIPT_DIR" "$INSTALL_DIR"
  # 불필요한 파일 정리
  rm -rf "$INSTALL_DIR/.git"
  find "$INSTALL_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  find "$INSTALL_DIR" -name "*.pyc" -o -name "*.pyo" | xargs rm -f 2>/dev/null || true
else
  info "GitHub에서 클론합니다..."
  git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
fi

ok "파일 설치 완료: $INSTALL_DIR"

# ─── 플러그인 구조 검증 ───
MANIFEST="$INSTALL_DIR/.claude-plugin/plugin.json"
HOOKS_FILE="$INSTALL_DIR/hooks/hooks.json"
if [ -f "$MANIFEST" ]; then
  ok "플러그인 매니페스트 확인 (.claude-plugin/plugin.json)"
else
  warn "plugin.json 누락 — 플러그인으로 인식되지 않을 수 있습니다."
fi
if [ -f "$HOOKS_FILE" ]; then
  ok "보안 후크 설정 확인 (hooks/hooks.json)"
else
  warn "hooks.json이 없습니다. 보안 후크가 미적용 상태입니다."
fi

# ─── 설치 검증 ───
ERRORS=0
[ -f "$INSTALL_DIR/skills/sast/SKILL.md" ] || { warn "skills/sast/SKILL.md 누락"; ERRORS=$((ERRORS+1)); }
[ -f "$INSTALL_DIR/.claude-plugin/plugin.json" ] || { warn ".claude-plugin/plugin.json 누락"; ERRORS=$((ERRORS+1)); }
[ -d "$INSTALL_DIR/skills/sast/scanners" ] || { warn "skills/sast/scanners/ 누락"; ERRORS=$((ERRORS+1)); }
[ -d "$INSTALL_DIR/skills/sast/prompts" ]  || { warn "skills/sast/prompts/ 누락"; ERRORS=$((ERRORS+1)); }
[ -d "$INSTALL_DIR/skills/sast/tools" ]    || { warn "skills/sast/tools/ 누락"; ERRORS=$((ERRORS+1)); }

SCANNER_COUNT=$(ls -d "$INSTALL_DIR/skills/sast/scanners"/*-scanner 2>/dev/null | wc -l | tr -d ' ')
if [ "$SCANNER_COUNT" -lt 46 ]; then
  warn "스캐너가 ${SCANNER_COUNT}개뿐입니다. (기대값: 47개)"
  ERRORS=$((ERRORS+1))
fi

# LLM 그룹 사전 단계 / Phase 2 의존 — 채널 어댑터 헬퍼 + 의존성
LLM_PROBE="$INSTALL_DIR/skills/sast/tools/llm_channel_probe.py"
LLM_AGENT="$INSTALL_DIR/skills/sast/prompts/llm-endpoint-probe-agent.md"
if [ -f "$LLM_PROBE" ] && [ -f "$LLM_AGENT" ]; then
  if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import websocket, requests" 2>/dev/null; then
      ok "LLM 그룹 채널 어댑터 의존성 동작 확인"
    else
      warn "websocket-client/requests import 실패 — LLM 그룹 동적 검증이 비활성화됩니다."
      warn "수동 설치: python3 -m pip install --user websocket-client requests"
      ERRORS=$((ERRORS+1))
    fi
  fi
else
  warn "LLM 그룹 사전 단계 파일 누락 (llm_channel_probe.py 또는 llm-endpoint-probe-agent.md)"
  ERRORS=$((ERRORS+1))
fi

if [ "$ERRORS" -gt 0 ]; then
  warn "설치 검증에서 ${ERRORS}건의 경고가 발생했습니다."
else
  ok "설치 검증 통과 (스캐너 ${SCANNER_COUNT}개)"
fi

# ─── 완료 ───
echo ""
printf "${BOLD}${GREEN}╔══════════════════════════════════════╗${NC}\n"
printf "${BOLD}${GREEN}║      설치가 완료되었습니다!          ║${NC}\n"
printf "${BOLD}${GREEN}╚══════════════════════════════════════╝${NC}\n"
echo ""
info "설치 경로: $INSTALL_DIR"
info "스캐너 수: ${SCANNER_COUNT}개"
info "버전:     v$VERSION"
echo ""
printf "${BOLD}사용법:${NC}\n"
echo "  claude --plugin-dir $INSTALL_DIR"
echo "  이후: /noah-8719:sast"
echo ""
printf "${BOLD}업데이트:${NC}\n"
echo "  $INSTALL_DIR/install.sh --update"
echo ""
printf "${BOLD}제거:${NC}\n"
echo "  $INSTALL_DIR/uninstall.sh"
echo ""
