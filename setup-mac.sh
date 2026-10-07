#!/usr/bin/env bash
# ============================================================
#  ARTEX macOS 원클릭 설치 스크립트
#  - Docker Desktop 설치 (없을 경우)
#  - PostgreSQL + ARTEX 자동 구성
#  - http://localhost:8787 에서 접속
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

info()  { printf "${CYAN}[*]${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}[✓]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()   { printf "${RED}[✗]${NC} %s\n" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   ARTEX - AI 자율 침투 테스트 시스템   ║"
echo "║   macOS 설치 스크립트                  ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── Step 1: Docker Desktop 확인/설치 ──────────────
install_docker_desktop() {
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        ok "Docker Desktop 이미 실행 중입니다"
        return 0
    fi

    if [ -d "/Applications/Docker.app" ]; then
        warn "Docker Desktop이 설치되어 있지만 실행 중이 아닙니다"
        info "Docker Desktop을 시작합니다..."
        open -a Docker
        info "Docker 엔진이 시작될 때까지 대기 중... (최대 120초)"
        for i in $(seq 1 60); do
            if docker info &>/dev/null 2>&1; then
                ok "Docker 엔진 준비 완료!"
                return 0
            fi
            sleep 2
            printf "."
        done
        err "Docker 엔진 시작 시간 초과. Docker Desktop을 수동으로 시작해 주세요."
        exit 1
    fi

    info "Docker Desktop 설치가 필요합니다."

    # 이미 다운로드된 DMG 확인
    DMG_PATH="/tmp/Docker.dmg"
    if [ ! -f "$DMG_PATH" ]; then
        info "Docker Desktop DMG 다운로드 중... (약 560MB)"
        curl -L -o "$DMG_PATH" "https://desktop.docker.com/mac/main/arm64/Docker.dmg"
    else
        ok "Docker DMG 이미 다운로드 완료 ($DMG_PATH)"
    fi

    info "Docker Desktop DMG 마운트 중..."
    hdiutil attach "$DMG_PATH" -nobrowse -quiet

    info "Docker.app을 Applications에 복사 중..."
    cp -R "/Volumes/Docker/Docker.app" /Applications/

    info "DMG 마운트 해제 중..."
    hdiutil detach "/Volumes/Docker" -quiet 2>/dev/null || true

    ok "Docker Desktop 설치 완료!"

    info "Docker Desktop 시작 중..."
    open -a Docker

    info "Docker 엔진이 시작될 때까지 대기 중... (최대 120초)"
    for i in $(seq 1 60); do
        if docker info &>/dev/null 2>&1; then
            ok "Docker 엔진 준비 완료!"
            return 0
        fi
        sleep 2
        printf "."
    done
    echo ""
    warn "Docker 엔진 시작이 좀 오래 걸리고 있습니다."
    warn "Docker Desktop이 완전히 시작된 후 이 스크립트를 다시 실행해 주세요."
    exit 1
}

# ── Step 2: docker compose 확인 ──────────────────
check_compose() {
    if docker compose version &>/dev/null 2>&1; then
        ok "docker compose: $(docker compose version --short 2>/dev/null || echo 'OK')"
        return 0
    fi
    err "docker compose를 찾을 수 없습니다. Docker Desktop을 최신 버전으로 업데이트해 주세요."
    exit 1
}

# ── Step 3: .env 설정 ────────────────────────────
setup_env() {
    if [ -f .env ]; then
        info "기존 .env 파일을 사용합니다"
        return 0
    fi

    info ".env 설정 파일 생성 중..."
    cp .env.example .env

    # 랜덤 Postgres 비밀번호 생성
    PG_PASS=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)

    # .env에 비밀번호 설정
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${PG_PASS}|" .env
    else
        sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${PG_PASS}|" .env
    fi

    ok ".env 생성 완료 (Postgres 비밀번호 자동 생성됨)"
    echo ""
    info "LLM API 키 설정 (선택사항 - 나중에 웹 UI에서도 설정 가능):"
    echo "  Anthropic: export ANTHROPIC_API_KEY=sk-ant-..."
    echo "  OpenAI:    export OPENAI_API_KEY=sk-..."
    echo ""
    read -rp "  Anthropic API Key (없으면 Enter): " ANTHRO_KEY
    if [ -n "$ANTHRO_KEY" ]; then
        if [[ "$(uname)" == "Darwin" ]]; then
            sed -i '' "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${ANTHRO_KEY}|" .env
        else
            sed -i "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${ANTHRO_KEY}|" .env
        fi
        ok "Anthropic API Key 설정 완료"
    fi

    read -rp "  OpenAI API Key (없으면 Enter): " OPENAI_KEY
    if [ -n "$OPENAI_KEY" ]; then
        if [[ "$(uname)" == "Darwin" ]]; then
            sed -i '' "s|^OPENAI_API_KEY=.*|OPENAI_API_KEY=${OPENAI_KEY}|" .env
        else
            sed -i "s|^OPENAI_API_KEY=.*|OPENAI_API_KEY=${OPENAI_KEY}|" .env
        fi
        ok "OpenAI API Key 설정 완료"
    fi
}

# ── Step 4: Docker Compose 실행 ──────────────────
start_services() {
    info "Docker 이미지 다운로드 중... (첫 실행 시 시간이 걸릴 수 있습니다)"
    docker compose pull

    info "서비스 시작 중..."
    docker compose up -d

    echo ""
    ok "════════════════════════════════════════════"
    ok "  ARTEX 설치 및 시작 완료!"
    ok "════════════════════════════════════════════"
    echo ""
    info "접속 주소: http://localhost:8787"
    info "첫 접속 시 /setup 페이지에서 관리자 비밀번호를 설정하세요."
    echo ""
    info "유용한 명령어:"
    echo "  로그 확인:    docker compose logs -f artex"
    echo "  서비스 중지:  docker compose down"
    echo "  서비스 재시작: docker compose restart artex"
    echo "  업데이트:     docker compose pull artex && docker compose up -d artex"
    echo ""

    # 브라우저 열기
    sleep 3
    info "브라우저에서 ARTEX 열기..."
    open "http://localhost:8787" 2>/dev/null || true
}

# ── 실행 ─────────────────────────────────────────
install_docker_desktop
check_compose
setup_env
start_services
