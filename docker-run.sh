#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  CandyConnect - Docker Run Script (Linux / macOS)
#  Usage:
#    ./docker-run.sh              # Build & start
#    ./docker-run.sh stop         # Stop all containers
#    ./docker-run.sh logs         # View live logs
#    ./docker-run.sh restart      # Restart all services
#    ./docker-run.sh rebuild      # Full rebuild from scratch
#    ./docker-run.sh status       # Show container status
#    ./docker-run.sh shell        # Open shell in server container
# ═══════════════════════════════════════════════════════════

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Docker is not running (or you need sudo).${NC}"
    exit 1
fi

if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    echo -e "${RED}[ERROR] Neither 'docker compose' nor 'docker-compose' found.${NC}"
    exit 1
fi

ensure_env() {
    if [ ! -f .env ]; then
        echo -e "${YELLOW}[!] No .env file found. Creating with defaults...${NC}"
        JWT_SECRET=$(head -c 48 /dev/urandom | base64 | tr -d '\n=+/')
        cat > .env <<EOF
CC_PANEL_PORT=8443
CC_PANEL_PATH=/candyconnect
CC_ADMIN_USER=admin
CC_ADMIN_PASS=admin123
CC_JWT_SECRET=$JWT_SECRET
CC_REDIS_URL=redis://redis:6379/0
EOF
        echo -e "${GREEN}[✓] .env file created${NC}"
    fi
}

panel_port() {
    grep -E '^CC_PANEL_PORT=' .env 2>/dev/null | cut -d= -f2 | tr -d '[:space:]' || true
}

case "${1:-start}" in
    start)
        ensure_env
        echo -e "${CYAN}[i] Building and starting CandyConnect...${NC}"
        $COMPOSE up -d --build
        PORT=$(panel_port); PORT=${PORT:-8443}
        echo ""
        echo -e "${GREEN}[✓] CandyConnect is running!${NC}"
        echo "  Panel:   http://localhost:${PORT}/candyconnect"
        echo "  API:     http://localhost:${PORT}/api"
        echo "  Health:  http://localhost:${PORT}/health"
        echo -e "${YELLOW}  ⚠  Change the default password immediately!${NC}"
        ;;
    stop)    $COMPOSE down ;;
    logs)    $COMPOSE logs -f --tail=100 ;;
    restart) $COMPOSE restart ;;
    rebuild)
        ensure_env
        $COMPOSE down
        $COMPOSE build --no-cache
        $COMPOSE up -d
        ;;
    status)  $COMPOSE ps ;;
    shell)   docker exec -it candyconnect-server /bin/bash ;;
    *)
        echo "Usage: $0 [start|stop|logs|restart|rebuild|status|shell]"
        exit 1
        ;;
esac
