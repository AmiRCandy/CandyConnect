#!/bin/bash
# ═══════════════════════════════════════════════════════════
# CandyConnect - Installation Script
# Deploys server core + web panel on Ubuntu/Debian
# ═══════════════════════════════════════════════════════════


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CC_DIR="/opt/candyconnect"
CC_SERVER_DIR="$CC_DIR/server"
CC_PANEL_DIR="$CC_DIR/web-panel"
CC_SERVICE="candyconnect"
CC_USER="candyconnect"
CC_PORT="${CC_PORT:-8443}"

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

banner() {
    echo -e "${BOLD}${CYAN}"
    echo "  ╔═══════════════════════════════════╗"
    echo "  ║       🍬 CandyConnect VPN 🍬      ║"
    echo "  ║         Installation Script        ║"
    echo "  ╚═══════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "This script must be run as root (use sudo)"
    fi
}

check_os() {
    if ! command -v apt &>/dev/null; then
        err "This installer requires a Debian/Ubuntu system with apt"
    fi
    log "OS check passed"
}

install_nodejs() {
    info "Checking Node.js version..."
    local NEED_INSTALL=false

    if command -v node &>/dev/null; then
        NODE_VER=$(node -v 2>/dev/null | sed 's/v//' | cut -d. -f1)
        if [ "$NODE_VER" -lt 18 ] 2>/dev/null; then
            warn "Node.js version $NODE_VER is too old (need 18+). Upgrading..."
            NEED_INSTALL=true
        else
            log "Node.js $(node -v) is already installed"
        fi
    else
        NEED_INSTALL=true
    fi

    if [ "$NEED_INSTALL" = true ]; then
        info "Installing Node.js 20 from NodeSource..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - || {
            warn "NodeSource setup failed, trying alternative method..."
            apt install -y nodejs npm
        }
        apt install -y nodejs
        log "Node.js $(node -v) installed"
    fi
}

install_dependencies() {
    info "Installing system dependencies..."
    apt update -y
    apt install -y \
        python3 python3-pip python3-venv \
        redis-server \
        curl wget unzip git rsync \
        iptables iproute2 procps \
        sudo \
        ca-certificates gnupg \
        openvpn easy-rsa \
        strongswan strongswan-pki libcharon-extra-plugins \
        xl2tpd wireguard wireguard-tools dante-server \
        openssh-server openssh-client

    # Install Node.js (proper version)
    install_nodejs

    # Install Xray-core
    info "Installing Xray..."
    if ! command -v xray &>/dev/null; then
        bash -c 'curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash -s -- install' || warn "Xray installation failed"
    fi

    # Install DNSTT-server (Robust install with checksum verification)
    info "Installing DNSTT..."
    if [ ! -f "/usr/local/bin/dnstt-server" ]; then
        DURL="https://dnstt.network"
        ARCH=$(uname -m)
        if [ "$ARCH" = "x86_64" ]; then DARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then DARCH="arm64"; else DARCH="386"; fi
        DFILE="dnstt-server-linux-${DARCH}"
        
        info "Downloading DNSTT from ${DURL}/${DFILE}..."
        curl -L -o "/tmp/${DFILE}" "${DURL}/${DFILE}"
        curl -L -s -o "/tmp/SHA256SUMS" "${DURL}/SHA256SUMS"
        
        cd /tmp
        if sha256sum -c <(grep "${DFILE}" SHA256SUMS) 2>/dev/null; then
            mv "/tmp/${DFILE}" "/usr/local/bin/dnstt-server"
            chmod +x "/usr/local/bin/dnstt-server"
            info "DNSTT verified and installed"
        else
            warn "DNSTT checksum verification failed! Attempting insecure install..."
            wget -qO /usr/local/bin/dnstt-server "${DURL}/${DFILE}" || warn "DNSTT download failed"
            chmod +x /usr/local/bin/dnstt-server
        fi
        cd - >/dev/null
    fi

    # Enable and start Redis
    systemctl enable redis-server || true
    systemctl start redis-server || true

    log "Dependencies installed"
}

setup_directories() {
    info "Setting up directories..."
    mkdir -p "$CC_DIR"/{server,web-panel,cores,backups,logs}
    log "Directories created at $CC_DIR"
}

install_server() {
    info "Installing CandyConnect server..."

    # Copy server files
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [ ! -d "$SCRIPT_DIR/server" ]; then
        err "Server source directory not found at $SCRIPT_DIR/server"
    fi

    cp -r "$SCRIPT_DIR/server/"* "$CC_SERVER_DIR/"

    # Create Python virtual environment
    python3 -m venv "$CC_SERVER_DIR/venv"
    source "$CC_SERVER_DIR/venv/bin/activate"
    pip install --upgrade pip
    pip install -r "$CC_SERVER_DIR/requirements.txt"
    deactivate

    log "Server installed"
}

install_panel() {
    info "Building web panel..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [ ! -d "$SCRIPT_DIR/web-panel" ]; then
        err "Web panel source directory not found at $SCRIPT_DIR/web-panel"
    fi

    # Clean old build output so stale files don't persist on rebuild failure
    rm -rf "$CC_PANEL_DIR/dist"

    # Copy web-panel source (exclude node_modules and dist if present)
    rsync -a --delete --exclude='node_modules' --exclude='dist' "$SCRIPT_DIR/web-panel/" "$CC_PANEL_DIR/" 2>/dev/null || \
        cp -r "$SCRIPT_DIR/web-panel/"* "$CC_PANEL_DIR/"

    # Install npm dependencies and build
    cd "$CC_PANEL_DIR"
    npm install --legacy-peer-deps
    npm run build || err "Web panel build failed. Check TypeScript errors above."

    if [ ! -d "$CC_PANEL_DIR/dist" ]; then
        err "Web panel build failed - dist directory not created"
    fi

    log "Web panel built"
}

generate_secrets() {
    info "Generating secrets..."
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")

    # Write env file (only if it doesn't exist, to preserve user customizations)
    if [ -f "$CC_DIR/.env" ]; then
        warn ".env file already exists. Backing up to .env.bak"
        cp "$CC_DIR/.env" "$CC_DIR/.env.bak"
    fi

    cat > "$CC_DIR/.env" << EOF
CC_DATA_DIR=$CC_DIR
CC_REDIS_URL=redis://127.0.0.1:6379/0
CC_JWT_SECRET=$JWT_SECRET
CC_PANEL_PORT=$CC_PORT
CC_PANEL_PATH=/candyconnect
CC_ADMIN_USER=admin
CC_ADMIN_PASS=admin123
EOF

    chmod 600 "$CC_DIR/.env"
    log "Secrets generated"
}

create_systemd_service() {
    info "Creating systemd service..."

    # Stop existing service if running
    if systemctl is-active --quiet "$CC_SERVICE" 2>/dev/null; then
        info "Stopping existing $CC_SERVICE service..."
        systemctl stop "$CC_SERVICE" || true
    fi

    cat > /etc/systemd/system/${CC_SERVICE}.service << 'SERVICEEOF'
[Unit]
Description=CandyConnect VPN Server
After=network.target redis-server.service
Wants=redis-server.service
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=CC_SERVER_DIR_PLACEHOLDER
EnvironmentFile=CC_DIR_PLACEHOLDER/.env
ExecStartPre=/bin/bash -c 'redis-cli ping > /dev/null 2>&1 || sleep 5'
ExecStart=CC_SERVER_DIR_PLACEHOLDER/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port CC_PANEL_PORT_PLACEHOLDER --log-level info
Restart=on-failure
RestartSec=10
StandardOutput=append:CC_DIR_PLACEHOLDER/logs/server.log
StandardError=append:CC_DIR_PLACEHOLDER/logs/server.log

# Security
NoNewPrivileges=false
ProtectSystem=false

[Install]
WantedBy=multi-user.target
SERVICEEOF

    # Replace placeholders with actual paths
    sed -i "s|CC_SERVER_DIR_PLACEHOLDER|$CC_SERVER_DIR|g" /etc/systemd/system/${CC_SERVICE}.service
    sed -i "s|CC_DIR_PLACEHOLDER|$CC_DIR|g" /etc/systemd/system/${CC_SERVICE}.service
    sed -i "s|CC_PANEL_PORT_PLACEHOLDER|$CC_PORT|g" /etc/systemd/system/${CC_SERVICE}.service

    systemctl daemon-reload
    systemctl enable "$CC_SERVICE"
    systemctl start "$CC_SERVICE"

    # Verify the service started
    sleep 3
    if systemctl is-active --quiet "$CC_SERVICE"; then
        log "Service created and started"
    else
        warn "Service may not have started correctly. Check with: journalctl -u $CC_SERVICE -n 50"
    fi
}

setup_firewall() {
    info "Configuring firewall rules..."

    # Allow common VPN ports
    for port in $CC_PORT 443 51820 1194 500 4500 1701 53 8388 9443; do
        iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p tcp --dport $port -j ACCEPT
        iptables -C INPUT -p udp --dport $port -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p udp --dport $port -j ACCEPT
    done

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1
    grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || \
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

    # Try to save iptables rules for persistence
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables.rules 2>/dev/null || true
    fi

    log "Firewall configured"
}

print_summary() {
    # Get server IP
    SERVER_IP=$(curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  🍬 CandyConnect Installed Successfully!${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Panel URL:${NC}    http://${SERVER_IP}:${CC_PORT}/candyconnect"
    echo -e "  ${BOLD}API URL:${NC}      http://${SERVER_IP}:${CC_PORT}/api"
    echo -e "  ${BOLD}Client API:${NC}   http://${SERVER_IP}:${CC_PORT}/client-api"
    echo -e "  ${BOLD}Admin User:${NC}   admin"
    echo -e "  ${BOLD}Admin Pass:${NC}   admin123"
    echo ""
    echo -e "  ${YELLOW}⚠  Change the default password immediately!${NC}"
    echo ""
    echo -e "  ${CYAN}Service commands:${NC}"
    echo -e "    systemctl status ${CC_SERVICE}"
    echo -e "    systemctl restart ${CC_SERVICE}"
    echo -e "    journalctl -u ${CC_SERVICE} -f"
    echo ""
    echo -e "  ${CYAN}Logs:${NC} $CC_DIR/logs/"
    echo -e "  ${CYAN}Config:${NC} $CC_DIR/.env"
    echo ""
}

# ── Main ──

main() {
    banner
    check_root
    check_os
    install_dependencies
    setup_directories
    install_server
    install_panel
    generate_secrets
    setup_firewall
    create_systemd_service
    print_summary
}

main "$@"
