#!/bin/bash
# ═══════════════════════════════════════════════════════════
# CandyConnect - Management Menu
# ═══════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CC_DIR="/opt/candyconnect"
CC_SERVICE="candyconnect"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Helpers ──

clear_screen() {
    clear
}

banner() {
    echo -e "${BOLD}${CYAN}"
    echo "  ╔═══════════════════════════════════╗"
    echo "  ║       🍬 CandyConnect VPN 🍬      ║"
    echo "  ║          Management Menu          ║"
    echo "  ╚═══════════════════════════════════╝"
    echo -e "${NC}"
}

check_install_status() {
    if [ -d "$CC_DIR" ] && systemctl list-unit-files 2>/dev/null | grep -q "^$CC_SERVICE.service"; then
        echo -e "Status: ${GREEN}${BOLD}INSTALLED${NC}"
        return 0
    else
        echo -e "Status: ${RED}${BOLD}NOT INSTALLED${NC}"
        return 1
    fi
}

show_menu() {
    banner
    check_install_status
    echo ""
    echo -e "  ${BOLD}1.${NC} ${CYAN}Install CandyConnect${NC}"
    echo -e "  ${BOLD}2.${NC} ${RED}Uninstall CandyConnect${NC}"
    echo -e "  ${BOLD}3.${NC} Exit"
    echo ""
    echo -n "Choose an option [1-3]: "
}

# ── Functions ──

install_cc() {
    if [ -f "$SCRIPT_DIR/install.sh" ]; then
        bash "$SCRIPT_DIR/install.sh"
    else
        echo -e "${RED}[✗] Error: install.sh not found in $SCRIPT_DIR.${NC}"
    fi
}

uninstall_cc() {
    echo -e "${YELLOW}[!] Warning: This will completely remove CandyConnect, its configs, and all data.${NC}"
    read -p "Are you sure you want to proceed? (y/n): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        echo -e "${CYAN}[i] Stopping and disabling service...${NC}"
        systemctl stop "$CC_SERVICE" 2>/dev/null
        systemctl disable "$CC_SERVICE" 2>/dev/null
        
        echo -e "${CYAN}[i] Stopping active VPN sessions...${NC}"
        systemctl stop "wg-quick@*" 2>/dev/null
        systemctl stop "openvpn-server@*" 2>/dev/null
        systemctl stop "strongswan-starter" 2>/dev/null
        systemctl stop "xl2tpd" 2>/dev/null
        # Force kill any lingering processes
        pkill -f "dnstt-server" || true
        pkill -f "slipstream-server" || true
        pkill -f "trusttunnel_endpoint" || true
        pkill -f "/opt/candyconnect/cores/backhaul/backhaul" || true
        pkill -x "xray" || true
        wg-quick down wg0 2>/dev/null || true
        rm -f /etc/wireguard/wg0.conf
        
        echo -e "${CYAN}[i] Removing service files...${NC}"
        rm -f "/etc/systemd/system/$CC_SERVICE.service"
        systemctl daemon-reload
        
        echo -e "${CYAN}[i] Removing installation directory...${NC}"
        rm -rf "$CC_DIR"
        
        echo -e "${CYAN}[i] Removing protocol binaries...${NC}"
        rm -f "/usr/local/bin/dnstt-server" "/usr/local/bin/slipstream-server"
        rm -rf /opt/trusttunnel
        rm -f /etc/ssh/sshd_config.d/candyconnect-dnstt.conf
        rm -f "/usr/local/bin/xray"

        read -p "Do you also want to remove installed packages (wireguard, openvpn, strongswan, etc)? (y/n): " remove_pkgs
        if [[ "$remove_pkgs" == "y" || "$remove_pkgs" == "Y" ]]; then
            echo -e "${CYAN}[i] Removing installed packages...${NC}"
            apt remove -y wireguard wireguard-tools openvpn easy-rsa strongswan strongswan-pki xl2tpd dante-server redis-server nodejs
            apt autoremove -y
        fi
        
        echo -e "${GREEN}[✓] CandyConnect has been completely uninstalled.${NC}"
    else
        echo -e "${CYAN}[i] Uninstall cancelled.${NC}"
    fi
}

# ── Main ──

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[✗] This script must be run as root (use sudo)${NC}"
    exit 1
fi

while true; do
    clear_screen
    show_menu
    read choice
    
    case $choice in
        1)
            install_cc
            echo -e "\nPress enter to return to menu..."
            read
            ;;
        2)
            uninstall_cc
            echo -e "\nPress enter to return to menu..."
            read
            ;;
        3)
            echo -e "${CYAN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option.${NC}"
            sleep 1
            ;;
    esac
done
