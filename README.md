# 🍬 CandyConnect VPN

---

> # ⚠️ FOR EDUCATIONAL PURPOSES ONLY
> **This project is intended strictly for educational and research purposes. The authors do not condone or support any illegal, unauthorized, or unethical use of this software. Use it only on systems and networks you own or have explicit permission to operate. The authors bear no responsibility for any misuse.**

---

> ## 🚧 BETA SOFTWARE — WORK IN PROGRESS
> This project is currently in **beta**. It is functional but **may contain bugs, incomplete features, and missing options**. Things may break between updates. Features will be added and improved over time. Use in production at your own risk and always keep backups.

---

![License](https://img.shields.io/badge/license-MIT-orange)
![Version](https://img.shields.io/badge/version-1.4.2-blue)
![Platform](https://img.shields.io/badge/platform-Linux-green)
![Status](https://img.shields.io/badge/status-beta-yellow)

---

## 📸 Screenshots

<p align="center">
  <img src="screenshots/dashboard.png" alt="Web Panel Dashboard" />
  &nbsp;&nbsp;
  <img src="screenshots/client.png" alt="CandyConnect Desktop Client" width="48%" />
</p>
<p align="center">
  <em>Web Panel Dashboard &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Desktop Client</em>
</p>

---

## 🍭 Overview

CandyConnect is an all-in-one VPN server management system that supports multiple VPN protocols from a single control plane, with a web admin panel and a cross-platform desktop client.

| Protocol | Engine | Status |
|---|---|---|
| **V2Ray / Xray** | VLESS, VMess, Trojan, Shadowsocks | ✅ Full |
| **WireGuard** | Native kernel module | ✅ Full |
| **OpenVPN** | OpenVPN + Easy-RSA PKI | ✅ Full |
| **IKEv2/IPSec** | strongSwan | ✅ Full |
| **L2TP/IPSec** | xl2tpd + strongSwan | ✅ Full |
| **DNSTT** | DNS-over-UDP tunnel | ✅ Full |
| **SlipStream** | DNS tunnel over QUIC ([slipstream](https://github.com/EndPositive/slipstream)) | ✅ Server (Ubuntu 22.04+) · Linux client |
| **TrustTunnel** | HTTP/2 & QUIC VPN ([TrustTunnel](https://github.com/TrustTunnel/TrustTunnel)) | ✅ Full (`tt://` links) |

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                  CandyConnect Server                │
│                                                     │
│  ┌───────────┐  ┌───────────┐  ┌─────────────────┐ │
│  │ Panel API │  │Client API │  │Protocol Managers│ │
│  │  /api/*   │  │/client-   │  │ WG · V2Ray · OV │ │
│  │           │  │  api/*    │  │ IKE · L2TP · DNS│ │
│  └─────┬─────┘  └─────┬─────┘  └────────┬────────┘ │
│        │              │                  │          │
│        └──────────────┘                  │          │
│              │                           │          │
│       ┌──────┴──────┐          ┌─────────┴────────┐ │
│       │   FastAPI   │          │  System Cores    │ │
│       │   + Redis   │          │ (installed on    │ │
│       │   + JWT     │          │  the server)     │ │
│       └─────────────┘          └──────────────────┘ │
└──────────────────────────────────────────────────────┘
        │                              │
        ▼                              ▼
┌───────────────┐            ┌──────────────────┐
│   Web Panel   │            │  Desktop Client  │
│ (React+Vite)  │            │ (Tauri+React)    │
└───────────────┘            └──────────────────┘
```

---

## 🚀 Quick Installation

### Requirements

- **OS:** Ubuntu 20.04+ / Debian 11+ (x86_64)
- **RAM:** Minimum 1 GB (2 GB recommended)
- **Disk:** Minimum 5 GB free space
- **Access:** Root privileges
- **Ports:** 8443 (panel), plus VPN protocol ports

### Management Menu (Recommended)

Run the interactive menu to install, uninstall, or check the status:

```bash
git clone https://github.com/AmiRCandy/CandyConnect.git
cd CandyConnect
sudo bash menu.sh
```

The installer will:
1. Install system dependencies (Python, Redis, Node.js)
2. Set up the Python backend with virtual environment
3. Build the web panel frontend
4. Generate JWT secrets
5. Configure firewall rules & IP forwarding
6. Create and start a systemd service

### Post-Installation

After installation completes, you'll see:

```
✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅
  🍬 CandyConnect Installed Successfully!
✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅

  Panel URL:    http://<SERVER_IP>:8443/candyconnect
  API URL:      http://<SERVER_IP>:8443/api
  Client API:   http://<SERVER_IP>:8443/client-api
  Admin User:   admin
  Admin Pass:   admin123

  ⚠️  Change the default password immediately!
```

---

## 🌐 Web Panel

The admin web panel provides full server management:

- **Dashboard** — Server resources, VPN core status, active connections per protocol, real traffic stats, live logs
- **Clients** — Create, edit, delete VPN users with per-protocol access control, traffic limits, time limits, and connection history
- **Core Configs** — Configure each VPN protocol (ports, ciphers, keys, interfaces, DNS, etc.)
- **Panel Configs** — Change panel port/path (saved to `/opt/candyconnect/.env`, applied on panel restart), admin password, view server info
- **Tunnels** — Relay servers via [Backhaul](https://github.com/Musixal/Backhaul): give the relay's SSH login and CandyConnect installs the relay, runs the tunnel client here, and adds "via relay" V2Ray configs for users

### Access

Open `http://<SERVER_IP>:8443/candyconnect` in your browser (or the port/path you configured).

> **Docker:** the panel port is the one published by `docker-compose.yml` (`CC_PANEL_PORT` in the project's `.env`); changing it from the panel has no effect inside the container.

Default credentials:
- **Username:** `admin`
- **Password:** `admin123`

---

## 💻 Desktop Client

The CandyConnect desktop client (built with Tauri + React) connects to the server backend and provides a native VPN experience on Windows, macOS, and Linux.

### Supported Client Protocols

| Protocol | TUN Mode | Proxy Mode |
|---|---|---|
| V2Ray (VLESS/VMess/Trojan) | ✅ via sing-box | ✅ via Xray SOCKS |
| WireGuard | ✅ via sing-box | ✅ via sing-box |
| OpenVPN | ✅ Native | — |
| IKEv2 | ✅ Native | — |
| L2TP | ✅ Native | — |
| DNSTT | ✅ via tunnel | ✅ SOCKS (built-in SSH) |
| SlipStream | ✅ via tunnel (Linux) | ✅ SOCKS (Linux) |
| TrustTunnel | ✅ via TrustTunnel client | — (or import the `tt://` link in the TrustTunnel app) |

**Proxy mode** sets the system proxy (Windows / macOS / GNOME & KDE) while connected and restores it on disconnect.

### How It Works

1. User enters the server address (e.g., `http://your-server:8443`)
2. Logs in with their client username/password (created via the web panel)
3. The client fetches available VPN protocols and connection configs
4. User selects a protocol and mode (TUN/Proxy) and connects
5. Real-time speed and traffic stats are shown — **only VPN interface traffic is counted** (not general system traffic)

### Building the Client

```bash
cd client
npm install
npm run dev          # Development mode
npm run build        # Production build (Tauri)
```

> **Note:** Building the Tauri desktop app requires Rust and platform-specific dependencies. See [Tauri Prerequisites](https://v2.tauri.app/start/prerequisites/).

---

## 🖥 Server Management

### Service Commands

```bash
# Check status
sudo systemctl status candyconnect

# Restart
sudo systemctl restart candyconnect

# View live logs
sudo journalctl -u candyconnect -f

# Stop
sudo systemctl stop candyconnect
```

### Configuration

Server configuration is stored in `/opt/candyconnect/.env`:

```env
CC_DATA_DIR=/opt/candyconnect
CC_REDIS_URL=redis://127.0.0.1:6379/0
CC_JWT_SECRET=<auto-generated>
CC_PANEL_PORT=8443
CC_PANEL_PATH=/candyconnect
CC_ADMIN_USER=admin
CC_ADMIN_PASS=admin123
```

### File Structure

```
/opt/candyconnect/
├── server/          # Python backend
│   ├── main.py      # FastAPI application
│   ├── config.py    # Configuration
│   ├── database.py  # Redis data layer
│   ├── auth.py      # JWT authentication
│   ├── system_info.py
│   ├── protocols/   # VPN protocol managers
│   │   ├── base.py
│   │   ├── wireguard.py
│   │   ├── v2ray.py
│   │   ├── openvpn.py
│   │   ├── ikev2.py
│   │   ├── l2tp.py
│   │   ├── dnstt.py
│   │   └── manager.py
│   └── routes/      # API endpoints
│       ├── panel_api.py    # Web panel API
│       └── client_api.py   # Desktop client API
├── web-panel/       # React admin panel (built)
└── cores/           # VPN binaries (auto-installed)
    ├── xray/
    └── sing-box/
```

---

## 🔧 Troubleshooting

### Checking Protocol Status

```bash
# WireGuard
sudo wg show

# Xray
sudo /opt/candyconnect/cores/xray/xray run -c /opt/candyconnect/cores/xray/config.json

# IKEv2/IPSec
sudo ipsec statusall
sudo swanctl --list-conns

# OpenVPN
sudo tail -f /var/log/openvpn/openvpn-status.log

# L2TP
sudo journalctl -u xl2tpd -f

# DNSTT
ps aux | grep dnstt-server
```

### ⚙️ Manual Service Control

```bash
# WireGuard interface
sudo wg-quick down wg0
sudo wg-quick up wg0

# IPSec (IKEv2/L2TP)
sudo systemctl restart strongswan-starter

# L2TP Daemon
sudo systemctl restart xl2tpd

# SSH (for DNSTT tunnels)
sudo systemctl restart ssh
```

### 🆘 Emergency Port Release

If a protocol fails to start because "Port is already in use":
```bash
sudo lsof -i :<PORT_NUMBER>
# or
sudo netstat -tulpn | grep :<PORT_NUMBER>
```

---

## 🔒 VPN Protocol Setup

After installation, VPN protocols need to be installed and started via the web panel or API:

### Via Web Panel

1. Go to **Core Configs**
2. Configure each protocol's settings
3. Click **Save Config**
4. Use the **Restart Service** button (or install first if not yet installed)

### Via API

```bash
TOKEN="your-admin-jwt-token"
SERVER="http://your-server:8443"

# Install & start all protocols
for proto in v2ray wireguard openvpn ikev2 l2tp dnstt; do
  curl -X POST "$SERVER/api/cores/$proto/install" -H "Authorization: Bearer $TOKEN"
  curl -X POST "$SERVER/api/cores/$proto/start" -H "Authorization: Bearer $TOKEN"
done
```

---

## 🌐 DNSTT Setup (DNS Tunnel)

DNSTT allows VPN traffic to be tunneled over DNS queries, bypassing most firewalls. It requires you to own a domain and configure two DNS records.

### DNS Records Required

You must add the following records to your domain's DNS settings:

| Type | Name | Value | Purpose |
|---|---|---|---|
| **A** | `srv.YOURDOMAIN.COM` | `YOUR_SERVER_IP` | Points to your CandyConnect server |
| **NS** | `dns.YOURDOMAIN.COM` | `srv.YOURDOMAIN.COM` | Delegates DNS queries to your server |

**Example** (domain: `example.com`, server IP: `1.2.3.4`):

```
A     srv.example.com   →   1.2.3.4
NS    dns.example.com   →   srv.example.com
```

### How It Works

1. The client sends DNS queries to `dns.YOURDOMAIN.COM`
2. The NS record delegates those queries to `srv.YOURDOMAIN.COM` (your server)
3. Your server's DNSTT daemon handles the queries and tunnels VPN traffic through them
4. Traffic appears as normal DNS UDP port 53 traffic — bypasses most deep packet inspection

### DNSTT Configuration in Web Panel

1. Go to **Core Configs → DNSTT**
2. Set **DNS Zone** to `dns.YOURDOMAIN.COM`
3. Set **Listen Port** (default: `5300` for DNS; port 53 requires root)
4. Save and start the DNSTT core

> **Note:** Propagation of DNS records can take up to 24–48 hours depending on your registrar's TTL settings. Test with `dig NS dns.yourdomain.com` to confirm.

---

## 💨 SlipStream Setup (DNS tunnel over QUIC)

SlipStream works like DNSTT (same SSH accounts) but uses QUIC, which is usually much faster.
Use a **different subdomain** than DNSTT: both share UDP port 53 and the server routes
queries to the right daemon by domain name.

```
A     srv.example.com   →   1.2.3.4
NS    s.example.com     →   srv.example.com
```

1. Go to **Core Configs → SlipStream**, set **Domain** to `s.example.com` and save
2. Start the SlipStream core (the server downloads `slipstream-server` automatically; needs Ubuntu 22.04+ / Debian 12+)

## 🏰 TrustTunnel Setup

1. Go to **Core Configs → TrustTunnel**, set the port (default `9443`) and the TLS hostname.
   Leave the certificate paths empty to use an automatic self-signed certificate (it is embedded in the client links).
2. Start the TrustTunnel core. Each user enabled for TrustTunnel gets a `tt://` link in the desktop client,
   which also works in the official TrustTunnel apps (Android / iOS / macOS).

## 🔀 Relay Tunnels (Backhaul)

If users can reach a relay server (e.g. a domestic server) but not this server directly:

1. Go to **Tunnels → Add**, enter the relay's IP and SSH login (root or a sudo user).
2. CandyConnect installs the Backhaul server on the relay over SSH, starts the Backhaul client here
   and forwards the VPN TCP ports (all V2Ray inbounds by default).
3. Users automatically get extra V2Ray configs named "... (via &lt;relay&gt;)" that connect to the relay IP.

Without a password the panel shows an install script to run on the relay as root.

---

## 👥 Client Management

### Creating a Client

Via the web panel:
1. Go to **Clients** → **Add Client**
2. Set username, password, traffic limit, time limit
3. Select which VPN protocols the client can access
4. Click **Create**

Via API:
```bash
curl -X POST "$SERVER/api/clients" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "password": "SecurePass123!",
    "comment": "John Doe",
    "enabled": true,
    "traffic_limit": {"value": 50, "unit": "GB"},
    "time_limit": {"mode": "days", "value": 30, "on_hold": false},
    "protocols": {
      "v2ray": true, "wireguard": true, "openvpn": true,
      "ikev2": true, "l2tp": false, "dnstt": false,
      "slipstream": false, "trusttunnel": false
    }
  }'
```

### Client Features

- **Traffic Limits** — Per-client data caps in GB or MB
- **Time Limits** — Expiry in days or months
- **On Hold** — Pause a client's timer without deleting them
- **Per-Protocol Access** — Enable/disable individual VPN protocols per client
- **Real Traffic Tracking** — Per-protocol usage tracking (client-reported + server-measured)
- **Active Connections** — Real-time connection count per protocol in the dashboard
- **Connection History** — IP, protocol, duration logging

---

## 🛠 Development

### Project Structure

```
CandyConnect/
├── server/              # Python FastAPI backend
├── web-panel/           # React + Vite + Tailwind admin panel
├── client/              # Tauri + React desktop VPN client
│   └── src-tauri/src/   # Rust backend (Tauri commands, VPN launching)
├── install.sh           # Deployment script
├── menu.sh              # Interactive management menu
└── README.md
```

### Running in Development

**Server:**
```bash
cd server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# Requires Redis running locally
python main.py
```

**Web Panel:**
```bash
cd web-panel
npm install
npm run dev
# Opens at http://localhost:5174
# Proxies /api to http://127.0.0.1:8443
```

**Client:**
```bash
cd client
npm install
npm run dev
```

### Tech Stack

| Component | Technology |
|---|---|
| **Server** | Python 3.10+, FastAPI, Redis, JWT |
| **Web Panel** | React 18, Vite, Tailwind CSS, Lucide Icons |
| **Client** | React 19, Tauri 2, TypeScript, Vite |
| **Client Backend** | Rust (Tauri), sing-box, Xray |
| **Database** | Redis |
| **Auth** | JWT (separate admin/client tokens) |

---

## 🔒 Security Notes

- **Change the default admin password** immediately after installation
- All API endpoints are JWT-protected
- Client passwords are stored in Redis (consider encryption for production)
- Admin password is bcrypt-hashed
- Use HTTPS in production (configure SSL in CandyConnect settings)
- Firewall rules are auto-configured during installation
- This software is for **educational use only** — see disclaimer at top

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

---

## 📋 Roadmap / TODO

These are the features and improvements planned for future releases. Contributions toward any of these are especially welcome!

| Status | Feature | Description |
|---|---|---|
| 🔜 | **SSL for Web Panel** | Built-in Let's Encrypt / self-signed SSL support for the admin panel, no manual nginx/caddy setup required |
| 🔜 | **Xray CDN Configs** | Auto-generate CDN-fronted configs (Cloudflare, ArvanCloud, etc.) for VLESS/VMess over WebSocket with TLS |
| 🔜 | **Psiphon Protocol** | Integrate Psiphon as a supported tunnel protocol for censorship circumvention |
| 🔜 | **Auto Tunneling** | Automatic best-protocol selection and fallback — the client tries protocols in order and switches seamlessly if one is blocked |
| 🔜 | **Paqet Protocol** | Full Paqet protocol support as a tunneling backend |
| 🔜 | **WARP Protocol** | Cloudflare WARP / WireGuard+WARP integration as a connectable protocol |
| 🔜 | **iOS Client** | Native iOS client app (Swift/Tauri mobile) connecting to the CandyConnect backend |
| 🔜 | **Android Client** | Native Android client app connecting to the CandyConnect backend |
| 🔜 | **SlipStream Protocol** | Complete SlipStream protocol implementation and integration |
| 🔜 | **TrustTunnel Protocol** | Complete TrustTunnel protocol implementation and integration |

> 💡 Have a feature idea not on this list? Open an issue or pull request — contributions are always welcome!

---

## 🙏 Acknowledgements & Credits

CandyConnect would not exist without the incredible open-source projects that power it under the hood. Huge respect and gratitude to the teams and communities behind:

---

### ⚡ [Xray-core](https://github.com/XTLS/Xray-core)
The heart of the V2Ray engine in CandyConnect. Xray is a powerful, high-performance proxy platform supporting VLESS, VMess, Trojan, Shadowsocks and more — with cutting-edge features like XTLS and Reality. The XTLS team has pushed the boundaries of what's possible in censorship circumvention.

> *"Xray, Penetrates Everything."*

---

### 📦 [sing-box](https://github.com/SagerNet/sing-box)
The universal proxy platform that powers CandyConnect's TUN mode on the desktop client. sing-box handles WireGuard-over-TUN, DNS routing, and transparent proxying with remarkable efficiency. A masterpiece of modern network engineering.

> *"The universal proxy platform."*

---

### 🔒 [WireGuard](https://www.wireguard.com/)
The modern VPN protocol that redefined simplicity and security. WireGuard's clean codebase (~4,000 lines vs OpenVPN's ~100,000) and state-of-the-art cryptography (ChaCha20, Poly1305, Curve25519) make it the gold standard for fast, secure tunneling.

> *"WireGuard: fast, modern, secure VPN tunnel."* — Jason A. Donenfeld

---

### 🛡️ [OpenVPN](https://openvpn.net/)
The battle-tested VPN solution that has been securing networks for over two decades. OpenVPN's flexibility, wide platform support, and robust PKI infrastructure make it indispensable for enterprise and personal use alike.

> *"The world's most widely deployed open source VPN."*

---

### 🌐 [dnstt](https://www.bamsoftware.com/software/dnstt/)
The ingenious DNS tunnel tool by Dan Ayers (bamsoftware) that makes it possible to tunnel traffic over DNS queries — one of the few techniques that bypasses even the most aggressive firewalls. A remarkable piece of engineering for those who need it most.

> *"A DNS tunnel that actually works."*

---

*These projects are maintained by talented developers who give their time and expertise to the community for free. Please consider supporting them directly.*

---

<p align="center">
  Made with 🍬 by <a href="https://github.com/AmiRCandy">AmiRCandy</a>
</p>
