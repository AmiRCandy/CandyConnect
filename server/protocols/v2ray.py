"""
CandyConnect - V2Ray/Xray Protocol Manager
"""
import asyncio, os, json, uuid, time
from protocols.base import BaseProtocol
from database import get_core_config, get_core_status, set_core_status, add_log, update_core_config
from config import CORE_DIR


class V2RayProtocol(BaseProtocol):
    PROTOCOL_ID = "v2ray"
    PROTOCOL_NAME = "V2Ray"
    DEFAULT_PORT = 443

    XRAY_DIR = os.path.join(CORE_DIR, "xray")
    XRAY_BIN = os.path.join(CORE_DIR, "xray", "xray")
    XRAY_CONF = os.path.join(CORE_DIR, "xray", "config.json")

    async def install(self) -> bool:
        try:
            await add_log("INFO", self.PROTOCOL_NAME, "Checking for Xray...")
            os.makedirs(self.XRAY_DIR, exist_ok=True)

            # 1. Check if already installed
            for path in ["xray", "/usr/bin/xray", "/usr/local/bin/xray", self.XRAY_BIN]:
                if await self._is_installed(path) or os.path.exists(path):
                    await add_log("INFO", self.PROTOCOL_NAME, f"Xray found at {path}")
                    return True

            # 2. If not found, try quick install without apt update (assume dependencies met)
            await add_log("INFO", self.PROTOCOL_NAME, "Xray not found, attempting fast install...")
            rc, _, err = await self._run_cmd(
                "bash -c 'curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | sudo bash -s -- install'",
                check=False,
                timeout=120,
            )
            if rc == 0:
                await add_log("INFO", self.PROTOCOL_NAME, "Xray installed successfully")
                return True
                
            await add_log("ERROR", self.PROTOCOL_NAME, f"Installation failed (no apt update): {err}")
            return False
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Installation error: {e}")
            return False

    async def start(self) -> bool:
        try:
            config = await get_core_config("v2ray")
            if not config:
                await add_log("ERROR", self.PROTOCOL_NAME, "No V2Ray config found")
                return False

            os.makedirs(self.XRAY_DIR, exist_ok=True)

            # Write config file
            config_json = config.get("config_json", "{}")
            with open(self.XRAY_CONF, "w") as f:
                f.write(config_json)

            # Find xray binary
            xray_bin = self.XRAY_BIN
            if not os.path.exists(xray_bin):
                # Try system-wide
                rc, path, _ = await self._run_cmd("which xray", check=False)
                if rc == 0 and path:
                    xray_bin = path.strip()
                else:
                    await add_log("ERROR", self.PROTOCOL_NAME, "Xray binary not found. Run install first.")
                    return False

            pid = await self._start_process(
                f"{xray_bin} run -c {self.XRAY_CONF}",
                cwd=self.XRAY_DIR,
            )
            if not pid:
                await add_log("ERROR", self.PROTOCOL_NAME, "Failed to start Xray")
                return False

            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to start: {e}")
            return False

    async def get_version(self) -> str:
        for bin_path in [self.XRAY_BIN, "xray", "/usr/local/bin/xray"]:
            rc, out, _ = await self._run_cmd(f"{bin_path} version", check=False)
            if rc == 0 and out:
                # "Xray 1.8.24 ..."
                parts = out.split()
                if len(parts) >= 2:
                    return parts[1]
        return ""

    async def get_active_connections(self) -> int:
        """Count active connections through Xray/V2Ray.

        Strategy:
        1. Try the Xray gRPC stats API (if the StatsService is enabled in config).
        2. Fall back to counting established TCP connections to Xray's inbound ports
           via 'ss' (avoiding the pipe-to-grep exit-code issue).
        """
        # Strategy 1: check xray StatsService via grpcurl / xray api (if available)
        try:
            config = await get_core_config("v2ray")
            if config:
                config_obj = json.loads(config.get("config_json", "{}"))
                api_cfg = config_obj.get("api", {})
                if api_cfg.get("services") and "StatsService" in api_cfg.get("services", []):
                    api_port = None
                    for inbound in config_obj.get("inbounds", []):
                        if inbound.get("tag") == "api" or inbound.get("protocol") == "dokodemo-door":
                            api_port = inbound.get("port")
                            break
                    if api_port:
                        rc, out, _ = await self._run_cmd(
                            f"xray api statsquery --server=127.0.0.1:{api_port} 2>/dev/null | python3 -c \"import sys,json; d=json.load(sys.stdin); print(sum(1 for s in d.get('stat',[]) if 'user' in s.get('name','') and 'traffic' in s.get('name','') and s.get('value',0)>0))\" 2>/dev/null",
                            check=False,
                        )
                        if rc == 0 and out.strip().isdigit():
                            return int(out.strip())
        except Exception:
            pass

        # Strategy 2: count ESTABLISHED connections on Xray's inbound ports
        try:
            config = await get_core_config("v2ray")
            inbound_ports = []
            if config:
                config_obj = json.loads(config.get("config_json", "{}"))
                for inbound in config_obj.get("inbounds", []):
                    port = inbound.get("port")
                    if port and inbound.get("protocol") not in ("dokodemo-door",):
                        inbound_ports.append(str(port))

            if inbound_ports:
                port_filter = " or ".join(f"sport = :{p}" for p in inbound_ports)
                rc, out, _ = await self._run_cmd(
                    f"ss -tn state established '( {port_filter} )' 2>/dev/null",
                    check=False,
                )
                if rc == 0:
                    lines = [l for l in out.splitlines() if l.strip() and not l.startswith("Netid")]
                    return len(lines)
        except Exception:
            pass

        # Strategy 3: fall back to counting via PID
        status = await get_core_status(self.PROTOCOL_ID)
        pid = status.get("pid")
        if not pid:
            return 0
        rc, out, _ = await self._run_cmd(
            f"ss -tnp 2>/dev/null | grep 'pid={pid}'",
            check=False,
        )
        if rc == 0 and out:
            lines = [l for l in out.splitlines() if "ESTAB" in l]
            return len(lines)
        return 0

    async def sync_clients(self, clients: list) -> None:
        """Re-add every V2Ray-enabled client to the config with a single restart
        (used after the admin replaces the config JSON in the panel)."""
        for c in clients:
            if c.get("enabled", True) and (c.get("protocols") or {}).get("v2ray"):
                await self.add_client(c["username"], c, restart=False)
        if await self.is_running():
            await self.restart()

    async def add_client(self, username: str, client_data: dict, restart: bool = True) -> dict:
        """Add a client to V2Ray config (generates UUID for VLESS/VMess)."""
        client_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, username))
        password = client_data.get("password") or username
        email = f"{username}@candyconnect"
        result = {"uuid": client_uuid, "password": password}

        config = await get_core_config("v2ray")
        if not config:
            return result

        try:
            config_obj = json.loads(config.get("config_json", "{}"))
            before = json.dumps(config_obj, sort_keys=True)
            # Add client to all inbound protocols
            for inbound in config_obj.get("inbounds", []):
                proto = inbound.get("protocol", "")
                if proto not in ("vless", "vmess", "trojan"):
                    # Shadowsocks uses a single server-wide password; api/dokodemo have no users
                    continue
                settings = inbound.get("settings")
                if not isinstance(settings, dict):
                    settings = inbound["settings"] = {}
                clients = settings.get("clients")
                if not isinstance(clients, list):
                    clients = settings["clients"] = []

                if proto in ("vless", "vmess"):
                    if not any(c.get("id") == client_uuid for c in clients):
                        client_entry = {"id": client_uuid, "email": email}
                        if proto == "vless":
                            client_entry["flow"] = ""
                        clients.append(client_entry)
                else:  # trojan: replace entry so password changes are applied
                    settings["clients"] = [c for c in clients if c.get("email") != email]
                    settings["clients"].append({"password": password, "email": email})

            if json.dumps(config_obj, sort_keys=True) != before:
                config["config_json"] = json.dumps(config_obj, indent=2)
                await update_core_config("v2ray", config)

                # Restart if running to apply changes
                if restart and await self.is_running():
                    await self.restart()

        except json.JSONDecodeError:
            pass

        return result

    async def remove_client(self, username: str, protocol_data: dict):
        client_uuid = protocol_data.get("uuid") or str(uuid.uuid5(uuid.NAMESPACE_DNS, username))
        config = await get_core_config("v2ray")
        if not config:
            return

        try:
            config_obj = json.loads(config.get("config_json", "{}"))
            for inbound in config_obj.get("inbounds", []):
                settings = inbound.get("settings", {})
                clients = settings.get("clients", [])
                settings["clients"] = [
                    c for c in clients
                    if c.get("id") != client_uuid and c.get("email") != f"{username}@candyconnect"
                ]
            config["config_json"] = json.dumps(config_obj, indent=2)
            await update_core_config("v2ray", config)
            if await self.is_running():
                await self.restart()
        except json.JSONDecodeError:
            pass

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        client_uuid = protocol_data.get("uuid") or str(uuid.uuid5(uuid.NAMESPACE_DNS, username))
        config = await get_core_config("v2ray")
        if not config:
            return {}

        # A bare core id means "any inbound"
        if config_id and config_id.lower() in ("v2ray", "v2ray-basic", "xray"):
            config_id = None

        outbounds = []
        try:
            config_obj = json.loads(config.get("config_json", "{}"))
            # Prefer an exact tag match ("vless-tcp-tls" must not resolve to "vless-tcp")
            if config_id:
                wanted = {config_id.lower(), config_id.lower()[6:] if config_id.lower().startswith("v2ray-") else config_id.lower()}
                exact = [ib for ib in config_obj.get("inbounds", [])
                         if str(ib.get("tag", "")).lower() in wanted]
                if exact:
                    config_obj["inbounds"] = exact
            for inbound in config_obj.get("inbounds", []):
                proto = inbound.get("protocol", "")
                if proto not in ("vless", "vmess", "trojan", "shadowsocks"):
                    continue
                
                port = inbound.get("port", 443)
                stream = inbound.get("streamSettings", {})
                network = stream.get("network", "tcp")
                security = stream.get("security", "none")
                inbound_tag = inbound.get("tag", f"{proto}-{network}")

                # If a specific config_id was requested, filter to only the matching inbound
                if config_id:
                    # Match by tag directly, or by constructed name patterns
                    # e.g. config_id="vless-tcp-xtls" should match tag="vless-tcp-xtls"
                    # also handle cases like config_id="v2ray-vless-tcp" matching tag="vless-tcp"
                    config_id_lower = config_id.lower()
                    tag_lower = inbound_tag.lower()
                    
                    # Strip "v2ray-" prefix if present in config_id
                    normalized_id = config_id_lower
                    if normalized_id.startswith("v2ray-"):
                        normalized_id = normalized_id[6:]
                    
                    # Check if this inbound matches the requested config
                    if (tag_lower != config_id_lower and 
                        tag_lower != normalized_id and
                        not config_id_lower.startswith(tag_lower) and
                        not tag_lower.startswith(normalized_id)):
                        continue
                
                # Build client outbound
                user = {"id": client_uuid, "encryption": "none", "level": 0}
                if proto == "vmess":
                    user = {"id": client_uuid, "alterId": 0, "security": "auto", "level": 0}
                elif proto == "vless":
                    # Use the same flow the server has for this user (empty = no flow).
                    # Forcing xtls-rprx-vision when the server has none breaks the connection.
                    inbound_clients = inbound.get("settings", {}).get("clients", []) or []
                    me = next((c for c in inbound_clients if c.get("id") == client_uuid), None)
                    flow = (me or {}).get("flow") or ""
                    if flow:
                        user["flow"] = flow

                outbound = {
                    "protocol": proto,
                    "settings": {
                        "vnext": [{
                            "address": server_ip,
                            "port": port,
                            "users": [user]
                        }]
                    },
                    "streamSettings": self._client_stream_settings(stream),
                    "tag": "proxy",
                    "_inbound_tag": inbound_tag,
                }

                if proto == "trojan":
                    outbound["settings"] = {
                        "servers": [{
                            "address": server_ip,
                            "port": port,
                            "password": protocol_data.get("password") or username,
                        }]
                    }
                
                elif proto == "shadowsocks":
                    ss = inbound.get("settings", {})
                    outbound["settings"] = {
                        "servers": [{
                            "address": server_ip,
                            "port": port,
                            "method": ss.get("method", "aes-256-gcm"),
                            "password": ss.get("password", ""),
                        }]
                    }

                outbounds.append(outbound)
                
                # If filtering by config_id, we found our match — stop looking
                if config_id:
                    break
        except json.JSONDecodeError:
            pass

        # If config_id was specified but nothing matched, return empty
        if config_id and not outbounds:
            return {}

        # Create a full Xray client config structure
        # When a specific config is selected, use only that single outbound
        client_json = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "port": 10808,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True}
                },
                {
                    "port": 10809,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {}
                }
            ],
            "outbounds": outbounds + [{"protocol": "freedom", "tag": "direct"}],
            "routing": {
                "domainStrategy": "AsIs",
                # Plain CIDRs instead of geoip:/geosite: so the client works without geo*.dat files
                "rules": [
                    {"type": "field", "outboundTag": "direct", "ip": [
                        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
                    ]},
                ]
            }
        }

        # Extract sub-protocols for the client UI
        sub_protocols = []
        for outbound in outbounds:
            proto = outbound.get("protocol", "")
            if proto in ("vless", "vmess", "trojan", "shadowsocks"):
                port = 443
                if "settings" in outbound:
                    vnext = outbound["settings"].get("vnext", [])
                    if vnext: port = vnext[0].get("port", port)
                    servers = outbound["settings"].get("servers", [])
                    if servers: port = servers[0].get("port", port)
                
                stream = outbound.get("streamSettings", {})
                sub_protocols.append({
                    "tag": outbound.pop("_inbound_tag", None) or f"{proto}-{port}",
                    "protocol": proto,
                    "transport": stream.get("network", "tcp"),
                    "security": stream.get("security", "none"),
                    "port": port
                })

        return {
            "type": "v2ray",
            "server": server_ip,
            "uuid": client_uuid,
            "config_json": client_json,
            "sub_protocols": sub_protocols,
        }

    @staticmethod
    def _client_stream_settings(stream: dict) -> dict:
        """Convert server-side streamSettings to client-side ones.

        The server's tlsSettings/realitySettings contain certificate file paths and
        private keys that don't exist (and must not leak) on the client.
        """
        client = {k: v for k, v in (stream or {}).items()
                  if k not in ("tlsSettings", "realitySettings", "xtlsSettings", "sockopt")}
        security = client.get("security", "none")
        if security == "tls":
            tls = (stream or {}).get("tlsSettings", {}) or {}
            out = {"fingerprint": tls.get("fingerprint", "chrome")}
            if tls.get("serverName"):
                out["serverName"] = tls["serverName"]
            if tls.get("alpn"):
                out["alpn"] = tls["alpn"]
            if tls.get("allowInsecure"):
                out["allowInsecure"] = True
            client["tlsSettings"] = out
        elif security == "reality":
            rs = (stream or {}).get("realitySettings", {}) or {}
            server_names = rs.get("serverNames") or [rs.get("serverName", "")]
            short_ids = rs.get("shortIds") or [""]
            public_key = rs.get("publicKey", "")
            if not public_key and rs.get("privateKey"):
                try:
                    import base64
                    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
                    from cryptography.hazmat.primitives import serialization
                    raw = rs["privateKey"]
                    priv = X25519PrivateKey.from_private_bytes(
                        base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
                    pub = priv.public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    public_key = base64.urlsafe_b64encode(pub).decode().rstrip("=")
                except Exception:
                    public_key = ""
            client["realitySettings"] = {
                "serverName": server_names[0] if server_names else "",
                "publicKey": public_key,
                "shortId": short_ids[0] if short_ids else "",
                "fingerprint": rs.get("fingerprint", "chrome"),
                "spiderX": rs.get("spiderX", ""),
            }
        return client
