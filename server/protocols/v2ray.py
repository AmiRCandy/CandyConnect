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
        # Xray doesn't have a simple CLI for this. Check /api/stats if enabled.
        status = await get_core_status(self.PROTOCOL_ID)
        pid = status.get("pid")
        if not pid:
            return 0
        rc, out, _ = await self._run_cmd(
            f"ss -tnp | grep 'pid={pid}' | wc -l",
            check=False,
        )
        try:
            return max(0, int(out.strip()) - 1)  # Subtract listening sockets
        except ValueError:
            return 0

    async def add_client(self, username: str, client_data: dict) -> dict:
        """Add a client to V2Ray config (generates UUID for VLESS/VMess)."""
        client_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, username))

        config = await get_core_config("v2ray")
        if not config:
            return {"uuid": client_uuid}

        try:
            config_obj = json.loads(config.get("config_json", "{}"))
            # Add client to all inbound protocols
            for inbound in config_obj.get("inbounds", []):
                proto = inbound.get("protocol", "")
                settings = inbound.setdefault("settings", {})

                if proto in ("vless", "vmess"):
                    clients = settings.setdefault("clients", [])
                    # Check if already exists
                    if not any(c.get("id") == client_uuid for c in clients):
                        client_entry = {"id": client_uuid, "email": f"{username}@candyconnect"}
                        if proto == "vless":
                            client_entry["flow"] = ""
                        clients.append(client_entry)

                elif proto == "trojan":
                    clients = settings.setdefault("clients", [])
                    if not any(c.get("password") == client_data.get("password", username) for c in clients):
                        clients.append({
                            "password": client_data.get("password", username),
                            "email": f"{username}@candyconnect",
                        })

                elif proto == "shadowsocks":
                    # Shadowsocks uses single password, handled differently
                    pass

            config["config_json"] = json.dumps(config_obj, indent=2)
            await update_core_config("v2ray", config)

            # Restart if running to apply changes
            if await self.is_running():
                await self.restart()

        except json.JSONDecodeError:
            pass

        return {"uuid": client_uuid}

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
        except json.JSONDecodeError:
            pass

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict) -> dict:
        client_uuid = protocol_data.get("uuid") or str(uuid.uuid5(uuid.NAMESPACE_DNS, username))
        config = await get_core_config("v2ray")
        if not config:
            return {}

        outbounds = []
        try:
            config_obj = json.loads(config.get("config_json", "{}"))
            for inbound in config_obj.get("inbounds", []):
                proto = inbound.get("protocol", "")
                if proto not in ("vless", "vmess", "trojan", "shadowsocks"):
                    continue
                
                port = inbound.get("port", 443)
                stream = inbound.get("streamSettings", {})
                network = stream.get("network", "tcp")
                security = stream.get("security", "none")
                
                # Build client outbound
                outbound = {
                    "protocol": proto,
                    "settings": {
                        "vnext": [{
                            "address": server_ip,
                            "port": port,
                            "users": [{"id": client_uuid, "encryption": "none", "level": 0}]
                        }]
                    },
                    "streamSettings": stream, # Copy stream settings (network, security, tlsSettings)
                    "tag": f"proxy-{proto}-{port}"
                }

                # Protocol specific adjustments
                if proto == "vless":
                    outbound["settings"]["vnext"][0]["users"][0]["encryption"] = "none"
                    if "flow" in inbound.get("settings", {}).get("clients", [{}])[0]:
                        outbound["settings"]["vnext"][0]["users"][0]["flow"] = "xtls-rprx-vision"
                
                elif proto == "trojan":
                    outbound["settings"] = {
                        "servers": [{
                            "address": server_ip,
                            "port": port,
                            "password": protocol_data.get("password") or username,
                            "email": f"{username}@candyconnect"
                        }]
                    }
                
                elif proto == "shadowsocks":
                    # Shadowsocks usually has one global password - adjust if per-user logic added later
                    pass

                outbounds.append(outbound)
        except json.JSONDecodeError:
            pass

        # Create a full Xray client config structure
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
                "rules": [
                    {"type": "field", "outboundTag": "direct", "domain": ["geosite:cn", "geosite:private"]},
                    {"type": "field", "outboundTag": "direct", "ip": ["geoip:cn", "geoip:private"]}
                ]
            }
        }

        return {
            "type": "v2ray",
            "server": server_ip,
            "uuid": client_uuid,
            "config_json": client_json,
        }
