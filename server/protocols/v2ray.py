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
            await add_log("INFO", self.PROTOCOL_NAME, "Installing Xray...")
            os.makedirs(self.XRAY_DIR, exist_ok=True)

            # Download latest Xray from GitHub
            rc, out, err = await self._run_cmd(
                "bash -c 'curl -sL https://api.github.com/repos/XTLS/Xray-core/releases/latest "
                "| grep browser_download_url | grep linux-64 | head -1 | cut -d\\\"  -f4'",
                check=False,
            )
            if rc != 0 or not out:
                # Fallback: use install script (ensures curl present)
                await self._run_cmd("sudo apt update && sudo apt install -y curl", check=False)
                rc, _, err = await self._run_cmd(
                    "bash -c 'curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash -s -- install'",
                    check=False,
                )
                if rc != 0:
                    await add_log("ERROR", self.PROTOCOL_NAME, f"Installation failed: {err}")
                    return False
                # Link the binary
                await self._run_cmd(f"ln -sf /usr/local/bin/xray {self.XRAY_BIN}", check=False)
            else:
                # Ensure curl and unzip exist for manual download path
                await self._run_cmd("sudo apt update && sudo apt install -y curl unzip", check=False)
                download_url = out.strip()
                zip_path = os.path.join(self.XRAY_DIR, "xray.zip")
                await self._run_cmd(f"curl -sL -o {zip_path} '{download_url}'")
                await self._run_cmd(f"unzip -o {zip_path} -d {self.XRAY_DIR}")
                await self._run_cmd(f"chmod +x {self.XRAY_BIN}")
                await self._run_cmd(f"rm -f {zip_path}")

            await add_log("INFO", self.PROTOCOL_NAME, "Xray installed successfully")
            return True
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

        sub_protocols = []
        try:
            config_obj = json.loads(config.get("config_json", "{}"))
            for inbound in config_obj.get("inbounds", []):
                proto = inbound.get("protocol", "")
                port = inbound.get("port", 443)
                tag = inbound.get("tag", proto)
                stream = inbound.get("streamSettings", {})
                network = stream.get("network", "tcp")
                security = stream.get("security", "none")

                sub_protocols.append({
                    "tag": tag,
                    "protocol": proto,
                    "port": port,
                    "transport": network,
                    "security": security,
                })
        except json.JSONDecodeError:
            pass

        return {
            "type": "v2ray",
            "server": server_ip,
            "uuid": client_uuid,
            "sub_protocols": sub_protocols,
        }
