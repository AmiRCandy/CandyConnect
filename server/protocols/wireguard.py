"""
CandyConnect - WireGuard Protocol Manager
"""
import asyncio, os, json, base64, time
from protocols.base import BaseProtocol
from database import get_core_config, get_core_status, set_core_status, add_log
from config import DATA_DIR


class WireGuardProtocol(BaseProtocol):
    PROTOCOL_ID = "wireguard"
    PROTOCOL_NAME = "WireGuard"
    DEFAULT_PORT = 51820

    WG_DIR = "/etc/wireguard"

    async def install(self) -> bool:
        try:
            await add_log("INFO", self.PROTOCOL_NAME, "Configuring WireGuard...")
            
            # Check if installed
            if not await self._is_installed("wg"):
                if not await self._apt_install("wireguard wireguard-tools"):
                    return False

            # Enable IP forwarding
            await self._run_cmd("sudo sysctl -w net.ipv4.ip_forward=1", check=False)
            await self._run_cmd(
                "echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf",
                check=False,
            )

            await add_log("INFO", self.PROTOCOL_NAME, "WireGuard installed successfully")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Installation error: {e}")
            return False

    async def start(self) -> bool:
        try:
            config = await get_core_config("wireguard")
            if not config:
                config = {}

            # Set defaults if missing
            updated = False
            if "address" not in config:
                config["address"] = "10.66.66.1/24"
                updated = True
            if "listen_port" not in config:
                config["listen_port"] = self.DEFAULT_PORT
                updated = True
            if "mtu" not in config:
                config["mtu"] = 1420
                updated = True
            if "dns" not in config:
                config["dns"] = "1.1.1.1"
                updated = True
            
            if updated:
                from database import update_core_config
                await update_core_config("wireguard", config)

            name = "wg0" # Use wg0 as primary
            await self._write_config(config)
            
            await self._run_cmd(f"sudo systemctl enable wg-quick@{name}", check=False)
            rc, _, err = await self._run_cmd(f"sudo systemctl start wg-quick@{name}", check=False)
            
            if rc != 0:
                # Try bringing up directly
                rc2, _, err2 = await self._run_cmd(f"sudo wg-quick up {name}", check=False)
                if rc2 != 0:
                    error_msg = err2 or err or "Unknown WireGuard error"
                    await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to start: {error_msg}")
                    return False

            version = await self.get_version()
            await set_core_status(self.PROTOCOL_ID, {
                "status": "running",
                "pid": None,
                "started_at": int(time.time()),
                "version": version,
            })
            await add_log("INFO", self.PROTOCOL_NAME, "WireGuard started")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Start exception: {e}")
            return False

    async def stop(self) -> bool:
        try:
            config = await get_core_config("wireguard")
            name = "wg0"
            await self._run_cmd(f"sudo systemctl stop wg-quick@{name}", check=False)
            await self._run_cmd(f"sudo wg-quick down {name}", check=False)

            status = await get_core_status(self.PROTOCOL_ID)
            await set_core_status(self.PROTOCOL_ID, {
                "status": "stopped",
                "pid": None,
                "started_at": None,
                "version": status.get("version", ""),
            })
            await add_log("INFO", self.PROTOCOL_NAME, "WireGuard stopped")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to stop: {e}")
            return False

    async def is_running(self) -> bool:
        name = "wg0"
        active = await self._is_service_active(f"wg-quick@{name}")
        if active:
            return True
        return False

    async def get_version(self) -> str:
        rc, out, _ = await self._run_cmd("wg --version", check=False)
        if rc == 0 and out:
            # "wireguard-tools v1.0.20210914 - ..."
            parts = out.split()
            for p in parts:
                if p.startswith("v"):
                    return p.lstrip("v")
            return out.split()[0] if out else ""
        return ""

    async def get_active_connections(self) -> int:
        """Count peers that have a recent handshake (non-zero)."""
        rc, out, _ = await self._run_cmd("sudo wg show all dump", check=False)
        if rc != 0 or not out:
            return 0
        active = 0
        for line in out.strip().split("\n"):
            parts = line.split("\t")
            # Peer lines in `wg show all dump` have >= 9 columns; interface lines have fewer
            if len(parts) >= 9:
                latest_handshake = parts[5]
                try:
                    if int(latest_handshake) > 0:
                        active += 1
                except ValueError:
                    # If not parsable, skip
                    continue
        return active

    async def get_traffic(self) -> dict:
        """Get total traffic for all WireGuard interfaces."""
        total_rx = 0
        total_tx = 0
        try:
            rc, out, _ = await self._run_cmd("sudo wg show all dump", check=False)
            if rc == 0 and out:
                for line in out.strip().split("\n"):
                    parts = line.split("\t")
                    if parts[0] == "peer":
                        # peer public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
                        if len(parts) >= 8:
                            total_rx += int(parts[6])
                            total_tx += int(parts[7])
        except Exception:
            pass

        return {
            "in": round(total_rx / (1024 ** 3), 2),
            "out": round(total_tx / (1024 ** 3), 2)
        }

    async def add_client(self, username: str, client_data: dict) -> dict:
        """Create a new WireGuard peer for a client."""
        client_privkey = ""
        client_pubkey = ""
        
        # 1. Generate client keys
        rc, client_privkey, _ = await self._run_cmd("wg genkey")
        if rc == 0:
            proc = await asyncio.create_subprocess_shell(
                "wg pubkey",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
            )
            pub_out, _ = await proc.communicate(client_privkey.encode())
            client_pubkey = pub_out.decode().strip()

        # 2. Get server config
        config = await get_core_config("wireguard")
        name = "wg0"
        
        # 3. Choose next IP (random for now within the 10.66.66.0/24 subnet)
        import random
        last_octet = random.randint(2, 254)
        client_address = f"10.66.66.{last_octet}/32"

        # 4. Add peer to running interface
        await self._run_cmd(
            f"sudo wg set {name} peer {client_pubkey} allowed-ips {client_address}",
            check=False,
        )
        
        return {
            "private_key": client_privkey,
            "public_key": client_pubkey,
            "address": client_address,
            "server_public_key": config.get("public_key", ""),
        }

    async def remove_client(self, username: str, protocol_data: dict):
        """Remove WireGuard peer for a client."""
        pubkey = protocol_data.get("public_key")
        if not pubkey:
            return

        name = "wg0"
        await self._run_cmd(f"sudo wg set {name} peer {pubkey} remove", check=False)

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict) -> dict:
        config = await get_core_config("wireguard")
        if not config:
            return {}

        # Build full WG config string for convenience
        address = protocol_data.get("address", "")
        privkey = protocol_data.get("private_key", "")
        pubkey = config.get("public_key", "")
        port = config.get("listen_port", 51820)

        wg_config = f"""[Interface]
PrivateKey = {privkey}
Address = {address}
DNS = {config.get('dns', '1.1.1.1')}
MTU = {config.get('mtu', 1420)}

[Peer]
PublicKey = {pubkey}
Endpoint = {server_ip}:{port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

        return {
            "type": "wireguard",
            "server": server_ip,
            "port": port,
            "server_public_key": pubkey,
            "client_private_key": privkey,
            "client_address": address,
            "dns": config.get("dns", "1.1.1.1"),
            "mtu": config.get("mtu", 1420),
            "wg_config": wg_config,
        }

    async def _write_config(self, config: dict):
        """Write WireGuard config file."""
        os.makedirs(self.WG_DIR, exist_ok=True)
        name = "wg0"
        conf_path = os.path.join(self.WG_DIR, f"{name}.conf")

        # Generate keys if not set
        if not config.get("private_key"):
            rc, privkey, _ = await self._run_cmd("wg genkey")
            if rc == 0:
                config["private_key"] = privkey.strip()
                proc = await asyncio.create_subprocess_shell(
                    "wg pubkey",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                )
                pubkey_out, _ = await proc.communicate(privkey.encode())
                config["public_key"] = pubkey_out.decode().strip()
                # Update config in DB
                from database import update_core_config
                await update_core_config("wireguard", config)

        # Auto-generate NAT rules if PostUp/PostDown are empty
        interface = config.get("bind_interface", "eth0")
        
        post_up = config.get("post_up", "")
        if not post_up and interface:
            post_up = f"iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE"
            
        post_down = config.get("post_down", "")
        if not post_down and interface:
            post_down = f"iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {interface} -j MASQUERADE"

        conf = f"""[Interface]
Address = {config['address']}
ListenPort = {config['listen_port']}
PrivateKey = {config['private_key']}
MTU = {config.get('mtu', 1420)}
DNS = {config.get('dns', '1.1.1.1')}
PostUp = {post_up}
PostDown = {post_down}
"""
        tmp_path = f"/tmp/cc_{name}.conf"
        with open(tmp_path, "w") as f:
            f.write(conf)
            
        await self._run_cmd(f"sudo mv {tmp_path} {conf_path}", check=False)
        await self._run_cmd(f"sudo chown root:root {conf_path}", check=False)
        await self._run_cmd(f"sudo chmod 600 {conf_path}", check=False)
