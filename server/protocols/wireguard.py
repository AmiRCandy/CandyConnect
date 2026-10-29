"""
CandyConnect - WireGuard Protocol Manager
"""
import asyncio, os, json, base64, time, ipaddress
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
            # restart (not start) so a changed wg0.conf is applied if wg0 is already up
            rc, _, err = await self._run_cmd(f"sudo systemctl restart wg-quick@{name}", check=False)
            
            if rc != 0:
                # Try bringing up directly (e.g. Docker without systemd)
                await self._run_cmd(f"sudo wg-quick down {name}", check=False)
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
        # wg-quick started without systemd (e.g. Docker)
        rc, _, _ = await self._run_cmd(f"ip link show {name}", check=False)
        return rc == 0

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
        """Get total traffic for all WireGuard interfaces.

        `wg show all dump` outputs two kinds of tab-separated lines:
          interface line: <iface>  <private_key>  <public_key>  <listen_port>  <fwmark>   (5 fields)
          peer line:      <iface>  <public_key>   <preshared>   <endpoint>     <allowed_ips>  <latest_handshake>  <rx_bytes>  <tx_bytes>  <keepalive>  (9 fields)
        We identify peer lines by having >= 9 fields.
        """
        total_rx = 0
        total_tx = 0
        try:
            rc, out, _ = await self._run_cmd("sudo wg show all dump", check=False)
            if rc == 0 and out:
                for line in out.strip().split("\n"):
                    parts = line.split("\t")
                    if len(parts) >= 9:
                        # peer line: rx_bytes at index 6, tx_bytes at index 7
                        try:
                            total_rx += int(parts[6])
                            total_tx += int(parts[7])
                        except (ValueError, IndexError):
                            continue
        except Exception:
            pass

        # Return raw bytes so callers can aggregate accurately
        return {"in": total_rx, "out": total_tx}

    async def add_client(self, username: str, client_data: dict) -> dict:
        """Create (or re-apply) the WireGuard peer for a client.

        Existing keys/address passed in client_data (from stored protocol_data)
        are reused so the client's config stays valid across restarts and edits.
        """
        client_privkey = client_data.get("private_key", "")
        client_pubkey = client_data.get("public_key", "")

        # 1. Generate client keys only if we don't have them yet
        if not client_privkey or not client_pubkey:
            client_privkey, client_pubkey = await self._gen_keypair()
            if not client_privkey:
                raise RuntimeError("wg genkey failed (is wireguard-tools installed?)")

        # 2. Get server config
        config = await get_core_config("wireguard") or {}
        name = "wg0"

        # 3. Keep the existing address if it is inside the server subnet, else allocate the next free one
        network = self._server_network(config)
        client_address = client_data.get("address", "")
        try:
            if not client_address or ipaddress.ip_interface(client_address).ip not in network:
                client_address = ""
        except ValueError:
            client_address = ""
        if not client_address:
            client_address = await self._allocate_address(network, username)

        # 4. Add peer to running interface (also persisted in wg0.conf on next start)
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

    async def _gen_keypair(self) -> tuple[str, str]:
        rc, privkey, _ = await self._run_cmd("wg genkey")
        if rc != 0 or not privkey:
            return "", ""
        proc = await asyncio.create_subprocess_shell(
            "wg pubkey",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        pub_out, _ = await proc.communicate(privkey.strip().encode())
        return privkey.strip(), pub_out.decode().strip()

    @staticmethod
    def _server_network(config: dict) -> ipaddress.IPv4Network:
        try:
            return ipaddress.ip_interface(config.get("address", "10.66.66.1/24")).network
        except ValueError:
            return ipaddress.ip_network("10.66.66.0/24")

    async def _allocate_address(self, network, username: str) -> str:
        """Return the first free /32 in the server subnet, skipping the server's own IP."""
        from database import get_all_clients
        config = await get_core_config("wireguard") or {}
        used = set()
        try:
            used.add(ipaddress.ip_interface(config.get("address", "10.66.66.1/24")).ip)
        except ValueError:
            pass
        for c in await get_all_clients():
            if c.get("username") == username:
                continue
            addr = ((c.get("protocol_data") or {}).get("wireguard") or {}).get("address")
            if addr:
                try:
                    used.add(ipaddress.ip_interface(addr).ip)
                except ValueError:
                    pass
        for host in network.hosts():
            if host not in used:
                return f"{host}/32"
        raise RuntimeError("WireGuard subnet is full")

    async def remove_client(self, username: str, protocol_data: dict):
        """Remove WireGuard peer for a client."""
        pubkey = protocol_data.get("public_key")
        if not pubkey:
            return

        name = "wg0"
        await self._run_cmd(f"sudo wg set {name} peer {pubkey} remove", check=False)

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        config = await get_core_config("wireguard")
        if not config:
            return {}

        # Build full WG config string for convenience
        address = protocol_data.get("address", "")
        privkey = protocol_data.get("private_key", "")
        pubkey = config.get("public_key", "") or protocol_data.get("server_public_key", "")
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
        """Write WireGuard config file (interface + all client peers)."""
        os.makedirs(self.WG_DIR, exist_ok=True)
        name = "wg0"
        conf_path = os.path.join(self.WG_DIR, f"{name}.conf")

        # Generate keys if not set
        if not config.get("private_key") or not config.get("public_key"):
            privkey, pubkey = await self._gen_keypair()
            if privkey:
                config["private_key"] = privkey
                config["public_key"] = pubkey
                # Update config in DB
                from database import update_core_config
                await update_core_config("wireguard", config)

        # NAT rules: auto-generate with the real outbound interface. Rules that still
        # carry the old hard-coded "eth0" default are regenerated too, because most
        # VPS images name the interface ens3/enp1s0/... and NAT would silently fail.
        interface = config.get("bind_interface") or await self._default_iface()
        legacy_up = "iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
        legacy_down = "iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"

        post_up = config.get("post_up", "")
        if not post_up or post_up.strip() == legacy_up:
            post_up = (f"iptables -I FORWARD -i %i -j ACCEPT; iptables -I FORWARD -o %i -j ACCEPT; "
                       f"iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE")

        post_down = config.get("post_down", "")
        if not post_down or post_down.strip() == legacy_down:
            post_down = (f"iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; "
                         f"iptables -t nat -D POSTROUTING -o {interface} -j MASQUERADE")

        # NOTE: no "DNS =" line here. On the server side wg-quick would hand it to
        # resolvconf, which is usually not installed and makes `wg-quick up` fail.
        conf = f"""[Interface]
Address = {config['address']}
ListenPort = {config['listen_port']}
PrivateKey = {config['private_key']}
MTU = {config.get('mtu', 1420)}
PostUp = {post_up}
PostDown = {post_down}
"""
        # Persist all client peers so they survive restarts of wg0
        from database import get_all_clients
        for c in await get_all_clients():
            if not c.get("enabled", True) or not (c.get("protocols") or {}).get("wireguard"):
                continue
            pdata = (c.get("protocol_data") or {}).get("wireguard") or {}
            if pdata.get("public_key") and pdata.get("address"):
                conf += f"""
# {c.get('username', '')}
[Peer]
PublicKey = {pdata['public_key']}
AllowedIPs = {pdata['address']}
"""

        tmp_path = f"/tmp/cc_{name}.conf"
        with open(tmp_path, "w") as f:
            f.write(conf)
            
        await self._run_cmd(f"sudo mv {tmp_path} {conf_path}", check=False)
        await self._run_cmd(f"sudo chown root:root {conf_path}", check=False)
        await self._run_cmd(f"sudo chmod 600 {conf_path}", check=False)
