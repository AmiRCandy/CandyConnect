"""
CandyConnect - OpenVPN Protocol Manager
"""
import asyncio, os, time
from protocols.base import BaseProtocol
from database import get_core_config, get_core_status, set_core_status, add_log
from config import DATA_DIR


class OpenVPNProtocol(BaseProtocol):
    PROTOCOL_ID = "openvpn"
    PROTOCOL_NAME = "OpenVPN"
    DEFAULT_PORT = 1194

    OVPN_DIR = "/etc/openvpn/server"
    EASYRSA_DIR = "/etc/openvpn/easy-rsa"
    PKI_DIR = "/etc/openvpn/easy-rsa/pki"

    async def install(self) -> bool:
        try:
            await add_log("INFO", self.PROTOCOL_NAME, "Configuring OpenVPN...")

            # Check if installed
            if not await self._is_installed("openvpn"):
                if not await self._apt_install("openvpn easy-rsa"):
                    return False

            # Set up Easy-RSA PKI
            os.makedirs(self.EASYRSA_DIR, exist_ok=True)
            await self._run_cmd(f"cp -r /usr/share/easy-rsa/* {self.EASYRSA_DIR}/", check=False)

            # Initialize PKI
            await self._run_cmd(
                f"cd {self.EASYRSA_DIR} && ./easyrsa --batch init-pki",
                check=False,
            )
            # Build CA
            await self._run_cmd(
                f"cd {self.EASYRSA_DIR} && EASYRSA_BATCH=1 ./easyrsa --batch build-ca nopass",
                check=False,
            )
            # Generate server cert
            await self._run_cmd(
                f"cd {self.EASYRSA_DIR} && EASYRSA_BATCH=1 ./easyrsa --batch build-server-full server nopass",
                check=False,
            )
            # Generate DH params (can be slow, increase timeout)
            await self._run_cmd(
                f"cd {self.EASYRSA_DIR} && ./easyrsa --batch gen-dh",
                check=False,
                timeout=600,
            )
            # Generate TLS-Crypt key
            await self._run_cmd(
                f"sudo openvpn --genkey secret {self.PKI_DIR}/tc.key",
                check=False,
            )
            
            # Generate initial CRL (needed for crl-verify to work)
            await self._run_cmd(
                f"cd {self.EASYRSA_DIR} && EASYRSA_BATCH=1 ./easyrsa gen-crl",
                check=False,
            )
            
            # Ensure proper permissions and links
            await self._run_cmd(f"sudo chown -R root:root {self.OVPN_DIR} {self.EASYRSA_DIR}", check=False)
            await self._run_cmd(f"sudo chmod -R 700 {self.EASYRSA_DIR}", check=False)

            # Enable IP forwarding
            await self._run_cmd("sudo sysctl -w net.ipv4.ip_forward=1", check=False)
            await self._run_cmd(
                "grep -q 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf",
                check=False,
            )

            await add_log("INFO", self.PROTOCOL_NAME, "OpenVPN installed successfully")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Installation error: {e}")
            return False

    async def start(self) -> bool:
        try:
            config = await get_core_config("openvpn")
            if not config:
                await add_log("ERROR", self.PROTOCOL_NAME, "No OpenVPN config found")
                return False

            await self._write_server_config(config)

            # Try systemctl first
            rc, _, err = await self._run_cmd(
                "sudo systemctl enable openvpn-server@server && sudo systemctl start openvpn-server@server",
                check=False,
            )
            
            if rc != 0:
                # Fallback: direct process start (Docker typical)
                pid = await self._start_process(
                    f"openvpn --config {os.path.join(self.OVPN_DIR, 'server.conf')}"
                )
                if not pid:
                     await add_log("ERROR", self.PROTOCOL_NAME, f"OpenVPN failed to start: {err}")
                     return False
            else:
                # Update status for systemctl start
                version = await self.get_version()
                await set_core_status(self.PROTOCOL_ID, {
                    "status": "running",
                    "pid": None,
                    "started_at": int(time.time()),
                    "version": version,
                })

            await add_log("INFO", self.PROTOCOL_NAME, "OpenVPN started")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to start: {e}")
            return False

    async def stop(self) -> bool:
        try:
            # Stop both systemctl and direct processes
            await self._run_cmd("sudo systemctl stop openvpn-server@server", check=False)
            await self._run_cmd("sudo systemctl stop openvpn@server", check=False)
            await self._run_cmd("sudo pkill openvpn", check=False)

            status = await get_core_status(self.PROTOCOL_ID)
            await set_core_status(self.PROTOCOL_ID, {
                "status": "stopped",
                "pid": None,
                "started_at": None,
                "version": status.get("version", ""),
            })
            await add_log("INFO", self.PROTOCOL_NAME, "OpenVPN stopped")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to stop: {e}")
            return False

    async def is_running(self) -> bool:
        # Check systemctl OR base process check
        if await self._is_service_active("openvpn-server@server") or await self._is_service_active("openvpn@server"):
            return True
        # Check if process exists in table
        rc, out, _ = await self._run_cmd("pgrep openvpn", check=False)
        return rc == 0

    async def get_version(self) -> str:
        rc, out, _ = await self._run_cmd("openvpn --version", check=False)
        if rc == 0 or out:
            # "OpenVPN 2.6.8 x86_64 ..."
            for line in out.split("\n"):
                if "OpenVPN" in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "OpenVPN" and i + 1 < len(parts):
                            return parts[i + 1]
        return ""

    async def get_active_connections(self) -> int:
        # Read the OpenVPN status file and count CLIENT_LIST entries.
        # Avoid piping into grep -c (pipe exit-code issue).
        for status_file in [
            "/var/log/openvpn/openvpn-status.log",
            "/etc/openvpn/server/openvpn-status.log",
            "/etc/openvpn/openvpn-status.log",
        ]:
            rc, out, _ = await self._run_cmd(f"sudo cat {status_file} 2>/dev/null", check=False)
            if rc == 0 and out:
                # CLIENT_LIST lines: one header + one per connected client
                count = sum(1 for line in out.splitlines() if line.startswith("CLIENT_LIST,") or line.startswith("CLIENT_LIST\t"))
                # Subtract 1 for the header line ("CLIENT_LIST,Common Name,...")
                return max(0, count - 1)
        return 0

    async def get_traffic(self) -> dict:
        """Get total traffic from OpenVPN status log."""
        total_in = 0
        total_out = 0
        try:
            status_file = "/var/log/openvpn/openvpn-status.log"
            if not os.path.exists(status_file):
                status_file = "/etc/openvpn/server/openvpn-status.log"

            rc, out, _ = await self._run_cmd(f"sudo cat {status_file}", check=False)
            if rc == 0:
                for line in out.split("\n"):
                    if line.startswith("TCP/UDP read bytes,"):
                        total_in = int(line.split(",")[1])
                    elif line.startswith("TCP/UDP write bytes,"):
                        total_out = int(line.split(",")[1])
        except Exception:
            pass
        # Return raw bytes so callers can aggregate accurately
        return {"in": total_in, "out": total_out}

    async def add_client(self, username: str, client_data: dict) -> dict:
        """Generate client certificate and return .ovpn config data."""
        # Generate client cert
        await self._run_cmd(
            f"cd {self.EASYRSA_DIR} && EASYRSA_BATCH=1 ./easyrsa --batch build-client-full {username} nopass",
            check=False,
            timeout=120,
        )
        return {"cert_generated": True, "username": username}

    async def remove_client(self, username: str, protocol_data: dict):
        await self._run_cmd(
            f"cd {self.EASYRSA_DIR} && EASYRSA_BATCH=1 ./easyrsa --batch revoke {username}",
            check=False,
        )
        await self._run_cmd(
            f"cd {self.EASYRSA_DIR} && EASYRSA_BATCH=1 ./easyrsa gen-crl",
            check=False,
        )

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        config = await get_core_config("openvpn")
        if not config:
            return {}

        port = config.get("port", 1194)
        protocol = config.get("protocol", "udp")

        # Read cert files
        ca = await self._read_file(f"{self.PKI_DIR}/ca.crt")
        cert = await self._read_file(f"{self.PKI_DIR}/issued/{username}.crt")
        key = await self._read_file(f"{self.PKI_DIR}/private/{username}.key")
        tc = await self._read_file(f"{self.PKI_DIR}/tc.key")

        ovpn_config = f"""client
dev tun
proto {protocol}
remote {server_ip} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher {config.get('cipher', 'AES-256-GCM')}
auth {config.get('auth', 'SHA512')}
verb 3
<ca>
{ca}
</ca>
<cert>
{cert}
</cert>
<key>
{key}
</key>
<tls-crypt>
{tc}
</tls-crypt>
"""
        return {
            "type": "openvpn",
            "server": server_ip,
            "port": port,
            "protocol": protocol,
            "ovpn_config": ovpn_config,
        }

    async def _read_file(self, path: str) -> str:
        try:
            rc, out, _ = await self._run_cmd(f"sudo cat {path}", check=False)
            return out if rc == 0 else ""
        except Exception:
            return ""

    async def _write_server_config(self, config: dict):
        """Write OpenVPN server configuration."""
        os.makedirs(self.OVPN_DIR, exist_ok=True)

        # Detect default network interface
        _, default_iface, _ = await self._run_cmd(
            "ip route show default | awk '{print $5}' | head -1",
            check=False,
        )
        default_iface = default_iface.strip() or "eth0"

        subnet = config.get("subnet", "10.8.0.0/24")
        subnet_ip = subnet.split("/")[0]
        subnet_mask = "255.255.255.0"

        server_conf = f"""port {config.get('port', 1194)}
proto {config.get('protocol', 'udp')}
dev {config.get('device', 'tun')}
ca {self.PKI_DIR}/ca.crt
cert {self.PKI_DIR}/issued/server.crt
key {self.PKI_DIR}/private/server.key
dh none
topology subnet
server {subnet_ip} {subnet_mask}
ifconfig-pool-persist /var/log/openvpn/ipp.txt
push "dhcp-option DNS {config.get('dns1', '1.1.1.1')}"
push "dhcp-option DNS {config.get('dns2', '8.8.8.8')}"
push "redirect-gateway def1 bypass-dhcp"
keepalive {config.get('keepalive', '10 120')}
cipher {config.get('cipher', 'AES-256-GCM')}
auth {config.get('auth', 'SHA512')}
max-clients {config.get('max_clients', 100)}
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log /var/log/openvpn/openvpn.log
verb 3
crl-verify {self.PKI_DIR}/crl.pem
"""
        if config.get("tls_crypt"):
            server_conf += f"tls-crypt {self.PKI_DIR}/tc.key\n"
        if config.get("comp_lzo"):
            server_conf += "compress lzo\n"

        conf_path = os.path.join(self.OVPN_DIR, "server.conf")
        await self._run_cmd(f"sudo mkdir -p /var/log/openvpn", check=False)

        with open("/tmp/cc_ovpn_server.conf", "w") as f:
            f.write(server_conf)
        await self._run_cmd(f"sudo mv /tmp/cc_ovpn_server.conf {conf_path}", check=False)

        # Setup NAT
        await self._run_cmd(
            f"sudo iptables -t nat -C POSTROUTING -s {subnet} -o {default_iface} -j MASQUERADE 2>/dev/null || "
            f"sudo iptables -t nat -A POSTROUTING -s {subnet} -o {default_iface} -j MASQUERADE",
            check=False,
        )
