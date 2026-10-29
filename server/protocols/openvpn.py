"""
CandyConnect - OpenVPN Protocol Manager
"""
import asyncio, os, time, ipaddress
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

            # Set up Easy-RSA PKI.
            # install() runs on every server start, so every step must be idempotent:
            # `easyrsa --batch init-pki` DELETES an existing PKI (CA + all client certs).
            os.makedirs(self.EASYRSA_DIR, exist_ok=True)
            if not os.path.exists(os.path.join(self.EASYRSA_DIR, "easyrsa")):
                await self._run_cmd(f"cp -r /usr/share/easy-rsa/* {self.EASYRSA_DIR}/", check=False)

            if not os.path.exists(f"{self.PKI_DIR}/ca.crt"):
                await add_log("INFO", self.PROTOCOL_NAME, "Creating PKI (CA + server certificate)...")
                await self._run_cmd(
                    f"cd {self.EASYRSA_DIR} && ./easyrsa --batch init-pki",
                    check=False,
                )
                await self._run_cmd(
                    f"cd {self.EASYRSA_DIR} && EASYRSA_BATCH=1 EASYRSA_REQ_CN='CandyConnect CA' ./easyrsa --batch build-ca nopass",
                    check=False,
                    timeout=120,
                )
            if not os.path.exists(f"{self.PKI_DIR}/issued/server.crt"):
                await self._run_cmd(
                    f"cd {self.EASYRSA_DIR} && EASYRSA_BATCH=1 ./easyrsa --batch build-server-full server nopass",
                    check=False,
                    timeout=120,
                )
            # No DH params needed: the server config uses "dh none" (ECDHE)

            # Generate TLS-Crypt key (OpenVPN >= 2.5 syntax, fallback to 2.4 syntax)
            if not os.path.exists(f"{self.PKI_DIR}/tc.key"):
                rc, _, _ = await self._run_cmd(
                    f"sudo openvpn --genkey secret {self.PKI_DIR}/tc.key",
                    check=False,
                )
                if rc != 0:
                    await self._run_cmd(
                        f"sudo openvpn --genkey --secret {self.PKI_DIR}/tc.key",
                        check=False,
                    )
            
            # Generate initial CRL (needed for crl-verify to work)
            if not os.path.exists(f"{self.PKI_DIR}/crl.pem"):
                await self._run_cmd(
                    f"cd {self.EASYRSA_DIR} && EASYRSA_BATCH=1 ./easyrsa gen-crl",
                    check=False,
                )
            await self._publish_crl()
            
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
                "sudo systemctl enable openvpn-server@server && sudo systemctl restart openvpn-server@server",
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

    async def _read_status(self) -> str:
        for status_file in [
            "/var/log/openvpn/openvpn-status.log",
            "/etc/openvpn/server/openvpn-status.log",
            "/etc/openvpn/openvpn-status.log",
        ]:
            rc, out, _ = await self._run_cmd(f"sudo cat {status_file} 2>/dev/null", check=False)
            if rc == 0 and out:
                return out
        return ""

    async def get_active_connections(self) -> int:
        # status-version 2: one "CLIENT_LIST,..." line per connected client
        # (the header line starts with "HEADER,CLIENT_LIST" so it is not counted)
        out = await self._read_status()
        return sum(1 for line in out.splitlines() if line.startswith("CLIENT_LIST,"))

    async def get_traffic(self) -> dict:
        """Sum per-client byte counters from the OpenVPN status file."""
        total_in = 0
        total_out = 0
        try:
            # CLIENT_LIST,CN,Real Address,Virtual Address,Virtual IPv6,Bytes Received,Bytes Sent,...
            for line in (await self._read_status()).splitlines():
                if line.startswith("CLIENT_LIST,"):
                    parts = line.split(",")
                    if len(parts) > 6:
                        try:
                            total_in += int(parts[5])
                            total_out += int(parts[6])
                        except ValueError:
                            pass
        except Exception:
            pass
        # Return raw bytes so callers can aggregate accurately
        return {"in": total_in, "out": total_out}

    async def add_client(self, username: str, client_data: dict) -> dict:
        """Generate client certificate and return .ovpn config data."""
        if os.path.exists(f"{self.PKI_DIR}/issued/{username}.crt"):
            return {"cert_generated": True, "username": username}
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
        await self._publish_crl()

    async def _publish_crl(self):
        """Copy the CRL where OpenVPN can re-read it after dropping to nobody:nogroup.

        The easy-rsa dir is chmod 700, and OpenVPN re-reads crl-verify on every
        new connection *after* dropping privileges, so pointing it at pki/crl.pem
        rejects every client.
        """
        os.makedirs(self.OVPN_DIR, exist_ok=True)
        await self._run_cmd(
            f"sudo cp {self.PKI_DIR}/crl.pem {self.OVPN_DIR}/crl.pem && sudo chmod 644 {self.OVPN_DIR}/crl.pem",
            check=False,
        )

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        config = await get_core_config("openvpn")
        if not config:
            return {}

        port = config.get("port", 1194)
        protocol = config.get("protocol", "udp")

        # Client created before OpenVPN was set up? Issue its certificate now.
        if not os.path.exists(f"{self.PKI_DIR}/issued/{username}.crt") and os.path.exists(f"{self.PKI_DIR}/ca.crt"):
            await self.add_client(username, {})

        # Read cert files
        ca = await self._read_file(f"{self.PKI_DIR}/ca.crt")
        cert = await self._read_file(f"{self.PKI_DIR}/issued/{username}.crt")
        key = await self._read_file(f"{self.PKI_DIR}/private/{username}.key")
        tc = await self._read_file(f"{self.PKI_DIR}/tc.key")
        if not ca or not cert or not key:
            return {}
        # Certificate files contain a text dump before the PEM block; keep only the PEM part
        if "-----BEGIN CERTIFICATE-----" in cert:
            cert = cert[cert.index("-----BEGIN CERTIFICATE-----"):]
        tls_crypt_block = f"<tls-crypt>\n{tc}\n</tls-crypt>\n" if config.get("tls_crypt") and tc else ""

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
{tls_crypt_block}"""
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
        default_iface = await self._default_iface()

        subnet = config.get("subnet", "10.8.0.0/24")
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            subnet = str(net)
            subnet_ip, subnet_mask = str(net.network_address), str(net.netmask)
        except ValueError:
            subnet, subnet_ip, subnet_mask = "10.8.0.0/24", "10.8.0.0", "255.255.255.0"

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
status-version 2
log /var/log/openvpn/openvpn.log
verb 3
crl-verify {self.OVPN_DIR}/crl.pem
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
        await self._run_cmd(
            f"sudo iptables -C FORWARD -s {subnet} -j ACCEPT 2>/dev/null || sudo iptables -I FORWARD -s {subnet} -j ACCEPT; "
            f"sudo iptables -C FORWARD -d {subnet} -j ACCEPT 2>/dev/null || sudo iptables -I FORWARD -d {subnet} -j ACCEPT",
            check=False,
        )
