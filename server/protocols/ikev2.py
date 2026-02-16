"""
CandyConnect - IKEv2/IPSec Protocol Manager (strongSwan)
"""
import os, time
from protocols.base import BaseProtocol
from database import get_core_config, get_core_status, set_core_status, add_log
from config import DATA_DIR


class IKEv2Protocol(BaseProtocol):
    PROTOCOL_ID = "ikev2"
    PROTOCOL_NAME = "IKEv2"
    DEFAULT_PORT = 500

    IPSEC_DIR = "/etc/ipsec.d"
    SWANCTL_DIR = "/etc/swanctl"

    async def install(self) -> bool:
        try:
            await add_log("INFO", self.PROTOCOL_NAME, "Configuring strongSwan (IKEv2)...")

            # Check if installed
            if not await self._is_installed("ipsec"):
                if not await self._apt_install("strongswan strongswan-pki libcharon-extra-plugins"):
                    return False

            # Create directories
            for d in ["cacerts", "certs", "private"]:
                os.makedirs(os.path.join(self.IPSEC_DIR, d), exist_ok=True)

            # Generate CA key and cert
            await self._run_cmd(
                f"ipsec pki --gen --type rsa --size 4096 --outform pem > {self.IPSEC_DIR}/private/ca-key.pem",
                check=False,
            )
            await self._run_cmd(
                f"ipsec pki --self --ca --lifetime 3650 --in {self.IPSEC_DIR}/private/ca-key.pem "
                f"--type rsa --dn 'CN=CandyConnect VPN CA' --outform pem > {self.IPSEC_DIR}/cacerts/ca-cert.pem",
                check=False,
            )

            # Generate server key and cert
            await self._run_cmd(
                f"ipsec pki --gen --type rsa --size 4096 --outform pem > {self.IPSEC_DIR}/private/server-key.pem",
                check=False,
            )

            # Get server IP for SAN
            _, server_ip, _ = await self._run_cmd(
                "curl -4 -s ifconfig.me || hostname -I | awk '{print $1}'",
                check=False,
            )
            server_ip = server_ip.strip() or "0.0.0.0"

            await self._run_cmd(
                f"ipsec pki --pub --in {self.IPSEC_DIR}/private/server-key.pem --type rsa | "
                f"ipsec pki --issue --lifetime 3650 --cacert {self.IPSEC_DIR}/cacerts/ca-cert.pem "
                f"--cakey {self.IPSEC_DIR}/private/ca-key.pem "
                f"--dn 'CN={server_ip}' --san '{server_ip}' --san '@{server_ip}' "
                f"--flag serverAuth --flag ikeIntermediate "
                f"--outform pem > {self.IPSEC_DIR}/certs/server-cert.pem",
                check=False,
            )

            # Enable IP forwarding
            await self._run_cmd("sudo sysctl -w net.ipv4.ip_forward=1", check=False)

            await add_log("INFO", self.PROTOCOL_NAME, "strongSwan installed successfully")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Installation error: {e}")
            return False

    async def start(self) -> bool:
        try:
            config = await get_core_config("ikev2")
            if not config:
                await add_log("ERROR", self.PROTOCOL_NAME, "No IKEv2 config found")
                return False

            await self._write_config(config)

            # Try systemctl
            await self._run_cmd("sudo systemctl enable strongswan-starter", check=False)
            rc, _, err = await self._run_cmd("sudo systemctl start strongswan-starter", check=False)

            if rc != 0:
                # Docker fallback
                await self._run_cmd("sudo ipsec start", check=False)

            if await self.is_running():
                version = await self.get_version()
                await set_core_status(self.PROTOCOL_ID, {
                    "status": "running",
                    "pid": None,
                    "started_at": int(time.time()),
                    "version": version,
                })
                await add_log("INFO", self.PROTOCOL_NAME, "IKEv2 started")
                return True
            else:
                await add_log("ERROR", self.PROTOCOL_NAME, "IKEv2 failed to start")
                return False
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to start: {e}")
            return False

    async def stop(self) -> bool:
        try:
            await self._run_cmd("sudo systemctl stop strongswan-starter", check=False)
            await self._run_cmd("sudo systemctl stop ipsec", check=False)

            status = await get_core_status(self.PROTOCOL_ID)
            await set_core_status(self.PROTOCOL_ID, {
                "status": "stopped", "pid": None,
                "started_at": None, "version": status.get("version", ""),
            })
            await add_log("INFO", self.PROTOCOL_NAME, "IKEv2 stopped")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to stop: {e}")
            return False

    async def is_running(self) -> bool:
        if await self._is_service_active("strongswan-starter") or await self._is_service_active("ipsec"):
            return True
        # Strongswan process is usually 'charon'
        rc, _, _ = await self._run_cmd("pgrep charon", check=False)
        return rc == 0

    async def get_version(self) -> str:
        rc, out, _ = await self._run_cmd("ipsec --version", check=False)
        if rc == 0 and out:
            # "Linux strongSwan U5.9.14/K6.5.0..."
            for part in out.split():
                if part.startswith("U"):
                    return part[1:].split("/")[0]
        return ""

    async def get_active_connections(self) -> int:
        rc, out, _ = await self._run_cmd("sudo ipsec statusall | grep -c 'ESTABLISHED'", check=False)
        try:
            return int(out.strip())
        except ValueError:
            return 0

    async def add_client(self, username: str, client_data: dict) -> dict:
        """Generate client certificate for IKEv2."""
        password = client_data.get("password", username)

        # Generate client key
        await self._run_cmd(
            f"ipsec pki --gen --type rsa --size 2048 --outform pem > {self.IPSEC_DIR}/private/{username}-key.pem",
            check=False,
        )
        # Generate client cert
        await self._run_cmd(
            f"ipsec pki --pub --in {self.IPSEC_DIR}/private/{username}-key.pem --type rsa | "
            f"ipsec pki --issue --lifetime 3650 "
            f"--cacert {self.IPSEC_DIR}/cacerts/ca-cert.pem "
            f"--cakey {self.IPSEC_DIR}/private/ca-key.pem "
            f"--dn 'CN={username}' --san '{username}' "
            f"--outform pem > {self.IPSEC_DIR}/certs/{username}-cert.pem",
            check=False,
        )
        # Generate .p12 for client
        await self._run_cmd(
            f"openssl pkcs12 -export -in {self.IPSEC_DIR}/certs/{username}-cert.pem "
            f"-inkey {self.IPSEC_DIR}/private/{username}-key.pem "
            f"-certfile {self.IPSEC_DIR}/cacerts/ca-cert.pem "
            f"-name '{username}' -out {self.IPSEC_DIR}/{username}.p12 "
            f"-passout pass:{password}",
            check=False,
        )

        # Add/Update EAP credentials in ipsec.secrets
        await self._run_cmd(f"sudo sed -i '/{username} : EAP/d' /etc/ipsec.secrets 2>/dev/null || true", check=False)
        await self._run_cmd(
            f"echo '{username} : EAP \"{password}\"' | sudo tee -a /etc/ipsec.secrets",
            check=False,
        )

        return {"cert_generated": True, "username": username}

    async def remove_client(self, username: str, protocol_data: dict):
        for ext in ["key.pem", "cert.pem"]:
            path = os.path.join(self.IPSEC_DIR, "private" if "key" in ext else "certs", f"{username}-{ext}")
            await self._run_cmd(f"sudo rm -f {path}", check=False)
        await self._run_cmd(f"sudo rm -f {self.IPSEC_DIR}/{username}.p12", check=False)
        await self._run_cmd(f"sudo sed -i '/{username}/d' /etc/ipsec.secrets", check=False)

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict) -> dict:
        config = await get_core_config("ikev2")
        if not config:
            return {}
        return {
            "type": "ikev2",
            "server": server_ip,
            "port": config.get("port", 500),
            "username": username,
            "ca_cert_available": os.path.exists(f"{self.IPSEC_DIR}/cacerts/ca-cert.pem"),
        }

    async def _write_config(self, config: dict):
        """Write ipsec.conf and ipsec.secrets."""
        _, server_ip, _ = await self._run_cmd(
            "curl -4 -s ifconfig.me || hostname -I | awk '{print $1}'",
            check=False,
        )
        server_ip = server_ip.strip() or "0.0.0.0"

        # Detect default interface
        _, default_iface, _ = await self._run_cmd(
            "ip route show default | awk '{print $5}' | head -1",
            check=False,
        )
        default_iface = default_iface.strip() or "eth0"

        subnet = config.get("subnet", "10.10.0.0/24")

        ipsec_conf = f"""config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid={server_ip}
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip={subnet}
    rightdns={config.get('dns', '1.1.1.1')}
    rightsendcert=never
    eap_identity=%identity
    ike={config.get('cipher', 'aes256-sha256-modp2048')}!
    esp={config.get('cipher', 'aes256-sha256-modp2048')}!
    ikelifetime={config.get('lifetime', '24h')}
    margintime={config.get('margintime', '3h')}
"""
        with open("/tmp/cc_ipsec.conf", "w") as f:
            f.write(ipsec_conf)
        await self._run_cmd("sudo mv /tmp/cc_ipsec.conf /etc/ipsec.conf", check=False)

        # Secrets file (preserve existing entries)
        if not os.path.exists("/etc/ipsec.secrets"):
            secrets = f": RSA server-key.pem\n"
            with open("/tmp/cc_ipsec.secrets", "w") as f:
                f.write(secrets)
            await self._run_cmd("sudo mv /tmp/cc_ipsec.secrets /etc/ipsec.secrets", check=False)
        else:
            # Ensure RSA line exists
            await self._run_cmd(
                "grep -q 'RSA server-key.pem' /etc/ipsec.secrets || "
                "echo ': RSA server-key.pem' | sudo tee -a /etc/ipsec.secrets",
                check=False,
            )

        # NAT rules
        await self._run_cmd(
            f"sudo iptables -t nat -C POSTROUTING -s {subnet} -o {default_iface} -j MASQUERADE 2>/dev/null || "
            f"sudo iptables -t nat -A POSTROUTING -s {subnet} -o {default_iface} -j MASQUERADE",
            check=False,
        )
        await self._run_cmd(
            f"sudo iptables -C FORWARD -s {subnet} -j ACCEPT 2>/dev/null || "
            f"sudo iptables -A FORWARD -s {subnet} -j ACCEPT",
            check=False,
        )
