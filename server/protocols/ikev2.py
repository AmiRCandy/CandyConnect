"""
CandyConnect - IKEv2/IPSec Protocol Manager (strongSwan)
"""
import os, time, shlex
from protocols.base import BaseProtocol
from database import get_core_config, get_core_status, set_core_status, add_log
from system_info import get_public_ip
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

            # Read cert_validity from config (default 3650 days)
            config = await get_core_config("ikev2") or {}
            cert_validity = config.get("cert_validity", 3650)
            pki = await self._pki_cmd()
            server_ip = await self._server_address()

            # install() runs on every server start: only create the CA / server cert once,
            # otherwise every restart would invalidate the CA clients have imported.
            ca_key = f"{self.IPSEC_DIR}/private/ca-key.pem"
            ca_cert = f"{self.IPSEC_DIR}/cacerts/ca-cert.pem"
            if not (os.path.exists(ca_key) and os.path.exists(ca_cert)):
                await add_log("INFO", self.PROTOCOL_NAME, "Generating CA certificate...")
                await self._run_cmd(
                    f"{pki} --gen --type rsa --size 4096 --outform pem > {ca_key}",
                    check=False, timeout=180,
                )
                await self._run_cmd(
                    f"{pki} --self --ca --lifetime {cert_validity} --in {ca_key} "
                    f"--type rsa --dn 'CN=CandyConnect VPN CA' --outform pem > {ca_cert}",
                    check=False,
                )
                # New CA -> the old server cert is no longer valid
                await self._run_cmd(f"rm -f {self.IPSEC_DIR}/certs/server-cert.pem", check=False)

            # (Re)issue the server cert if missing or issued for another address
            server_key = f"{self.IPSEC_DIR}/private/server-key.pem"
            server_cert = f"{self.IPSEC_DIR}/certs/server-cert.pem"
            issued_for = ""
            if os.path.exists(server_cert):
                _, issued_for, _ = await self._run_cmd(f"{pki} --print --in {server_cert}", check=False)
            if not os.path.exists(server_cert) or f"CN={server_ip}" not in issued_for:
                if not os.path.exists(server_key):
                    await self._run_cmd(
                        f"{pki} --gen --type rsa --size 4096 --outform pem > {server_key}",
                        check=False, timeout=180,
                    )
                san = f"--san '{server_ip}' --san '@{server_ip}'"
                await self._run_cmd(
                    f"{pki} --pub --in {server_key} --type rsa | "
                    f"{pki} --issue --lifetime {cert_validity} --cacert {ca_cert} "
                    f"--cakey {ca_key} "
                    f"--dn 'CN={server_ip}' {san} "
                    f"--flag serverAuth --flag ikeIntermediate "
                    f"--outform pem > {server_cert}",
                    check=False,
                )
            await self._run_cmd(f"chmod 600 {self.IPSEC_DIR}/private/*.pem", check=False)

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
            rc, _, err = await self._run_cmd("sudo systemctl restart strongswan-starter", check=False)

            if rc != 0:
                # Docker fallback
                rc2, _, err2 = await self._run_cmd("sudo ipsec start", check=False)
                if rc2 != 0 and not await self.is_running():
                    error_msg = err2 or err or "StrongSwan failed to start"
                    await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to start: {error_msg}")
                    return False

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
                await add_log("ERROR", self.PROTOCOL_NAME, "IKEv2 failed to start (no process running)")
                return False
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Start exception: {e}")
            return False

    async def stop(self) -> bool:
        try:
            rc, _, _ = await self._run_cmd("pgrep xl2tpd", check=False)
            if rc == 0:
                # L2TP/IPSec shares strongSwan: only unload the IKEv2 connection
                await self._run_cmd("sudo ipsec down ikev2-vpn", check=False)
                self._write_ipsec_conf(with_ikev2=False)
                await self._run_cmd("sudo ipsec reload", check=False)
            else:
                await self._run_cmd("sudo systemctl stop strongswan-starter", check=False)
                await self._run_cmd("sudo systemctl stop ipsec", check=False)
                await self._run_cmd("sudo ipsec stop", check=False)

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
        try:
            with open("/etc/ipsec.conf") as f:
                if "conn ikev2-vpn" not in f.read():
                    return False
        except OSError:
            return False
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
        # Count ESTABLISHED IKE SAs. We avoid piping into grep -c because the
        # exit code of a pipe reflects grep (1 when no match), not ipsec.
        rc, out, _ = await self._run_cmd("sudo ipsec statusall 2>/dev/null", check=False)
        if rc != 0 or not out:
            # Try swanctl as fallback (newer strongSwan)
            rc2, out2, _ = await self._run_cmd("sudo swanctl --list-sas 2>/dev/null", check=False)
            out = out2 if rc2 == 0 else ""
        count = sum(1 for line in out.splitlines() if "ESTABLISHED" in line)
        return count

    async def get_traffic(self) -> dict:
        """Sum RX/TX bytes across all VPN-related network interfaces used by IKEv2.

        IKEv2/IPSec traffic flows through the default network interface (no
        separate tun device).  We read byte counters from /proc/net/dev for
        interfaces whose names match common strongSwan virtual IP patterns, or
        fall back to reading the ipsec traffic stats via 'ip -s xfrm state'.
        """
        total_rx = 0
        total_tx = 0
        try:
            # Method 1: xfrm state statistics (kernel IPSec SA byte counters)
            rc, out, _ = await self._run_cmd("sudo ip -s xfrm state 2>/dev/null", check=False)
            if rc == 0 and out:
                current_rx = 0
                current_tx = 0
                # ip -s xfrm state output has blocks per SA; each SA has a
                # "stats:" section followed by "current bytes: X, ..." lines.
                # We sum up all of them.
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("current bytes:"):
                        # "current bytes: 12345678"
                        parts = line.split()
                        if len(parts) >= 3:
                            try:
                                val = int(parts[2].rstrip(","))
                                # Alternate SA directions: odd = outbound, even = inbound
                                # We just sum all SA byte counters and divide by 2
                                current_rx += val
                            except ValueError:
                                pass
                if current_rx > 0:
                    total_rx = current_rx // 2
                    total_tx = current_rx // 2
        except Exception:
            pass
        return {"in": total_rx, "out": total_tx}

    async def add_client(self, username: str, client_data: dict) -> dict:
        """Register EAP-MSCHAPv2 credentials (and a client certificate) for IKEv2."""
        password = client_data.get("password", username)

        # Read cert_validity from config (default 3650 days)
        config = await get_core_config("ikev2") or {}
        cert_validity = config.get("cert_validity", 3650)
        pki = await self._pki_cmd()
        key_path = f"{self.IPSEC_DIR}/private/{username}-key.pem"
        cert_path = f"{self.IPSEC_DIR}/certs/{username}-cert.pem"

        if os.path.exists(f"{self.IPSEC_DIR}/cacerts/ca-cert.pem") and not os.path.exists(cert_path):
            # Generate client key
            await self._run_cmd(
                f"{pki} --gen --type rsa --size 2048 --outform pem > {key_path}",
                check=False,
            )
            # Generate client cert
            await self._run_cmd(
                f"{pki} --pub --in {key_path} --type rsa | "
                f"{pki} --issue --lifetime {cert_validity} "
                f"--cacert {self.IPSEC_DIR}/cacerts/ca-cert.pem "
                f"--cakey {self.IPSEC_DIR}/private/ca-key.pem "
                f"--dn 'CN={username}' --san '{username}' "
                f"--outform pem > {cert_path}",
                check=False,
            )
            # Generate .p12 for client
            await self._run_cmd(
                f"openssl pkcs12 -export -in {cert_path} "
                f"-inkey {key_path} "
                f"-certfile {self.IPSEC_DIR}/cacerts/ca-cert.pem "
                f"-name '{username}' -out {self.IPSEC_DIR}/{username}.p12 "
                f"-passout pass:{shlex.quote(password)}",
                check=False,
            )

        # Add/Update EAP credentials in ipsec.secrets
        _set_secret_line(f"{username} : EAP ", f'{username} : EAP "{_escape_secret(password)}"')
        await self._run_cmd("sudo ipsec rereadsecrets", check=False)

        return {"cert_generated": True, "username": username}

    async def remove_client(self, username: str, protocol_data: dict):
        for ext in ["key.pem", "cert.pem"]:
            path = os.path.join(self.IPSEC_DIR, "private" if "key" in ext else "certs", f"{username}-{ext}")
            await self._run_cmd(f"sudo rm -f {path}", check=False)
        await self._run_cmd(f"sudo rm -f {self.IPSEC_DIR}/{username}.p12", check=False)
        _set_secret_line(f"{username} : EAP ", None)
        await self._run_cmd("sudo ipsec rereadsecrets", check=False)

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        config = await get_core_config("ikev2")
        if not config:
            return {}
        ca_cert = ""
        try:
            with open(f"{self.IPSEC_DIR}/cacerts/ca-cert.pem") as f:
                ca_cert = f.read()
        except OSError:
            pass
        return {
            "type": "ikev2",
            "server": server_ip,
            "port": config.get("port", 500),
            "username": username,
            "remote_id": server_ip,
            "auth": "eap-mschapv2",
            "ca_cert_available": bool(ca_cert),
            "ca_cert": ca_cert,
        }

    async def _write_config(self, config: dict):
        """Write ipsec.conf and ipsec.secrets."""
        server_ip = await self._server_address()
        default_iface = await self._default_iface()
        subnet = config.get("subnet", "10.10.0.0/24")
        cipher = config.get("cipher", "aes256-sha256-modp2048")
        # The configured cipher first, then proposals used by the native Windows,
        # macOS/iOS and Android (strongSwan) clients; a single strict proposal
        # rejects most of them.
        ike = f"{cipher},aes256-sha256-ecp256,aes256gcm16-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024!"
        esp_cipher = "-".join(p for p in cipher.split("-") if not p.startswith(("modp", "ecp")))
        esp = f"{esp_cipher},aes256gcm16,aes256-sha256,aes256-sha1,aes128-sha1!"

        self._ikev2_conn = f"""conn ikev2-vpn
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
    ike={ike}
    esp={esp}
    ikelifetime={config.get('lifetime', '24h')}
    margintime={config.get('margintime', '3h')}
"""
        self._write_ipsec_conf(with_ikev2=True)

        # Server key for the RSA cert (keep EAP/PSK entries)
        if not os.path.exists("/etc/ipsec.secrets"):
            open("/etc/ipsec.secrets", "w").close()
            os.chmod("/etc/ipsec.secrets", 0o600)
        _set_secret_line(": RSA ", ": RSA server-key.pem")

        # NAT rules
        await self._run_cmd(
            f"sudo iptables -t nat -C POSTROUTING -s {subnet} -o {default_iface} -j MASQUERADE 2>/dev/null || "
            f"sudo iptables -t nat -A POSTROUTING -s {subnet} -o {default_iface} -j MASQUERADE",
            check=False,
        )
        await self._run_cmd(
            f"sudo iptables -C FORWARD -s {subnet} -j ACCEPT 2>/dev/null || "
            f"sudo iptables -I FORWARD -s {subnet} -j ACCEPT; "
            f"sudo iptables -C FORWARD -d {subnet} -j ACCEPT 2>/dev/null || "
            f"sudo iptables -I FORWARD -d {subnet} -j ACCEPT",
            check=False,
        )

    _ikev2_conn = ""

    def _write_ipsec_conf(self, with_ikev2: bool):
        """Write /etc/ipsec.conf. Always includes /etc/ipsec.d/*.conf so the
        L2TP/IPSec connection (written there by the L2TP manager) is loaded too."""
        conf = IPSEC_CONF_HEADER
        if with_ikev2 and self._ikev2_conn:
            conf += "\n" + self._ikev2_conn
        conf += "\ninclude /etc/ipsec.d/*.conf\n"
        with open("/etc/ipsec.conf", "w") as f:
            f.write(conf)

    async def _server_address(self) -> str:
        """Address clients connect to (panel override first, then public IP)."""
        panel_cfg = await get_core_config("candyconnect") or {}
        return panel_cfg.get("server_ip") or await get_public_ip()

    async def _pki_cmd(self) -> str:
        """strongSwan's pki tool: `pki` (strongswan-pki) or the legacy `ipsec pki` wrapper."""
        rc, _, _ = await self._run_cmd("command -v pki", check=False)
        return "pki" if rc == 0 else "ipsec pki"


IPSEC_CONF_HEADER = """config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no
"""


def _escape_secret(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _set_secret_line(prefix: str, line, path: str = "/etc/ipsec.secrets"):
    """Replace (or remove when line is None) the ipsec.secrets line starting with prefix."""
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    lines = [l for l in lines if not l.startswith(prefix)]
    if line is not None:
        lines.append(line)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
