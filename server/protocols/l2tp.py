"""
CandyConnect - L2TP/IPSec Protocol Manager
"""
import os, time, ipaddress
from protocols.base import BaseProtocol
from database import get_core_config, get_core_status, set_core_status, add_log
from system_info import get_public_ip
from protocols.ikev2 import IPSEC_CONF_HEADER, _set_secret_line, _escape_secret


class L2TPProtocol(BaseProtocol):
    PROTOCOL_ID = "l2tp"
    PROTOCOL_NAME = "L2TP"
    DEFAULT_PORT = 1701

    async def install(self) -> bool:
        try:
            await add_log("INFO", self.PROTOCOL_NAME, "Configuring L2TP/IPSec...")
            
            # Check if installed
            if not await self._is_installed("xl2tpd"):
                if not await self._apt_install("xl2tpd strongswan"):
                    return False
                    
            await self._run_cmd("sudo sysctl -w net.ipv4.ip_forward=1", check=False)
            await add_log("INFO", self.PROTOCOL_NAME, "L2TP/IPSec configured successfully")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Installation error: {e}")
            return False

    async def start(self) -> bool:
        try:
            config = await get_core_config("l2tp")
            if not config:
                await add_log("ERROR", self.PROTOCOL_NAME, "No L2TP config found")
                return False
            await self._write_config(config)
            await self._ensure_ipsec()
            
            # Try systemctl
            rc, _, err = await self._run_cmd("sudo systemctl enable xl2tpd && sudo systemctl restart xl2tpd", check=False)
            
            if rc != 0:
                # Fallback: direct start
                pid = await self._start_process("xl2tpd -D")
                if not pid:
                    error_msg = err or "xl2tpd binary failed"
                    await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to start: {error_msg}")
                    return False
            else:
                # Track for status
                version = await self.get_version()
                await set_core_status(self.PROTOCOL_ID, {
                    "status": "running", "pid": None,
                    "started_at": int(time.time()), "version": version,
                })

            await add_log("INFO", self.PROTOCOL_NAME, "L2TP started")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Start exception: {e}")
            return False

    async def stop(self) -> bool:
        try:
            await self._run_cmd("sudo systemctl stop xl2tpd", check=False)
            await self._run_cmd("sudo pkill xl2tpd", check=False)
            # strongSwan is shared with IKEv2, so only drop the L2TP connection
            await self._run_cmd("sudo ipsec down L2TP-PSK", check=False)
            
            status = await get_core_status(self.PROTOCOL_ID)
            await set_core_status(self.PROTOCOL_ID, {
                "status": "stopped", "pid": None,
                "started_at": None, "version": status.get("version", ""),
            })
            await add_log("INFO", self.PROTOCOL_NAME, "L2TP stopped")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to stop: {e}")
            return False

    async def is_running(self) -> bool:
        if await self._is_service_active("xl2tpd"):
            return True
        rc, _, _ = await self._run_cmd("pgrep xl2tpd", check=False)
        return rc == 0

    async def get_version(self) -> str:
        rc, out, _ = await self._run_cmd("xl2tpd --version 2>&1 || dpkg -s xl2tpd | grep Version", check=False)
        if out:
            for part in out.split():
                if any(c.isdigit() for c in part):
                    return part.strip().lstrip("Version:").strip()
        return ""

    async def get_active_connections(self) -> int:
        # L2TP/IPSec uses PPP interfaces (ppp0, ppp1, ...) for each connected client.
        # Count the number of pppX interfaces that are currently UP.
        rc, out, _ = await self._run_cmd(
            "ip link show | grep -c '^[0-9]*: ppp'",
            check=False,
        )
        try:
            count = int(out.strip())
            return count
        except ValueError:
            pass
        # Fallback: count via /proc/net/dev
        try:
            with open("/proc/net/dev") as f:
                content = f.read()
            return sum(1 for line in content.splitlines() if line.strip().startswith("ppp"))
        except Exception:
            return 0

    async def get_traffic(self) -> dict:
        """Sum RX/TX bytes across all pppX interfaces (one per L2TP client)."""
        total_rx = 0
        total_tx = 0
        try:
            with open("/proc/net/dev") as f:
                content = f.read()
            for line in content.splitlines():
                line = line.strip()
                if not line.startswith("ppp"):
                    continue
                iface, rest = line.split(":", 1)
                fields = rest.split()
                if len(fields) >= 9:
                    try:
                        total_rx += int(fields[0])
                        total_tx += int(fields[8])
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass
        return {"in": total_rx, "out": total_tx}

    async def add_client(self, username: str, client_data: dict) -> dict:
        password = str(client_data.get("password", username)).replace('"', '')
        # Replace any existing line so password changes take effect
        _set_chap_secret(username, f'"{username}" * "{password}" *')
        return {"username": username}

    async def remove_client(self, username: str, protocol_data: dict):
        _set_chap_secret(username, None)

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        config = await get_core_config("l2tp")
        if not config:
            return {}
        return {
            "type": "l2tp",
            "server": server_ip,
            "port": config.get("port", 1701),
            "psk": config.get("psk", ""),
            "username": username,
        }

    async def _write_config(self, config: dict):
        default_iface = await self._default_iface()

        local_ip = config.get("local_ip", "10.20.0.1")
        remote_range = config.get("remote_range", "10.20.0.10-10.20.0.250")
        remote_start = remote_range.split("-")[0] if "-" in remote_range else "10.20.0.10"
        remote_end = remote_range.split("-")[1] if "-" in remote_range else "10.20.0.250"

        # xl2tpd config
        xl2tpd_conf = f"""[global]
port = {config.get('port', 1701)}

[lns default]
ip range = {remote_start}-{remote_end}
local ip = {local_ip}
require chap = yes
refuse pap = yes
require authentication = yes
name = CandyConnectVPN
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
"""
        with open("/tmp/cc_xl2tpd.conf", "w") as f:
            f.write(xl2tpd_conf)
        await self._run_cmd("sudo mv /tmp/cc_xl2tpd.conf /etc/xl2tpd/xl2tpd.conf", check=False)

        # PPP options
        ppp_opts = f"""ipcp-accept-local
ipcp-accept-remote
ms-dns {config.get('dns', '1.1.1.1')}
noccp
auth
require-mschap-v2
lcp-echo-failure 4
lcp-echo-interval 30
mtu {config.get('mtu', 1400)}
mru {config.get('mru', 1400)}
nodefaultroute
proxyarp
connect-delay 5000
"""
        with open("/tmp/cc_ppp_options.xl2tpd", "w") as f:
            f.write(ppp_opts)
        await self._run_cmd("sudo mkdir -p /etc/ppp", check=False)
        await self._run_cmd("sudo mv /tmp/cc_ppp_options.xl2tpd /etc/ppp/options.xl2tpd", check=False)

        # IPSec config for L2TP
        psk = config.get("psk", "CandyConnect_L2TP_PSK")
        ipsec_port = config.get("ipsec_port", 500)
        l2tp_port = config.get("port", 1701)
        ipsec_conf = f"""conn L2TP-PSK
    authby=secret
    pfs=no
    auto=add
    keyexchange=ikev1
    type=transport
    left=%defaultroute
    leftprotoport=17/{l2tp_port}
    right=%any
    rightprotoport=17/%any
    rekey=no
    forceencaps=yes
    ike=aes256-sha1-modp1024,aes128-sha1-modp1024,aes256-sha256-modp2048,3des-sha1-modp1024!
    esp=aes256-sha1,aes128-sha1,aes256-sha256,3des-sha1!
"""
        with open("/tmp/cc_l2tp_ipsec.conf", "w") as f:
            f.write(ipsec_conf)
        await self._run_cmd("sudo mkdir -p /etc/ipsec.d", check=False)
        await self._run_cmd(
            "sudo cp /tmp/cc_l2tp_ipsec.conf /etc/ipsec.d/l2tp.conf",
            check=False,
        )

        # PSK secret - update if changed
        if not os.path.exists("/etc/ipsec.secrets"):
            open("/etc/ipsec.secrets", "w").close()
        _set_secret_line("%any %any : PSK ", f'%any %any : PSK "{_escape_secret(psk)}"')

        # NAT + forwarding for the PPP clients
        try:
            subnet = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
        except ValueError:
            subnet = "10.20.0.0/24"
        await self._run_cmd(
            f"sudo iptables -t nat -C POSTROUTING -s {subnet} -o {default_iface} -j MASQUERADE 2>/dev/null || "
            f"sudo iptables -t nat -A POSTROUTING -s {subnet} -o {default_iface} -j MASQUERADE; "
            f"sudo iptables -C FORWARD -i ppp+ -j ACCEPT 2>/dev/null || sudo iptables -I FORWARD -i ppp+ -j ACCEPT; "
            f"sudo iptables -C FORWARD -o ppp+ -j ACCEPT 2>/dev/null || sudo iptables -I FORWARD -o ppp+ -j ACCEPT",
            check=False,
        )

    async def _ensure_ipsec(self):
        """Make strongSwan load /etc/ipsec.d/l2tp.conf and (re)start or reload it."""
        try:
            with open("/etc/ipsec.conf") as f:
                conf = f.read()
        except OSError:
            conf = IPSEC_CONF_HEADER
        if "include /etc/ipsec.d/*.conf" not in conf:
            conf = conf.rstrip("\n") + "\n\ninclude /etc/ipsec.d/*.conf\n"
            with open("/etc/ipsec.conf", "w") as f:
                f.write(conf)

        if await self._is_service_active("strongswan-starter") or await self._is_service_active("ipsec"):
            await self._run_cmd("sudo ipsec reload && sudo ipsec rereadsecrets", check=False)
            return
        await self._run_cmd("sudo systemctl enable strongswan-starter", check=False)
        rc, _, _ = await self._run_cmd("sudo systemctl start strongswan-starter", check=False)
        if rc != 0:
            rc2, _, _ = await self._run_cmd("pgrep charon", check=False)
            if rc2 == 0:
                await self._run_cmd("sudo ipsec reload && sudo ipsec rereadsecrets", check=False)
            else:
                await self._run_cmd("sudo ipsec start", check=False)


def _set_chap_secret(username: str, line, path: str = "/etc/ppp/chap-secrets"):
    """Replace (or remove when line is None) a user's entry in chap-secrets."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    lines = [l for l in lines
             if not (l.split()[:1] and l.split()[0].strip('"') == username)]
    if line is not None:
        lines.append(line)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
