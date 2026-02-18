"""
CandyConnect - L2TP/IPSec Protocol Manager
"""
import os, time
from protocols.base import BaseProtocol
from database import get_core_config, get_core_status, set_core_status, add_log
from system_info import get_public_ip


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
            
            # Try systemctl
            rc, _, err = await self._run_cmd("sudo systemctl enable xl2tpd && sudo systemctl start xl2tpd", check=False)
            
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
            await self._run_cmd("sudo systemctl stop ipsec", check=False)
            await self._run_cmd("sudo ipsec stop", check=False)
            
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
        rc, out, _ = await self._run_cmd("ss -tnp sport = :1701 | tail -n +2 | wc -l", check=False)
        try:
            return int(out.strip())
        except ValueError:
            return 0

    async def add_client(self, username: str, client_data: dict) -> dict:
        password = client_data.get("password", username)
        await self._run_cmd(
            f"grep -q '{username}' /etc/ppp/chap-secrets 2>/dev/null || "
            f"echo '{username} * {password} *' | sudo tee -a /etc/ppp/chap-secrets",
            check=False,
        )
        return {"username": username}

    async def remove_client(self, username: str, protocol_data: dict):
        await self._run_cmd(f"sudo sed -i '/^{username} /d' /etc/ppp/chap-secrets", check=False)

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
        _, default_iface, _ = await self._run_cmd(
            "ip route show default | awk '{print $5}' | head -1", check=False,
        )
        default_iface = default_iface.strip() or "eth0"

        server_ip = await get_public_ip()

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
ppp debug = yes
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
    ikeport={ipsec_port}
"""
        with open("/tmp/cc_l2tp_ipsec.conf", "w") as f:
            f.write(ipsec_conf)
        await self._run_cmd("sudo mkdir -p /etc/ipsec.d", check=False)
        await self._run_cmd(
            "sudo cp /tmp/cc_l2tp_ipsec.conf /etc/ipsec.d/l2tp.conf",
            check=False,
        )

        # PSK secret - update if changed
        await self._run_cmd(
            f"sudo sed -i '/%any %any : PSK/d' /etc/ipsec.secrets 2>/dev/null || true",
            check=False,
        )
        await self._run_cmd(
            f"echo '%any %any : PSK \"{psk}\"' | sudo tee -a /etc/ipsec.secrets",
            check=False,
        )

        # NAT
        subnet_base = local_ip.rsplit(".", 1)[0]
        await self._run_cmd(
            f"sudo iptables -t nat -C POSTROUTING -s {subnet_base}.0/24 -o {default_iface} -j MASQUERADE 2>/dev/null || "
            f"sudo iptables -t nat -A POSTROUTING -s {subnet_base}.0/24 -o {default_iface} -j MASQUERADE",
            check=False,
        )
