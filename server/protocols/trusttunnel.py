"""
CandyConnect - TrustTunnel Protocol Manager
TrustTunnel (https://github.com/TrustTunnel/TrustTunnel) by AdGuard: an
HTTP/1.1, HTTP/2 and QUIC (HTTP/3) based VPN. Users live in credentials.toml;
client configs are exported by the endpoint itself (tt:// deep link / TOML).
"""
import os
from protocols.base import BaseProtocol
from database import get_core_config, add_log
from config import CORE_DIR, PANEL_DOMAIN

TRUSTTUNNEL_VERSION = "1.1.0"


def _toml_str(value) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


class TrustTunnelProtocol(BaseProtocol):
    PROTOCOL_ID = "trusttunnel"
    PROTOCOL_NAME = "TrustTunnel"
    DEFAULT_PORT = 9443

    INSTALL_DIR = "/opt/trusttunnel"
    BIN = "/opt/trusttunnel/trusttunnel_endpoint"
    CONF_DIR = os.path.join(CORE_DIR, "trusttunnel")

    async def install(self) -> bool:
        try:
            if os.path.exists(self.BIN):
                return True
            await add_log("INFO", self.PROTOCOL_NAME, f"Installing TrustTunnel endpoint {TRUSTTUNNEL_VERSION}...")
            # Release tarball: trusttunnel-v<ver>-linux-<arch>/{trusttunnel_endpoint,setup_wizard,...}
            # (the official install.sh may prompt interactively, so it is not used here)
            arch = self._arch()
            name = f"trusttunnel-v{TRUSTTUNNEL_VERSION}-linux-{arch}"
            url = f"https://github.com/TrustTunnel/TrustTunnel/releases/download/v{TRUSTTUNNEL_VERSION}/{name}.tar.gz"
            os.makedirs(self.INSTALL_DIR, exist_ok=True)
            tmp = f"/tmp/{name}.tar.gz"
            err = ""
            if await self._download(url, tmp):
                rc, _, err = await self._run_cmd(
                    f"tar -xzf {tmp} -C {self.INSTALL_DIR} --strip-components=1 && "
                    f"chmod 755 {self.BIN} {self.INSTALL_DIR}/setup_wizard; rm -f {tmp}",
                    check=False,
                )
            else:
                err = f"download failed: {url}"
            if not os.path.exists(self.BIN):
                await add_log("ERROR", self.PROTOCOL_NAME, f"Installation failed: {err[-300:]}")
                return False
            await add_log("INFO", self.PROTOCOL_NAME, "TrustTunnel endpoint installed")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Installation error: {e}")
            return False

    async def start(self) -> bool:
        try:
            if not os.path.exists(self.BIN):
                await add_log("ERROR", self.PROTOCOL_NAME, "trusttunnel_endpoint not found. Run install first.")
                return False
            config = await get_core_config("trusttunnel") or {}
            if not await self._write_config(config):
                return False
            await self._run_cmd("sudo pkill -x trusttunnel_endp", check=False)
            port = int(config.get("port", self.DEFAULT_PORT))
            await self._run_cmd(
                f"sudo iptables -C INPUT -p tcp --dport {port} -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p tcp --dport {port} -j ACCEPT; "
                f"sudo iptables -C INPUT -p udp --dport {port} -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p udp --dport {port} -j ACCEPT",
                check=False,
            )
            pid = await self._start_process(f"{self.BIN} vpn.toml hosts.toml", cwd=self.CONF_DIR)
            if not pid:
                await add_log("ERROR", self.PROTOCOL_NAME, "Failed to start (see logs/trusttunnel.log)")
                return False
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Start exception: {e}")
            return False

    async def get_version(self) -> str:
        return TRUSTTUNNEL_VERSION if os.path.exists(self.BIN) else ""

    async def get_active_connections(self) -> int:
        config = await get_core_config("trusttunnel") or {}
        port = int(config.get("port", self.DEFAULT_PORT))
        rc, out, _ = await self._run_cmd(f"ss -tn state established '( sport = :{port} )' 2>/dev/null", check=False)
        if rc != 0:
            return 0
        return sum(1 for l in out.splitlines() if l.strip() and not l.startswith(("Recv-Q", "Netid")))

    # ── Users ──

    async def add_client(self, username: str, client_data: dict) -> dict:
        password = client_data.get("password") or username
        users = self._read_credentials()
        if users.get(username) != password:
            users[username] = password
            self._write_credentials(users)
            if await self.is_running():
                await self.restart()
        return {"username": username}

    async def remove_client(self, username: str, protocol_data: dict):
        users = self._read_credentials()
        if username in users:
            del users[username]
            self._write_credentials(users)
            if await self.is_running():
                await self.restart()

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        config = await get_core_config("trusttunnel") or {}
        port = int(config.get("port", self.DEFAULT_PORT))
        result = {
            "type": "trusttunnel",
            "server": server_ip,
            "port": port,
            "hostname": self._hostname(config),
            "username": username,
        }
        if not os.path.exists(self.BIN) or not os.path.exists(os.path.join(self.CONF_DIR, "vpn.toml")):
            return result
        if username not in self._read_credentials():
            await self.add_client(username, protocol_data or {})
        base = f"{self.BIN} vpn.toml hosts.toml -c '{username}' -a {server_ip}:{port} --name 'CandyConnect'"
        rc, link, _ = await self._run_cmd(f"cd {self.CONF_DIR} && {base}", check=False)
        if rc == 0 and "tt://" in link:
            result["link"] = link[link.index("tt://"):].split()[0]
        rc, toml_cfg, _ = await self._run_cmd(f"cd {self.CONF_DIR} && {base} --format toml", check=False)
        if rc == 0 and toml_cfg.strip():
            result["endpoint_config"] = toml_cfg
        return result

    # ── Config files ──

    def _hostname(self, config: dict) -> str:
        return config.get("hostname") or PANEL_DOMAIN

    def _read_credentials(self) -> dict:
        path = os.path.join(self.CONF_DIR, "credentials.toml")
        users, cur = {}, None
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line == "[[client]]":
                        cur = {}
                        continue
                    if cur is not None and "=" in line:
                        k, v = line.split("=", 1)
                        v = v.strip()
                        if v.startswith('"') and v.endswith('"'):
                            v = v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                        cur[k.strip()] = v
                        if "username" in cur and "password" in cur:
                            users[cur["username"]] = cur["password"]
                            cur = None
        except OSError:
            pass
        return users

    def _write_credentials(self, users: dict):
        os.makedirs(self.CONF_DIR, exist_ok=True)
        path = os.path.join(self.CONF_DIR, "credentials.toml")
        body = "".join(f"[[client]]\nusername = {_toml_str(u)}\npassword = {_toml_str(p)}\n\n"
                       for u, p in users.items())
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, 0o600)

    async def _write_config(self, config: dict) -> bool:
        os.makedirs(self.CONF_DIR, exist_ok=True)
        hostname = self._hostname(config)
        port = int(config.get("port", self.DEFAULT_PORT))

        # TLS certificate: configured files, else a self-signed one (embedded in exported client configs)
        cert = config.get("cert_path") or os.path.join(self.CONF_DIR, "cert.pem")
        key = config.get("key_path") or os.path.join(self.CONF_DIR, "key.pem")
        if not config.get("cert_path"):
            stamp = os.path.join(self.CONF_DIR, ".cert_host")
            current = open(stamp).read().strip() if os.path.exists(stamp) else ""
            if not (os.path.exists(cert) and os.path.exists(key)) or current != hostname:
                rc, _, err = await self._run_cmd(
                    f"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
                    f"-keyout {key} -out {cert} -days 3650 -subj '/CN={hostname}' "
                    f"-addext 'subjectAltName=DNS:{hostname}'",
                    check=False,
                )
                if rc != 0:
                    await add_log("ERROR", self.PROTOCOL_NAME, f"Certificate generation failed: {err}")
                    return False
                with open(stamp, "w") as f:
                    f.write(hostname)
                os.chmod(key, 0o600)

        protocols = ""
        if config.get("enable_http1", True):
            protocols += "\n[listen_protocols.http1]\nupload_buffer_size = 32768\n"
        if config.get("enable_http2", True):
            protocols += "\n[listen_protocols.http2]\nmax_concurrent_streams = 1000\n"
        if config.get("enable_quic", True) or not protocols:
            protocols += "\n[listen_protocols.quic]\nrecv_udp_payload_size = 1350\nsend_udp_payload_size = 1350\n"

        vpn = (
            f'listen_address = "0.0.0.0:{port}"\n'
            f'ipv6_available = {"true" if config.get("ipv6_available", True) else "false"}\n'
            f'allow_private_network_connections = {"true" if config.get("allow_private_network_connections", False) else "false"}\n'
            'credentials_file = "credentials.toml"\n'
            "\n[listen_protocols]\n" + protocols +
            "\n[forward_protocol]\ndirect = {}\n"
        )
        hosts = (
            "[[main_hosts]]\n"
            f"hostname = {_toml_str(hostname)}\n"
            f"cert_chain_path = {_toml_str(cert)}\n"
            f"private_key_path = {_toml_str(key)}\n"
        )
        with open(os.path.join(self.CONF_DIR, "vpn.toml"), "w") as f:
            f.write(vpn)
        with open(os.path.join(self.CONF_DIR, "hosts.toml"), "w") as f:
            f.write(hosts)

        # Make sure every TrustTunnel-enabled client exists in credentials.toml
        from database import get_all_clients, client_limit_reason
        users = {}
        for c in await get_all_clients():
            if c.get("enabled", True) and (c.get("protocols") or {}).get("trusttunnel") and not client_limit_reason(c):
                users[c["username"]] = c.get("password") or c["username"]
        self._write_credentials(users)
        return True
