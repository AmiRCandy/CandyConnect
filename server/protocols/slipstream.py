"""
CandyConnect - SlipStream Protocol Manager
SlipStream (https://github.com/EndPositive/slipstream) tunnels TCP over DNS
using QUIC. Like DNSTT, the tunnel is forwarded to the local SSH server and
each client logs in with its own SSH account (shared with DNSTT).
"""
import os
from protocols.base import BaseProtocol
from database import get_core_config, update_core_config, add_log

SLIPSTREAM_VERSION = "v0.1.1"


class SlipStreamProtocol(BaseProtocol):
    PROTOCOL_ID = "slipstream"
    PROTOCOL_NAME = "SlipStream"
    DEFAULT_PORT = 5301

    BIN = "/usr/local/bin/slipstream-server"

    async def _binary(self) -> str:
        if os.path.exists(self.BIN):
            return self.BIN
        rc, path, _ = await self._run_cmd("command -v slipstream-server", check=False)
        return path.strip() if rc == 0 and path.strip() else ""

    async def install(self) -> bool:
        try:
            if await self._binary():
                return True
            arch = {"x86_64": "x86_64", "aarch64": "arm64"}.get(self._arch())
            if not arch:
                await add_log("ERROR", self.PROTOCOL_NAME, f"Unsupported architecture: {self._arch()}")
                return False
            await add_log("INFO", self.PROTOCOL_NAME, f"Downloading slipstream-server {SLIPSTREAM_VERSION}...")
            url = (f"https://github.com/EndPositive/slipstream/releases/download/{SLIPSTREAM_VERSION}/"
                   f"slipstream-server-{SLIPSTREAM_VERSION}-linux-{arch}")
            if not await self._download(url, self.BIN):
                await add_log("ERROR", self.PROTOCOL_NAME,
                              f"Install failed. Put the binary at {self.BIN} manually ({url})")
                return False
            await self._run_cmd(f"chmod 755 {self.BIN}", check=False)
            # The release binary is dynamically linked against OpenSSL 3
            rc, out, _ = await self._run_cmd(f"ldd {self.BIN} | grep 'not found'", check=False)
            if rc == 0 and out:
                await add_log("ERROR", self.PROTOCOL_NAME,
                              f"Missing libraries (Ubuntu 22.04+ / Debian 12+ required): {out}")
                return False
            await add_log("INFO", self.PROTOCOL_NAME, "slipstream-server installed")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Installation error: {e}")
            return False

    async def start(self) -> bool:
        try:
            config = await get_core_config("slipstream") or {}
            bin_path = await self._binary()
            if not bin_path:
                await add_log("ERROR", self.PROTOCOL_NAME, "slipstream-server binary not found. Run install first.")
                return False
            domain = config.get("domain", "")
            if not domain:
                await add_log("ERROR", self.PROTOCOL_NAME, "Set a tunnel domain (NS record) in the SlipStream config first")
                return False
            port = int(config.get("dns_listen_port", self.DEFAULT_PORT))
            target_port = await self._ssh_port()
            await self._run_cmd("sudo systemctl start ssh || sudo systemctl start sshd", check=False)

            # Clean stale process, then route DNS queries for our domain to us
            await self._run_cmd("sudo pkill -x slipstream-serv", check=False)
            await self._dns_redirect(domain, port)

            pid = await self._start_process(
                f'"{bin_path}" --dns-listen-port={port} '
                f'--target-address=127.0.0.1:{target_port} --domain={domain}'
            )
            if not pid:
                await add_log("ERROR", self.PROTOCOL_NAME, "Failed to start slipstream-server (see logs/slipstream.log)")
                return False
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Start exception: {e}")
            return False

    async def stop(self) -> bool:
        await super().stop()
        config = await get_core_config("slipstream") or {}
        if config.get("domain"):
            await self._dns_redirect(config["domain"], int(config.get("dns_listen_port", self.DEFAULT_PORT)), remove=True)
        return True

    async def get_version(self) -> str:
        return SLIPSTREAM_VERSION.lstrip("v") if await self._binary() else ""

    async def get_active_connections(self) -> int:
        # Tunnelled sessions arrive at sshd from 127.0.0.1
        rc, out, _ = await self._run_cmd(
            f"ss -tn state established '( dport = :{await self._ssh_port()} )' 2>/dev/null", check=False)
        if rc != 0:
            return 0
        return sum(1 for l in out.splitlines() if "127.0.0.1" in l)

    async def _ssh_port(self) -> int:
        rc, out, _ = await self._run_cmd(
            "sudo ss -tlnp | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | head -1", check=False)
        try:
            return int(out.strip())
        except ValueError:
            return 22

    # SSH accounts are shared with DNSTT (dnstt_<username>)
    async def add_client(self, username: str, client_data: dict) -> dict:
        from protocols.dnstt import DNSTTProtocol
        return await DNSTTProtocol().add_client(username, client_data)

    async def remove_client(self, username: str, protocol_data: dict):
        from database import get_client_by_username
        client = await get_client_by_username(username)
        if client and (client.get("protocols") or {}).get("dnstt") and client.get("enabled", True):
            return  # account still used by DNSTT
        from protocols.dnstt import DNSTTProtocol
        await DNSTTProtocol().remove_client(username, protocol_data)

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        config = await get_core_config("slipstream") or {}
        return {
            "type": "slipstream",
            "server": server_ip,
            "domain": config.get("domain", ""),
            "congestion_control": config.get("congestion_control", "bbr"),
            "tunnel_mode": "ssh",
            "ssh_username": protocol_data.get("ssh_username") or f"dnstt_{username}",
            "ssh_password": protocol_data.get("ssh_password", ""),
        }
