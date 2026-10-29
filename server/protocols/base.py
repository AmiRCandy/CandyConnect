"""
CandyConnect - Base VPN Protocol Manager
"""
from __future__ import annotations
import asyncio, os, signal, time, json, logging
from typing import Optional
from database import get_core_status, set_core_status, add_log, get_core_config
from config import LOG_DIR

logger = logging.getLogger("candyconnect")


class BaseProtocol:
    """Base class for all VPN protocol managers."""

    PROTOCOL_ID: str = ""
    PROTOCOL_NAME: str = ""
    DEFAULT_PORT: int = 0

    def __init__(self):
        self._process: Optional[asyncio.subprocess.Process] = None

    # ── Public API ──

    async def install(self) -> bool:
        """Install the protocol software. Returns True on success."""
        raise NotImplementedError

    async def start(self) -> bool:
        """Start the protocol service."""
        raise NotImplementedError

    async def stop(self) -> bool:
        """Stop the protocol service."""
        try:
            status = await get_core_status(self.PROTOCOL_ID)
            pid = status.get("pid")
            if pid:
                try:
                    os.kill(int(pid), signal.SIGTERM)
                    await asyncio.sleep(1)
                    try:
                        os.kill(int(pid), 0)
                        os.kill(int(pid), signal.SIGKILL)
                    except OSError:
                        pass
                except (OSError, ProcessLookupError):
                    pass

            if self._process and self._process.returncode is None:
                self._process.terminate()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    self._process.kill()
                self._process = None

            await set_core_status(self.PROTOCOL_ID, {
                "status": "stopped",
                "pid": None,
                "started_at": None,
                "version": status.get("version", ""),
            })
            await add_log("INFO", self.PROTOCOL_NAME, "Service stopped")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to stop: {e}")
            return False

    async def restart(self) -> bool:
        """Restart the protocol service."""
        await self.stop()
        await asyncio.sleep(1)
        return await self.start()

    async def is_running(self) -> bool:
        """Check if the protocol service is running."""
        status = await get_core_status(self.PROTOCOL_ID)
        pid = status.get("pid")
        if not pid:
            return False
        try:
            os.kill(int(pid), 0)
            return True
        except (OSError, ProcessLookupError):
            # Process died, update status
            await set_core_status(self.PROTOCOL_ID, {
                "status": "stopped",
                "pid": None,
                "started_at": None,
                "version": status.get("version", ""),
            })
            return False

    async def get_version(self) -> str:
        """Get the installed version."""
        return ""

    async def get_active_connections(self) -> int:
        """Get the number of active connections."""
        return 0

    async def get_traffic(self) -> dict:
        """Get traffic statistics."""
        return {"in": 0, "out": 0}

    async def add_client(self, username: str, client_data: dict) -> dict:
        """Add a client to this protocol. Returns client config data."""
        raise NotImplementedError

    async def remove_client(self, username: str, protocol_data: dict):
        """Remove a client from this protocol."""
        raise NotImplementedError

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        """Get client connection config for this protocol.
        
        Args:
            config_id: Optional specific config/tag ID to filter to (e.g. 'vless-tcp-xtls').
                        If None, returns all sub-protocols.
        """
        return {}

    # ── Helpers ──

    async def _run_cmd(self, cmd: str, check: bool = True, timeout: int = 30) -> tuple[int, str, str]:
        """Run a shell command and return (returncode, stdout, stderr)."""
        proc = None
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            out = stdout.decode("utf-8", errors="replace").strip()
            err = stderr.decode("utf-8", errors="replace").strip()
            if check and proc.returncode != 0:
                logger.error(f"Command failed: {cmd}\nstderr: {err}")
            return proc.returncode, out, err
        except asyncio.TimeoutError:
            logger.error(f"Command timed out after {timeout}s: {cmd}")
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return -1, "", f"Command timed out after {timeout}s"

    async def _start_process(self, cmd: str, cwd: str = None) -> Optional[int]:
        """Start a background process and return its PID.

        Output goes to a per-protocol log file instead of a pipe: nothing reads
        the pipe of a long-running daemon, so once its buffer fills the daemon
        would block on write and hang. ``exec`` makes the shell replace itself,
        so the tracked PID is the daemon itself and SIGTERM reaches it.
        """
        os.makedirs(LOG_DIR, exist_ok=True)
        log_path = os.path.join(LOG_DIR, f"{self.PROTOCOL_ID}.log")
        log_file = open(log_path, "ab")
        try:
            self._process = await asyncio.create_subprocess_shell(
                f"exec {cmd}",
                stdout=log_file,
                stderr=asyncio.subprocess.STDOUT,
                stdin=asyncio.subprocess.DEVNULL,
                cwd=cwd,
            )
        finally:
            log_file.close()
        pid = self._process.pid

        # Wait a moment to see if it crashes early
        await asyncio.sleep(1.5)
        if self._process.returncode is not None:
            err_msg = ""
            try:
                with open(log_path, "rb") as f:
                    f.seek(max(0, os.path.getsize(log_path) - 2000))
                    err_msg = f.read().decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            await add_log("ERROR", self.PROTOCOL_NAME, f"Process died immediately: {err_msg[-500:]}")
            self._process = None
            return None

        await set_core_status(self.PROTOCOL_ID, {
            "status": "running",
            "pid": pid,
            "started_at": int(time.time()),
            "version": await self.get_version(),
        })
        await add_log("INFO", self.PROTOCOL_NAME, f"Service started (PID: {pid})")
        return pid

    async def _default_iface(self) -> str:
        """Return the interface of the default route (falls back to eth0)."""
        _, out, _ = await self._run_cmd(
            "ip -4 route show default | awk '{for(i=1;i<NF;i++) if($i==\"dev\") {print $(i+1); exit}}'",
            check=False,
        )
        return out.strip().splitlines()[0] if out.strip() else "eth0"

    async def _dns_redirect(self, domain: str, port: int, remove: bool = False):
        """Redirect DNS queries (udp/53) for *domain* to a local port.

        The rule matches the wire-format domain name (e.g. |01|t|07|example|03|com|)
        case-insensitively, so several DNS tunnels (DNSTT, SlipStream) can share
        port 53 as long as they use different domains.
        """
        labels = [l for l in domain.strip(".").split(".") if l]
        if not labels:
            return
        hexstr = "".join(f"|{len(l):02x}|{l}" for l in labels) + "|00|"
        iface = await self._default_iface()
        match = f'-m string --algo bm --icase --hex-string "{hexstr}"'
        rules = [
            ("iptables", "", f"INPUT -p udp --dport {port} -j ACCEPT"),
            ("iptables", "-t nat ", f"PREROUTING -i {iface} -p udp --dport 53 {match} -j REDIRECT --to-ports {port}"),
        ]
        if os.path.exists("/proc/net/if_inet6"):
            rules += [
                ("ip6tables", "", f"INPUT -p udp --dport {port} -j ACCEPT"),
                ("ip6tables", "-t nat ", f"PREROUTING -i {iface} -p udp --dport 53 {match} -j REDIRECT --to-ports {port}"),
            ]
        for tool, table, rule in rules:
            if remove:
                await self._run_cmd(f"while sudo {tool} {table}-D {rule} 2>/dev/null; do :; done", check=False)
            else:
                await self._run_cmd(
                    f"sudo {tool} {table}-C {rule} 2>/dev/null || sudo {tool} {table}-I {rule}", check=False)

    async def _download(self, url: str, dest: str, timeout: int = 300) -> bool:
        """Download a file with curl (falls back to wget)."""
        rc, _, err = await self._run_cmd(
            f"curl -fsSL --retry 3 -o '{dest}.part' '{url}' || wget -q -O '{dest}.part' '{url}'",
            check=False, timeout=timeout,
        )
        if rc != 0:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Download failed: {url} {err[-200:]}")
            await self._run_cmd(f"rm -f '{dest}.part'", check=False)
            return False
        await self._run_cmd(f"mv '{dest}.part' '{dest}'", check=False)
        return True

    @staticmethod
    def _arch() -> str:
        """Machine architecture as x86_64 / aarch64."""
        m = os.uname().machine
        return {"amd64": "x86_64", "arm64": "aarch64"}.get(m, m)

    async def _is_installed(self, binary: str) -> bool:
        """Check if a binary is available, checking common system paths as well."""
        # 1. Try 'which'
        rc, _, _ = await self._run_cmd(f"which {binary}", check=False)
        if rc == 0:
            return True
        
        # 2. Check common system paths explicitly (important for sbin)
        search_paths = ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin"]
        for p in search_paths:
            if os.path.exists(os.path.join(p, binary)):
                return True
        return False

    async def _apt_install(self, packages: str) -> bool:
        """Helper to run apt install with retries for lock issues."""
        max_retries = 5
        for i in range(max_retries):
            # Use -o DPkg::Lock::Timeout=60 if supported, but manual retry is safer
            rc, out, err = await self._run_cmd(f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {packages}", check=False, timeout=180)
            if rc == 0:
                return True
            
            # Check for lock error
            if "Could not get lock" in err or "Unable to lock" in err:
                await add_log("WARNING", self.PROTOCOL_NAME, f"Apt lock held, retry {i+1}/{max_retries}...")
                await asyncio.sleep(10)
                continue
            
            # Other error
            await add_log("ERROR", self.PROTOCOL_NAME, f"Apt install failed: {err}")
            return False
            
        return False

    async def _systemctl(self, action: str, service: str) -> bool:
        """Run systemctl action."""
        rc, out, err = await self._run_cmd(f"sudo systemctl {action} {service}", check=False)
        return rc == 0

    async def _is_service_active(self, service: str) -> bool:
        """Check if a systemd service is active."""
        rc, out, _ = await self._run_cmd(f"systemctl is-active {service}", check=False)
        return out.strip() == "active"
