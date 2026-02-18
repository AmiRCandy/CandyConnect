"""
CandyConnect - Base VPN Protocol Manager
"""
import asyncio, os, signal, time, json, logging
from typing import Optional
from database import get_core_status, set_core_status, add_log, get_core_config

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
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
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
        """Start a background process and return its PID."""
        self._process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        pid = self._process.pid
        
        # Wait a moment to see if it crashes early
        await asyncio.sleep(1.5)
        if self._process.returncode is not None:
            _, err = await self._process.communicate()
            err_msg = err.decode("utf-8", errors="replace").strip()
            await add_log("ERROR", self.PROTOCOL_NAME, f"Process died immediately: {err_msg}")
            return None

        await set_core_status(self.PROTOCOL_ID, {
            "status": "running",
            "pid": pid,
            "started_at": int(time.time()),
            "version": await self.get_version(),
        })
        await add_log("INFO", self.PROTOCOL_NAME, f"Service started (PID: {pid})")
        return pid

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
            rc, out, err = await self._run_cmd(f"sudo apt install -y {packages}", check=False, timeout=180)
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
