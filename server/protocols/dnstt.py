"""
CandyConnect - DNSTT Protocol Manager
Based on https://github.com/bugfloyd/dnstt-deploy
DNSTT tunnels traffic over DNS queries using SSH for each user.
"""
import asyncio, os, time, secrets, string
from protocols.base import BaseProtocol
from database import get_core_config, get_core_status, set_core_status, add_log
from config import DATA_DIR


class DNSTTProtocol(BaseProtocol):
    PROTOCOL_ID = "dnstt"
    PROTOCOL_NAME = "DNSTT"
    DEFAULT_PORT = 53

    DNSTT_DIR = os.path.join(DATA_DIR, "cores", "dnstt")

    async def install(self) -> bool:
        try:
            await add_log("INFO", self.PROTOCOL_NAME, "Installing DNSTT...")
            os.makedirs(self.DNSTT_DIR, exist_ok=True)

            # Install dependencies
            rc, _, err = await self._run_cmd(
                "sudo apt update && sudo apt install -y golang-go openssh-server git",
                check=False,
            )
            if rc != 0:
                await add_log("ERROR", self.PROTOCOL_NAME, f"Dependency install failed: {err}")
                return False

            # Clone and build dnstt
            dnstt_src = os.path.join(self.DNSTT_DIR, "dnstt-src")
            if not os.path.exists(dnstt_src):
                rc, _, err = await self._run_cmd(
                    f"git clone https://www.bamsoftware.com/git/dnstt.git {dnstt_src}",
                    check=False,
                )
                if rc != 0:
                    # Try GitHub mirror
                    await self._run_cmd(
                        f"git clone https://github.com/nicko-v/dnstt.git {dnstt_src}",
                        check=False,
                    )

            # Build server
            await self._run_cmd(
                f"cd {dnstt_src}/dnstt-server && go build -o {self.DNSTT_DIR}/dnstt-server",
                check=False,
            )

            # Generate keypair
            rc, out, _ = await self._run_cmd(
                f"cd {dnstt_src}/dnstt-server && go run ./noise-key-tool generate 2>&1 || "
                f"{self.DNSTT_DIR}/dnstt-server -gen-key 2>&1",
                check=False,
            )
            if out:
                # Parse public key from output
                for line in out.split("\n"):
                    if "public" in line.lower() or len(line.strip()) > 30:
                        key = line.split(":")[-1].strip() if ":" in line else line.strip()
                        if key:
                            from database import update_core_config
                            config = await get_core_config("dnstt") or {}
                            config["public_key"] = key
                            await update_core_config("dnstt", config)
                            break

            # Ensure SSH is running
            await self._run_cmd("sudo systemctl enable ssh && sudo systemctl start ssh", check=False)

            await add_log("INFO", self.PROTOCOL_NAME, "DNSTT installed successfully")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Installation error: {e}")
            return False

    async def start(self) -> bool:
        try:
            config = await get_core_config("dnstt")
            if not config:
                await add_log("ERROR", self.PROTOCOL_NAME, "No DNSTT config found")
                return False

            dnstt_bin = os.path.join(self.DNSTT_DIR, "dnstt-server")
            if not os.path.exists(dnstt_bin):
                await add_log("ERROR", self.PROTOCOL_NAME, "DNSTT binary not found. Run install first.")
                return False

            domain = config.get("domain", "dns.candyconnect.io")
            listen_port = config.get("listen_port", 53)

            # The dnstt-server listens for DNS queries and forwards to SSH
            pid = await self._start_process(
                f"{dnstt_bin} -udp :{listen_port} -doh https://dns.google/dns-query {domain} 127.0.0.1:22",
                cwd=self.DNSTT_DIR,
            )
            if not pid:
                await add_log("ERROR", self.PROTOCOL_NAME, "Failed to start DNSTT")
                return False
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Failed to start: {e}")
            return False

    async def get_version(self) -> str:
        dnstt_bin = os.path.join(self.DNSTT_DIR, "dnstt-server")
        if os.path.exists(dnstt_bin):
            rc, out, _ = await self._run_cmd(f"stat -c '%Y' {dnstt_bin}", check=False)
            if rc == 0 and out:
                ts = int(out.strip())
                return time.strftime("0.%Y%m%d", time.localtime(ts))
        return ""

    async def get_active_connections(self) -> int:
        # Count SSH connections from DNSTT users
        rc, out, _ = await self._run_cmd(
            "ps aux | grep 'sshd:.*dnstt_' | grep -v grep | wc -l",
            check=False,
        )
        try:
            return int(out.strip())
        except ValueError:
            return 0

    async def add_client(self, username: str, client_data: dict) -> dict:
        """Create a non-root SSH user for DNSTT access."""
        ssh_user = f"dnstt_{username}"
        password = client_data.get("password", self._gen_password())

        # Create system user (non-root, no shell login except through tunnel)
        await self._run_cmd(
            f"sudo useradd -m -s /bin/false {ssh_user} 2>/dev/null || true",
            check=False,
        )
        # Set password
        proc = await asyncio.create_subprocess_shell(
            f"echo '{ssh_user}:{password}' | sudo chpasswd",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        return {"ssh_username": ssh_user, "ssh_password": password}

    async def remove_client(self, username: str, protocol_data: dict):
        ssh_user = protocol_data.get("ssh_username") or f"dnstt_{username}"
        await self._run_cmd(f"sudo userdel -r {ssh_user} 2>/dev/null || true", check=False)

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict) -> dict:
        config = await get_core_config("dnstt")
        if not config:
            return {}
        return {
            "type": "dnstt",
            "server": server_ip,
            "domain": config.get("domain", ""),
            "port": config.get("listen_port", 53),
            "public_key": config.get("public_key", ""),
            "ssh_username": protocol_data.get("ssh_username") or f"dnstt_{username}",
            "ssh_password": protocol_data.get("ssh_password"),
        }

    def _gen_password(self, length: int = 16) -> str:
        chars = string.ascii_letters + string.digits + "!@#$%"
        return "".join(secrets.choice(chars) for _ in range(length))
