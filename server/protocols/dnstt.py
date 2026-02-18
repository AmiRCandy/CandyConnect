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
            await add_log("INFO", self.PROTOCOL_NAME, "Configuring DNSTT...")
            os.makedirs(self.DNSTT_DIR, exist_ok=True)

            # Check if binary exists (should be in /usr/local/bin from Docker or installer)
            dnstt_bin = "/usr/local/bin/dnstt-server"
            if not os.path.exists(dnstt_bin):
                # Try simple path search
                rc, path, _ = await self._run_cmd("which dnstt-server", check=False)
                if rc == 0:
                    dnstt_bin = path.strip()
                else:
                    await add_log("ERROR", self.PROTOCOL_NAME, "dnstt-server binary not found")
                    return False

            # Create dnstt user if not exists (as in dnstt-deploy.sh)
            await self._run_cmd(
                "id dnstt &>/dev/null || sudo useradd -r -s /bin/false -d /nonexistent -c 'dnstt service user' dnstt",
                check=False
            )
            await self._run_cmd(f"sudo chown dnstt:dnstt {self.DNSTT_DIR}", check=False)
            await self._run_cmd(f"sudo chmod 750 {self.DNSTT_DIR}", check=False)

            # Generate keypair if missing (prefixed with domain name)
            config = await get_core_config("dnstt") or {}
            domain = config.get("domain", "dns.candyconnect.io")
            key_prefix = domain.replace(".", "_")
            
            priv_key = os.path.join(self.DNSTT_DIR, f"{key_prefix}_server.key")
            pub_key = os.path.join(self.DNSTT_DIR, f"{key_prefix}_server.pub")
            
            if not os.path.exists(priv_key):
                await self._run_cmd(
                    f"sudo {dnstt_bin} -gen-key -privkey-file {priv_key} -pubkey-file {pub_key}",
                    check=False,
                )
                await self._run_cmd(f"sudo chown dnstt:dnstt {priv_key} {pub_key}", check=False)
                await self._run_cmd(f"sudo chmod 600 {priv_key}", check=False)
                await self._run_cmd(f"sudo chmod 644 {pub_key}", check=False)

            # Update public key in DB
            if os.path.exists(pub_key):
                rc, key_content, _ = await self._run_cmd(f"cat {pub_key}", check=False)
                if rc == 0:
                    config["public_key"] = key_content.strip()
                    from database import update_core_config
                    await update_core_config("dnstt", config)

            await add_log("INFO", self.PROTOCOL_NAME, "DNSTT configured successfully")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Configuration error: {e}")
            return False

    async def start(self) -> bool:
        try:
            config = await get_core_config("dnstt")
            if not config:
                await add_log("ERROR", self.PROTOCOL_NAME, "No DNSTT config found")
                return False

            dnstt_bin = "/usr/local/bin/dnstt-server"
            if not os.path.exists(dnstt_bin):
                rc, path, _ = await self._run_cmd("which dnstt-server", check=False)
                if rc == 0:
                    dnstt_bin = path.strip()
                else:
                    await add_log("ERROR", self.PROTOCOL_NAME, "dnstt-server binary missing")
                    return False

            domain = config.get("domain", "dns.candyconnect.io")
            listen_port = config.get("listen_port", 5300)
            tunnel_mode = config.get("tunnel_mode", "ssh")
            mtu = config.get("mtu", 1232)
            key_prefix = domain.replace(".", "_")
            priv_key = os.path.join(self.DNSTT_DIR, f"{key_prefix}_server.key")

            # Determine target port (SSH=auto, SOCKS=1080)
            target_port = 22
            if tunnel_mode == "socks":
                target_port = 1080
                # Ensure danted is installed and configured
                await self._setup_dante()
                await self._run_cmd("sudo systemctl start danted", check=False)
            else:
                # Detect SSH port (as in dnstt-deploy.sh) - use more robust awk
                rc, ssh_p, _ = await self._run_cmd("sudo ss -tlnp | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | head -1", check=False)
                if rc == 0 and ssh_p.strip():
                    try:
                        target_port = int(ssh_p.strip())
                    except ValueError:
                        target_port = 22
                
                # Ensure ssh is running
                await self._run_cmd("sudo systemctl start ssh", check=False)

            # Clean up old iptables rules to avoid duplicates
            await self._run_cmd("sudo iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT 2>/dev/null || true", check=False)
            
            # Redirect port 53 to listen_port
            await self._setup_redirection(listen_port)

            # Start dnstt-server
            pid = await self._start_process(
                f'"{dnstt_bin}" -udp :{listen_port} -privkey-file "{priv_key}" -mtu {mtu} {domain} 127.0.0.1:{target_port}',
                cwd=self.DNSTT_DIR,
            )
            
            if not pid:
                await add_log("ERROR", self.PROTOCOL_NAME, "Failed to start DNSTT process (check binary permissions/paths)")
                return False
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Start exception: {e}")
            return False

    async def stop(self) -> bool:
        """Enhanced stop to ensure no hanging processes block restarts."""
        # 1. Base stop (kills by PID)
        await super().stop()
        
        # 2. Force kill any remaining dnstt-server by name
        await self._run_cmd("sudo pkill -9 dnstt-server", check=False)
        
        # 3. Clean up iptables for redirection
        await self._run_cmd("sudo iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT 2>/dev/null || true", check=False)
        
        return True

    async def _setup_redirection(self, port: int):
        """Redirect port 53/udp to the custom listen port using iptables."""
        # Get default interface
        _, iface, _ = await self._run_cmd("ip route | grep default | awk '{print $5}' | head -1", check=False)
        iface = iface.strip() or "eth0"
        
        # Add rules
        await self._run_cmd(f"sudo iptables -I INPUT -p udp --dport {port} -j ACCEPT", check=False)
        await self._run_cmd(
            f"sudo iptables -t nat -I PREROUTING -i {iface} -p udp --dport 53 -j REDIRECT --to-ports {port}",
            check=False,
        )
        # IPv6 support if available
        if os.path.exists("/proc/net/if_inet6"):
            await self._run_cmd(f"sudo ip6tables -I INPUT -p udp --dport {port} -j ACCEPT", check=False)
            await self._run_cmd(
                f"sudo ip6tables -t nat -I PREROUTING -i {iface} -p udp --dport 53 -j REDIRECT --to-ports {port}",
                check=False,
            )

    async def _setup_dante(self):
        """Configure dante-server for DNSTT SOCKS mode."""
        _, iface, _ = await self._run_cmd("ip route | grep default | awk '{print $5}' | head -1", check=False)
        iface = iface.strip() or "eth0"
        
        config_path = "/etc/danted.conf"
        content = f"logoutput: syslog\nuser.privileged: root\nuser.unprivileged: nobody\n\ninternal: 127.0.0.1 port = 1080\nexternal: {iface}\nsocksmethod: none\ncompatibility: sameport\nextension: bind\n\nclient pass {{\n    from: 127.0.0.1/8 to: 0.0.0.0/0\n    log: error\n}}\n\nsocks pass {{\n    from: 127.0.0.1/8 to: 0.0.0.0/0\n    command: bind connect udpassociate\n    log: error\n}}\n"
        
        # Safer write: write to tmp then move
        with open("/tmp/cc_danted.conf", "w") as f:
            f.write(content)
        
        await self._run_cmd("sudo mv /tmp/cc_danted.conf /etc/danted.conf", check=False)
        await self._run_cmd("sudo systemctl enable danted", check=False)
        await self._run_cmd("sudo systemctl restart danted", check=False)

    async def get_version(self) -> str:
        dnstt_bin = "/usr/local/bin/dnstt-server"
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

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        config = await get_core_config("dnstt")
        if not config:
            return {}
        return {
            "type": "dnstt",
            "server": server_ip,
            "domain": config.get("domain", ""),
            "port": config.get("listen_port", 5300),
            "tunnel_mode": config.get("tunnel_mode", "ssh"),
            "mtu": config.get("mtu", 1232),
            "public_key": config.get("public_key", ""),
            "ssh_username": protocol_data.get("ssh_username") or f"dnstt_{username}",
            "ssh_password": protocol_data.get("ssh_password"),
        }

    def _gen_password(self, length: int = 16) -> str:
        chars = string.ascii_letters + string.digits + "!@#$%"
        return "".join(secrets.choice(chars) for _ in range(length))
