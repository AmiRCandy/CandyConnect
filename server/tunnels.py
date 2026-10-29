"""
CandyConnect - Relay tunnels (Backhaul)

A relay server (e.g. a domestic server that is reachable for users) runs the
Backhaul *server*: it listens on the tunnel port and on the forwarded VPN
ports. This CandyConnect server runs the Backhaul *client*, which dials out to
the relay, so users connect to the relay's IP and their traffic reaches the VPN
services here. https://github.com/Musixal/Backhaul
"""
from __future__ import annotations

import asyncio, json, os, shlex, logging
from typing import Optional

import database as db
from config import CORE_DIR, LOG_DIR

logger = logging.getLogger("candyconnect")

BACKHAUL_VERSION = "v0.7.2"
BACKHAUL_DIR = os.path.join(CORE_DIR, "backhaul")
BACKHAUL_BIN = os.path.join(BACKHAUL_DIR, "backhaul")
TRANSPORTS = ("tcp", "tcpmux", "ws", "wsmux")

_processes: dict[str, asyncio.subprocess.Process] = {}


def _arch() -> str:
    m = os.uname().machine
    return "arm64" if m in ("aarch64", "arm64") else "amd64"


def _download_url(arch: str) -> str:
    return (f"https://github.com/Musixal/Backhaul/releases/download/{BACKHAUL_VERSION}/"
            f"backhaul_linux_{arch}.tar.gz")


async def _run(cmd: str, timeout: int = 300) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_shell(
        cmd, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "timeout"
    return proc.returncode, out.decode("utf-8", errors="replace").strip()


async def default_ports() -> list[str]:
    """TCP ports of the local VPN services that make sense to relay."""
    ports: list[str] = []
    v2 = await db.get_core_config("v2ray") or {}
    try:
        for ib in json.loads(v2.get("config_json", "{}")).get("inbounds", []):
            if ib.get("protocol") in ("vless", "vmess", "trojan", "shadowsocks") and ib.get("port"):
                ports.append(str(ib["port"]))
    except ValueError:
        pass
    ovpn = await db.get_core_config("openvpn") or {}
    if str(ovpn.get("protocol", "udp")).startswith("tcp"):
        ports.append(str(ovpn.get("port", 1194)))
    tt = await db.get_core_config("trusttunnel") or {}
    if await db.get_autostart("trusttunnel"):
        ports.append(str(tt.get("port", 9443)))
    return list(dict.fromkeys(ports))


def parse_ports(value) -> list[str]:
    """Accept "443, 8080" / ["443", "8443=443"] and return Backhaul port specs."""
    items = value if isinstance(value, list) else str(value or "").replace("\n", ",").split(",")
    out = []
    for item in items:
        item = str(item).strip()
        if item and all(c.isdigit() or c in "=:-." for c in item):
            out.append(item)
    return out


def server_toml(t: dict) -> str:
    ports = ",\n".join(f'  "{p}"' for p in t["ports"])
    return (
        "[server]\n"
        f'bind_addr = "0.0.0.0:{t["tunnel_port"]}"\n'
        f'transport = "{t["transport"]}"\n'
        f'token = "{t["token"]}"\n'
        f'accept_udp = {"true" if t.get("accept_udp") else "false"}\n'
        "keepalive_period = 75\n"
        "nodelay = true\n"
        "heartbeat = 40\n"
        "channel_size = 2048\n"
        "sniffer = false\n"
        "web_port = 0\n"
        'log_level = "info"\n'
        f"ports = [\n{ports}\n]\n"
    )


def client_toml(t: dict) -> str:
    return (
        "[client]\n"
        f'remote_addr = "{t["ip"]}:{t["tunnel_port"]}"\n'
        f'transport = "{t["transport"]}"\n'
        f'token = "{t["token"]}"\n'
        "connection_pool = 8\n"
        "keepalive_period = 75\n"
        "nodelay = true\n"
        "retry_interval = 3\n"
        "dial_timeout = 10\n"
        "sniffer = false\n"
        "web_port = 0\n"
        'log_level = "info"\n'
    )


def remote_install_script(t: dict) -> str:
    """Shell script that installs/updates the Backhaul server on the relay."""
    tid = t["id"]
    ports = " ".join(p.split("=")[0].split(":")[-1] for p in t["ports"])
    return f"""set -e
ARCH=$(uname -m); case "$ARCH" in aarch64|arm64) A=arm64;; *) A=amd64;; esac
mkdir -p /opt/backhaul && cd /opt/backhaul
if [ ! -x /opt/backhaul/backhaul ]; then
  curl -fsSL -o backhaul.tar.gz "https://github.com/Musixal/Backhaul/releases/download/{BACKHAUL_VERSION}/backhaul_linux_${{A}}.tar.gz" \\
    || wget -qO backhaul.tar.gz "https://github.com/Musixal/Backhaul/releases/download/{BACKHAUL_VERSION}/backhaul_linux_${{A}}.tar.gz"
  tar -xzf backhaul.tar.gz && chmod 755 backhaul && rm -f backhaul.tar.gz
fi
cat > /opt/backhaul/candy-{tid}.toml <<'CCEOF'
{server_toml(t)}CCEOF
cat > /etc/systemd/system/backhaul-candy-{tid}.service <<'CCEOF'
[Unit]
Description=Backhaul relay for CandyConnect ({tid})
After=network.target

[Service]
ExecStart=/opt/backhaul/backhaul -c /opt/backhaul/candy-{tid}.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
CCEOF
for p in {t["tunnel_port"]} {ports}; do
  iptables -C INPUT -p tcp --dport $p -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport $p -j ACCEPT || true
  command -v ufw >/dev/null && ufw status | grep -q "Status: active" && ufw allow $p >/dev/null || true
done
systemctl daemon-reload
systemctl enable backhaul-candy-{tid} >/dev/null 2>&1
systemctl restart backhaul-candy-{tid}
sleep 2
systemctl is-active backhaul-candy-{tid}
"""


def remote_uninstall_script(tid: str) -> str:
    return f"""systemctl disable --now backhaul-candy-{tid} 2>/dev/null || true
rm -f /etc/systemd/system/backhaul-candy-{tid}.service /opt/backhaul/candy-{tid}.toml
systemctl daemon-reload
"""


def _ssh_exec(t: dict, script: str) -> tuple[bool, str]:
    """Run a script on the relay over SSH (sync; call in a thread)."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(t["ip"], port=int(t.get("port", 22)), username=t.get("username") or "root",
                       password=t.get("ssh_password"), timeout=20, allow_agent=False, look_for_keys=False)
        user = t.get("username") or "root"
        cmd = "bash -s" if user == "root" else "sudo -S -p '' bash -s"
        stdin, stdout, stderr = client.exec_command(cmd, timeout=600)
        if user != "root":
            stdin.write((t.get("ssh_password") or "") + "\n")
        stdin.write(script)
        stdin.channel.shutdown_write()
        status = stdout.channel.recv_exit_status()
        out = (stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")).strip()
        return status == 0, out
    except Exception as e:
        return False, str(e)
    finally:
        client.close()


# ── Local Backhaul client ──

async def ensure_binary() -> bool:
    if os.path.exists(BACKHAUL_BIN):
        return True
    os.makedirs(BACKHAUL_DIR, exist_ok=True)
    rc, out = await _run(
        f"cd {BACKHAUL_DIR} && (curl -fsSL -o bh.tar.gz '{_download_url(_arch())}' || "
        f"wget -qO bh.tar.gz '{_download_url(_arch())}') && tar -xzf bh.tar.gz && "
        f"chmod 755 backhaul && rm -f bh.tar.gz")
    if rc != 0:
        await db.add_log("ERROR", "Tunnel", f"Backhaul download failed: {out[-300:]}")
    return os.path.exists(BACKHAUL_BIN)


async def start_local(t: dict) -> bool:
    await stop_local(t["id"])
    if not await ensure_binary():
        return False
    conf = os.path.join(BACKHAUL_DIR, f"candy-{t['id']}.toml")
    with open(conf, "w") as f:
        f.write(client_toml(t))
    os.makedirs(LOG_DIR, exist_ok=True)
    log = open(os.path.join(LOG_DIR, f"tunnel-{t['id']}.log"), "ab")
    try:
        proc = await asyncio.create_subprocess_exec(
            BACKHAUL_BIN, "-c", conf, cwd=BACKHAUL_DIR,
            stdin=asyncio.subprocess.DEVNULL, stdout=log, stderr=asyncio.subprocess.STDOUT)
    finally:
        log.close()
    await asyncio.sleep(1.5)
    if proc.returncode is not None:
        await db.add_log("ERROR", "Tunnel", f"Backhaul client for '{t['name']}' exited immediately")
        return False
    _processes[t["id"]] = proc
    return True


async def stop_local(tid: str):
    proc = _processes.pop(tid, None)
    if proc and proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()


def local_running(tid: str) -> bool:
    proc = _processes.get(tid)
    return bool(proc and proc.returncode is None)


async def install_tunnel(tunnel_id: str):
    """Install the relay over SSH (if credentials are stored) and start the local client."""
    t = await db.get_tunnel(tunnel_id)
    if not t:
        return
    await db.update_tunnel(tunnel_id, {"status": "installing", "error": ""})
    await db.add_log("INFO", "Tunnel", f"Installing relay '{t['name']}' on {t['ip']}...")
    if t.get("ssh_password"):
        from starlette.concurrency import run_in_threadpool
        ok, out = await run_in_threadpool(_ssh_exec, t, remote_install_script(t))
        if not ok:
            await db.update_tunnel(tunnel_id, {"status": "failed", "error": out[-500:]})
            await db.add_log("ERROR", "Tunnel", f"Relay '{t['name']}' install failed: {out[-300:]}")
            return
    if not await start_local(t):
        await db.update_tunnel(tunnel_id, {"status": "failed", "error": "Local Backhaul client failed to start"})
        return
    await db.update_tunnel(tunnel_id, {"status": "installed", "error": ""})
    await db.add_log("INFO", "Tunnel", f"Relay '{t['name']}' is up ({t['ip']}:{t['tunnel_port']})")


async def remove_tunnel(tunnel_id: str):
    t = await db.get_tunnel(tunnel_id)
    await stop_local(tunnel_id)
    try:
        os.remove(os.path.join(BACKHAUL_DIR, f"candy-{tunnel_id}.toml"))
    except OSError:
        pass
    if t and t.get("ssh_password"):
        from starlette.concurrency import run_in_threadpool
        ok, out = await run_in_threadpool(_ssh_exec, t, remote_uninstall_script(tunnel_id))
        if not ok:
            await db.add_log("WARN", "Tunnel", f"Could not clean up relay {t['ip']}: {out[-200:]}")
    await db.delete_tunnel(tunnel_id)


async def start_all():
    """Start local Backhaul clients for installed tunnels (on server boot)."""
    for t in await db.get_tunnels(include_secrets=True):
        if t.get("status") == "installed" and t.get("token"):
            try:
                await start_local(t)
            except Exception as e:
                logger.warning(f"Tunnel {t.get('id')} start failed: {e}")


async def relays_for_port(port) -> list[dict]:
    """Installed relays that forward the given local port."""
    result = []
    for t in await db.get_tunnels(include_secrets=False):
        if t.get("status") != "installed":
            continue
        for spec in t.get("ports", []):
            # "443" / "443=443" / "443=1.2.3.4:443": target port is the last number
            target = spec.split("=")[-1].split(":")[-1]
            listen = spec.split("=")[0].split(":")[-1]
            if "-" not in spec and target == str(port):
                result.append({**t, "listen_port": int(listen)})
                break
    return result
