"""
CandyConnect Server - Redis Database Layer
All data is stored in Redis with JSON serialization.
"""
import json, time, uuid, hashlib, logging
from typing import Optional
import bcrypt
import redis.asyncio as redis

from config import (
    REDIS_URL, DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS,
    PANEL_PORT, PANEL_PATH, PANEL_VERSION, PANEL_BUILD_DATE,
)

_pool: Optional[redis.Redis] = None


async def get_redis() -> redis.Redis:
    global _pool
    if _pool is None:
        _pool = redis.from_url(REDIS_URL, decode_responses=True)
    # Verify connection is alive
    try:
        await _pool.ping()
    except Exception:
        # Connection is broken, reset and retry once
        try:
            await _pool.aclose()
        except Exception:
            pass
        _pool = redis.from_url(REDIS_URL, decode_responses=True)
        await _pool.ping()  # Let this raise if still failing
    return _pool


async def close_redis():
    global _pool
    if _pool:
        try:
            await _pool.aclose()
        except Exception:
            pass
        _pool = None


# ── Key helpers ──
K_ADMIN = "cc:admin"
K_PANEL = "cc:panel"
K_SERVER_START = "cc:server_start"
K_CLIENTS = "cc:clients"           # hash: id -> json
K_CLIENT_IDX = "cc:client_idx"     # hash: username -> id
K_CONFIGS = "cc:configs"           # hash: section -> json
K_LOGS = "cc:logs"                 # list (newest first)
K_CORE_STATUS = "cc:core_status"   # hash: core_id -> json
K_TRAFFIC = "cc:traffic"           # hash: client_id:protocol -> bytes
K_LAST_SYNC = "cc:last_sync"


def _gen_id() -> str:
    return "c" + uuid.uuid4().hex[:8]


# ── Initialization ──

async def init_db():
    """Seed default data if DB is empty. Raises on connection failure."""
    # Test Redis connectivity first
    r = await get_redis()
    await r.ping()  # Will raise if Redis is unreachable

    # Always sync admin credentials from env vars if they exist
    # This allows resetting the password via .env and restart
    admin_user = DEFAULT_ADMIN_USER
    admin_pass = DEFAULT_ADMIN_PASS
    
    # We use direct bcrypt to avoid passlib issues in docker
    password_hash = bcrypt.hashpw(admin_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    await r.hset(K_ADMIN, mapping={
        "username": admin_user,
        "password_hash": password_hash,
    })
    logging.getLogger("candyconnect").info(f"Admin credentials synced: {admin_user}")

    # Panel config
    if not await r.exists(K_PANEL):
        await r.hset(K_PANEL, mapping={
            "panel_port": str(PANEL_PORT),
            "panel_path": PANEL_PATH,
            "version": PANEL_VERSION,
            "build_date": PANEL_BUILD_DATE,
        })

    # Server start time
    if not await r.exists(K_SERVER_START):
        await r.set(K_SERVER_START, str(int(time.time())))

    # Default core configs
    if not await r.hexists(K_CONFIGS, "candyconnect"):
        defaults = _default_core_configs()
        for section, data in defaults.items():
            await r.hset(K_CONFIGS, section, json.dumps(data))

    # Default core statuses
    for proto in ["v2ray", "wireguard", "openvpn", "ikev2", "l2tp", "dnstt", "slipstream", "trusttunnel"]:
        if not await r.hexists(K_CORE_STATUS, proto):
            # All protocols except slipstream and trusttunnel are running by default
            status = "running" if proto not in ["slipstream", "trusttunnel"] else "stopped"
            await r.hset(K_CORE_STATUS, proto, json.dumps({
                "status": status,
                "pid": None,
                "started_at": int(time.time()) if status == "running" else None,
                "version": "",
            }))

    await r.set(K_LAST_SYNC, str(int(time.time())))

    # Create default 'admin' client if it doesn't exist
    if not await r.hexists(K_CLIENT_IDX, admin_user):
        admin_client_data = {
            "username": admin_user,
            "password": admin_pass,
            "comment": "Default administrator client",
            "enabled": True,
            "protocols": {p: (p not in ["slipstream", "trusttunnel"]) for p in [
                "v2ray", "wireguard", "openvpn", "ikev2", "l2tp", "dnstt", "slipstream", "trusttunnel"
            ]}
        }
        await create_client(admin_client_data)
        logging.getLogger("candyconnect").info(f"Default client '{admin_user}' created")


def _default_core_configs() -> dict:
    return {
        "candyconnect": {
            "panel_domain": "vpn.candyconnect.io",
            "ssl_enabled": True,
            "ssl_cert_path": "/etc/ssl/certs/candyconnect.pem",
            "ssl_key_path": "/etc/ssl/private/candyconnect.key",
            "max_clients": 500,
            "log_level": "info",
            "mode": "normal",
            "auto_backup": True,
            "backup_interval": 24,
            "api_enabled": True,
            "api_port": 8444,
        },
        "wireguard": {
            "listen_port": 51820,
            "dns": "1.1.1.1, 8.8.8.8",
            "address": "10.66.66.1/24",
            "private_key": "",
            "public_key": "",
            "mtu": 1420,
            "post_up": "iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
            "post_down": "iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        },
        "v2ray": {
            "config_json": json.dumps({
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {
                        "tag": "vless-tcp-xtls", "port": 443, "protocol": "vless",
                        "settings": {"clients": [], "decryption": "none"},
                        "streamSettings": {
                            "network": "tcp",
                            "security": "none",
                            "tcpSettings": {"header": {"type": "none"}}
                        }
                    },
                    {
                        "tag": "vmess-ws", "port": 8080, "protocol": "vmess",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "network": "ws",
                            "wsSettings": {"path": "/vmess"}
                        }
                    }
                ],
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom"},
                    {"tag": "blocked", "protocol": "blackhole"},
                ],
                "routing": {
                    "domainStrategy": "AsIs",
                    "rules": [{"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]}]
                }
            }, indent=2),
        },
        "openvpn": {
            "port": 1194, "protocol": "udp", "device": "tun",
            "cipher": "AES-256-GCM", "auth": "SHA512", "dh": "none",
            "tls_crypt": True, "dns1": "1.1.1.1", "dns2": "8.8.8.8",
            "subnet": "10.8.0.0/24", "max_clients": 100,
            "keepalive": "10 120", "comp_lzo": False,
        },
        "ikev2": {
            "port": 500, "nat_port": 4500,
            "cipher": "aes256-sha256-modp2048",
            "lifetime": "24h", "margintime": "3h",
            "dns": "1.1.1.1", "subnet": "10.10.0.0/24",
            "cert_validity": 3650,
        },
        "l2tp": {
            "port": 1701, "ipsec_port": 500,
            "psk": "CandyConnect_L2TP_PSK_2026",
            "local_ip": "10.20.0.1",
            "remote_range": "10.20.0.10-10.20.0.250",
            "dns": "1.1.1.1", "mtu": 1400, "mru": 1400,
        },
        "dnstt": {
            "listen_port": 5300,
            "domain": "dns.candyconnect.io",
            "public_key": "",
            "tunnel_mode": "ssh",
            "mtu": 1232,
        },
        "slipstream": {
            "port": 8388, "method": "aes-256-cfb",
            "obfs": "tls", "obfs_host": "www.microsoft.com",
            "fast_open": True, "no_delay": True,
            "udp_relay": True, "timeout": 300,
        },
        "trusttunnel": {
            "port": 9443, "protocol": "https",
            "camouflage": "cloudflare",
            "fragment_size": 100, "fragment_interval": 50,
            "sni": "www.google.com", "alpn": "h2,http/1.1",
            "padding": True, "timeout": 60,
        },
    }


# ── Admin ──

async def verify_admin(username: str, password: str) -> bool:
    r = await get_redis()
    data = await r.hgetall(K_ADMIN)
    if not data:
        return False
    
    stored_hash = data.get("password_hash", "")
    if not stored_hash:
        return False
        
    try:
        return data.get("username") == username and bcrypt.checkpw(
            password.encode('utf-8'), 
            stored_hash.encode('utf-8')
        )
    except Exception:
        return False


async def get_admin_username() -> str:
    r = await get_redis()
    return (await r.hget(K_ADMIN, "username")) or "admin"


async def change_admin_password(current: str, new_pass: str) -> bool:
    r = await get_redis()
    data = await r.hgetall(K_ADMIN)
    stored_hash = data.get("password_hash", "")
    
    try:
        if not bcrypt.checkpw(current.encode('utf-8'), stored_hash.encode('utf-8')):
            return False
    except Exception:
        return False
        
    new_hash = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    await r.hset(K_ADMIN, "password_hash", new_hash)
    return True


# ── Panel Config ──

async def get_panel_config() -> dict:
    r = await get_redis()
    data = await r.hgetall(K_PANEL)
    return {
        "panel_port": int(data.get("panel_port", PANEL_PORT)),
        "panel_path": data.get("panel_path", PANEL_PATH),
        "version": data.get("version", PANEL_VERSION),
        "build_date": data.get("build_date", PANEL_BUILD_DATE),
    }


async def update_panel_config(updates: dict):
    r = await get_redis()
    mapping = {}
    if "panel_port" in updates:
        mapping["panel_port"] = str(updates["panel_port"])
    if "panel_path" in updates:
        mapping["panel_path"] = updates["panel_path"]
    if mapping:
        await r.hset(K_PANEL, mapping=mapping)


# ── Server Uptime ──

async def get_server_uptime() -> int:
    r = await get_redis()
    start = await r.get(K_SERVER_START)
    if not start:
        return 0
    return int(time.time()) - int(start)


# ── Clients ──

async def get_all_clients() -> list[dict]:
    r = await get_redis()
    raw = await r.hgetall(K_CLIENTS)
    clients = []
    for cid, data in raw.items():
        c = json.loads(data)
        c["id"] = cid
        # Attach per-protocol traffic
        c["protocol_traffic"] = await _get_client_protocol_traffic(r, cid)
        clients.append(c)
    return clients


async def get_client(client_id: str) -> Optional[dict]:
    r = await get_redis()
    raw = await r.hget(K_CLIENTS, client_id)
    if not raw:
        return None
    c = json.loads(raw)
    c["id"] = client_id
    c["protocol_traffic"] = await _get_client_protocol_traffic(r, client_id)
    return c


async def get_client_by_username(username: str) -> Optional[dict]:
    r = await get_redis()
    cid = await r.hget(K_CLIENT_IDX, username)
    if not cid:
        return None
    return await get_client(cid)


async def create_client(data: dict) -> dict:
    r = await get_redis()
    # Check duplicate username
    if await r.hexists(K_CLIENT_IDX, data["username"]):
        raise ValueError(f"Username '{data['username']}' already exists")

    cid = _gen_id()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    client = {
        "username": data["username"],
        "password": data["password"],
        "comment": data.get("comment", ""),
        "enabled": data.get("enabled", True),
        "group": data.get("group", ""),
        "traffic_limit": data.get("traffic_limit", {"value": 50, "unit": "GB"}),
        "traffic_used": 0,
        "time_limit": data.get("time_limit", {"mode": "days", "value": 30, "on_hold": False}),
        "time_used": 0,
        "created_at": now,
        "expires_at": _calc_expiry(now, data.get("time_limit", {"mode": "days", "value": 30})),
        "protocols": data.get("protocols", {p: True for p in [
            "v2ray", "wireguard", "openvpn", "ikev2", "l2tp", "dnstt", "slipstream", "trusttunnel"
        ]}),
        "protocol_data": data.get("protocol_data", {}),
        "last_connected_ip": None,
        "last_connected_time": None,
        "connection_history": [],
    }
    await r.hset(K_CLIENTS, cid, json.dumps(client))
    await r.hset(K_CLIENT_IDX, data["username"], cid)

    client["id"] = cid
    client["protocol_traffic"] = {}
    await _add_log("INFO", "System", f"Client '{data['username']}' created")
    return client


async def update_client(client_id: str, updates: dict) -> Optional[dict]:
    r = await get_redis()
    raw = await r.hget(K_CLIENTS, client_id)
    if not raw:
        return None
    client = json.loads(raw)

    for key in ["password", "comment", "enabled", "group", "traffic_limit", "time_limit", "protocols", "protocol_data"]:
        if key in updates:
            client[key] = updates[key]

    # Recalculate expiry if time_limit changed
    if "time_limit" in updates:
        client["expires_at"] = _calc_expiry(client["created_at"], updates["time_limit"])

    await r.hset(K_CLIENTS, client_id, json.dumps(client))
    client["id"] = client_id
    client["protocol_traffic"] = await _get_client_protocol_traffic(r, client_id)
    await _add_log("INFO", "System", f"Client '{client['username']}' updated")
    return client


async def delete_client(client_id: str) -> bool:
    r = await get_redis()
    raw = await r.hget(K_CLIENTS, client_id)
    if not raw:
        return False
    client = json.loads(raw)
    await r.hdel(K_CLIENTS, client_id)
    await r.hdel(K_CLIENT_IDX, client.get("username", ""))
    # Clean up traffic keys
    for proto in ["v2ray", "wireguard", "openvpn", "ikev2", "l2tp", "dnstt", "slipstream", "trusttunnel"]:
        await r.hdel(K_TRAFFIC, f"{client_id}:{proto}")
    await _add_log("INFO", "System", f"Client '{client.get('username', '')}' deleted")
    return True


async def verify_client(username: str, password: str) -> Optional[dict]:
    """Verify client credentials for client app login."""
    client = await get_client_by_username(username)
    if not client:
        return None
    if client.get("password") != password:
        return None
    if not client.get("enabled", False):
        return None
    return client


async def add_connection_history(client_id: str, protocol: str, event: str, ip: str):
    """Record a connection event (connect/disconnect)."""
    r = await get_redis()
    raw = await r.hget(K_CLIENTS, client_id)
    if not raw:
        return
    client = json.loads(raw)
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    
    if event == "connect":
        client["last_connected_ip"] = ip
        client["last_connected_time"] = now
        
    history = client.get("connection_history", [])
    history.insert(0, {
        "ip": ip,
        "time": now,
        "protocol": protocol,
        "event": event,
    })
    client["connection_history"] = history[:50]  # Keep last 50
    await r.hset(K_CLIENTS, client_id, json.dumps(client))

async def record_client_connection(client_id: str, ip: str, protocol: str):
    """Legacy wrapper for backward compatibility."""
    await add_connection_history(client_id, protocol, "connect", ip)


async def update_client_traffic(client_id: str, protocol: str, bytes_used: float):
    """Update traffic usage for a client on a specific protocol."""
    r = await get_redis()
    key = f"{client_id}:{protocol}"
    await r.hincrbyfloat(K_TRAFFIC, key, bytes_used)

    # Update total traffic_used in client record
    raw = await r.hget(K_CLIENTS, client_id)
    if raw:
        client = json.loads(raw)
        total = await _calc_total_traffic(r, client_id)
        client["traffic_used"] = total
        await r.hset(K_CLIENTS, client_id, json.dumps(client))


async def _get_client_protocol_traffic(r: redis.Redis, client_id: str) -> dict:
    result = {}
    for proto in ["v2ray", "wireguard", "openvpn", "ikev2", "l2tp", "dnstt", "slipstream", "trusttunnel"]:
        val = await r.hget(K_TRAFFIC, f"{client_id}:{proto}")
        if val:
            result[proto] = float(val)
    return result


async def _calc_total_traffic(r: redis.Redis, client_id: str) -> float:
    """Sum all protocol traffic for a client, return in GB."""
    total_bytes = 0.0
    for proto in ["v2ray", "wireguard", "openvpn", "ikev2", "l2tp", "dnstt", "slipstream", "trusttunnel"]:
        val = await r.hget(K_TRAFFIC, f"{client_id}:{proto}")
        if val:
            total_bytes += float(val)
    return total_bytes / (1024 ** 3)  # Convert bytes to GB


def _calc_expiry(created_at: str, time_limit: dict) -> str:
    from datetime import datetime, timedelta
    try:
        dt = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        dt = datetime.now()

    mode = time_limit.get("mode", "days")
    val = time_limit.get("value", 30)

    if mode == "months":
        month = dt.month + val
        year = dt.year + (month - 1) // 12
        month = ((month - 1) % 12) + 1
        day = min(dt.day, 28)
        dt = dt.replace(year=year, month=month, day=day)
    else:
        dt = dt + timedelta(days=val)

    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ── Core Configs ──

async def get_core_configs() -> dict:
    r = await get_redis()
    raw = await r.hgetall(K_CONFIGS)
    result = {}
    for section, data in raw.items():
        result[section] = json.loads(data)
    return result


async def get_core_config(section: str) -> Optional[dict]:
    r = await get_redis()
    raw = await r.hget(K_CONFIGS, section)
    return json.loads(raw) if raw else None


async def update_core_config(section: str, data: dict):
    r = await get_redis()
    await r.hset(K_CONFIGS, section, json.dumps(data))
    await _add_log("INFO", "System", f"Configuration updated: {section}")


# ── Core Status ──

async def get_core_status(core_id: str) -> dict:
    r = await get_redis()
    raw = await r.hget(K_CORE_STATUS, core_id)
    if not raw:
        return {"status": "stopped", "pid": None, "started_at": None, "version": ""}
    return json.loads(raw)


async def set_core_status(core_id: str, status: dict):
    r = await get_redis()
    await r.hset(K_CORE_STATUS, core_id, json.dumps(status))


async def get_all_core_statuses() -> dict:
    r = await get_redis()
    raw = await r.hgetall(K_CORE_STATUS)
    result = {}
    for core_id, data in raw.items():
        result[core_id] = json.loads(data)
    return result


# ── Logs ──

async def _add_log(level: str, source: str, message: str):
    r = await get_redis()
    entry = json.dumps({
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "level": level,
        "source": source,
        "message": message,
    })
    await r.lpush(K_LOGS, entry)
    await r.ltrim(K_LOGS, 0, 999)  # Keep last 1000 logs


async def add_log(level: str, source: str, message: str):
    await _add_log(level, source, message)


async def get_logs(limit: int = 100) -> list[dict]:
    r = await get_redis()
    raw = await r.lrange(K_LOGS, 0, limit - 1)
    return [json.loads(entry) for entry in raw]


# ── Client Count ──

async def get_client_count() -> int:
    r = await get_redis()
    return await r.hlen(K_CLIENTS)


async def get_total_protocol_traffic(protocol: str) -> dict:
    """Sum traffic for all clients on a protocol. Return {in: 0, out: total_bytes}."""
    r = await get_redis()
    total = 0.0
    # Scan K_TRAFFIC hash for keys ending with :protocol
    # Note: For large datasets, a more optimized approach would be needed
    all_traffic = await r.hgetall(K_TRAFFIC)
    for key, val in all_traffic.items():
        if key.endswith(f":{protocol}"):
            try:
                total += float(val)
            except ValueError:
                pass
    return {"in": 0, "out": int(total)}
