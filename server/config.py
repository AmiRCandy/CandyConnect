"""
CandyConnect Server - Configuration
"""
import os, secrets

# ── Paths ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("CC_DATA_DIR", "/opt/candyconnect")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
LOG_DIR = os.path.join(DATA_DIR, "logs")
CORE_DIR = os.path.join(DATA_DIR, "cores")

# ── Redis ──
def _build_redis_url() -> str:
    explicit = os.environ.get("CC_REDIS_URL")
    if explicit:
        return explicit
    password = os.environ.get("CC_REDIS_PASSWORD", "")
    if password:
        return f"redis://:{password}@127.0.0.1:6379/0"
    return "redis://127.0.0.1:6379/0"


REDIS_URL = _build_redis_url()

# ── HTTP / CORS ──
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CC_CORS_ORIGINS", "").split(",")
    if origin.strip()
]
FORCE_ADMIN_SYNC = os.environ.get("CC_FORCE_ADMIN_SYNC", "").lower() in ("1", "true", "yes")

# ── JWT (persist secret across restarts unless provided via env) ──

def _load_or_create_jwt_secret() -> str:
    # Priority 1: explicit environment variable
    env_secret = os.environ.get("CC_JWT_SECRET")
    if env_secret:
        return env_secret
    # Priority 2: secret file in DATA_DIR
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        secret_file = os.path.join(DATA_DIR, ".jwt_secret")
        if os.path.exists(secret_file):
            with open(secret_file, "r") as f:
                val = f.read().strip()
                if val:
                    return val
        # Create new persistent secret
        val = secrets.token_urlsafe(48)
        with open(secret_file, "w") as f:
            f.write(val)
        try:
            os.chmod(secret_file, 0o600)
        except Exception:
            pass
        return val
    except Exception:
        # Fallback: ephemeral secret (tokens will invalidate on restart)
        return secrets.token_urlsafe(48)

JWT_SECRET = _load_or_create_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_ADMIN_EXPIRE_HOURS = 24
JWT_CLIENT_EXPIRE_HOURS = int(os.environ.get("CC_JWT_CLIENT_EXPIRE_HOURS", "168"))  # 7 days

# ── Panel ──
PANEL_PORT = int(os.environ.get("CC_PANEL_PORT", "8443"))
PANEL_PATH = os.environ.get("CC_PANEL_PATH", "/candyconnect")
PANEL_DOMAIN = os.environ.get("CC_DOMAIN", "vpn.candyconnect.io")
PANEL_VERSION = "1.4.2"
PANEL_BUILD_DATE = "2026-01-28"

# ── Default Admin ──
DEFAULT_ADMIN_USER = os.environ.get("CC_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASS = os.environ.get("CC_ADMIN_PASS", "")

# ── TLS (optional uvicorn termination) ──
SSL_CERTFILE = os.environ.get("CC_SSL_CERT", "")
SSL_KEYFILE = os.environ.get("CC_SSL_KEY", "")

# ── Protocols ──
SUPPORTED_PROTOCOLS = [
    "v2ray", "wireguard", "openvpn", "ikev2", "l2tp", "dnstt",
    "slipstream", "trusttunnel",
]
