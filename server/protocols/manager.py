"""
CandyConnect - Protocol Manager
Coordinates installed protocol backends and provides a unified interface
for operations used by routes and background tasks.
"""
from __future__ import annotations
import json
from typing import Dict, Optional, List

from config import SUPPORTED_PROTOCOLS
from database import (
    get_all_core_statuses,
    get_core_status,
    set_core_status,
    get_core_config,
    get_all_clients,
    update_client,
    get_logs,
)
import database as db
import logging

logger = logging.getLogger("candyconnect")

# Import protocol implementations (some may be placeholders)
from protocols.v2ray import V2RayProtocol
from protocols.wireguard import WireGuardProtocol
from protocols.openvpn import OpenVPNProtocol
from protocols.ikev2 import IKEv2Protocol
from protocols.l2tp import L2TPProtocol
from protocols.dnstt import DNSTTProtocol
from protocols.slipstream import SlipStreamProtocol
from protocols.trusttunnel import TrustTunnelProtocol


class ProtocolManager:
    def __init__(self) -> None:
        # Instantiate protocol managers lazily to avoid import-time side-effects
        self._protocols: Dict[str, object] = {
            "v2ray": V2RayProtocol(),
            "wireguard": WireGuardProtocol(),
            "openvpn": OpenVPNProtocol(),
            "ikev2": IKEv2Protocol(),
            "l2tp": L2TPProtocol(),
            "dnstt": DNSTTProtocol(),
            "slipstream": SlipStreamProtocol(),
            "trusttunnel": TrustTunnelProtocol(),
        }

    def get_protocol(self, proto_id: str):
        return self._protocols.get(proto_id)

    async def auto_start_protocols(self) -> None:
        """Automatically install and start cores, and sync existing clients."""
        import logging
        logger = logging.getLogger("candyconnect")
        
        # 1. Start Protocols
        for pid in ["v2ray", "wireguard", "openvpn", "ikev2", "l2tp", "dnstt"]:
            try:
                installed = await self.install_protocol(pid)
                started = await self.start_protocol(pid)
                if started:
                    logger.info(f"Auto-started protocol: {pid}")
                else:
                    # Fetch last error from DB logs for this protocol
                    logs = await get_logs(20)
                    reason = "Unknown error"
                    for entry in logs:
                        entry_source = str(entry.get("source", "")).lower()
                        if entry_source == pid.lower():
                            if entry.get("level") == "ERROR":
                                reason = entry.get("message")
                                break
                    logger.warning(f"Failed to auto-start protocol: {pid} (Reason: {reason})")
            except Exception as e:
                logger.error(f"Failed to auto-start protocol {pid}: {e}")

        # 2. Sync Clients to Backends
        try:
            clients = await get_all_clients()
            for client in clients:
                logger.info(f"Syncing client '{client['username']}' to backends...")
                pdata = await self.sync_client(client)
                await update_client(client["id"], {"protocol_data": pdata}, log=False)
            # WireGuard peers are written into wg0.conf; apply now that keys are stored
            if clients and await self._protocols["wireguard"].is_running():
                await self._protocols["wireguard"].start()
        except Exception as e:
            logger.error(f"Failed to sync clients to backends: {e}")

    async def enforce_limits(self) -> int:
        """Remove expired / over-quota clients from the backends (and restore them
        when the admin extends the limit). Returns the number of state changes."""
        changed = 0
        for client in await get_all_clients():
            suspended = bool(client.get("enabled", True) and db.client_limit_reason(client))
            if suspended != bool(client.get("suspended", False)):
                pdata = await self.sync_client(client)
                await update_client(client["id"], {"protocol_data": pdata, "suspended": suspended}, log=False)
                await db.add_log("WARN" if suspended else "INFO", "System",
                                 f"Client '{client['username']}' "
                                 + (f"suspended: {db.client_limit_reason(client)}" if suspended else "re-activated"))
                changed += 1
        return changed

    async def install_protocol(self, proto_id: str) -> bool:
        proto = self.get_protocol(proto_id)
        if not proto:
            return False
        return await proto.install()

    async def start_protocol(self, proto_id: str) -> bool:
        proto = self.get_protocol(proto_id)
        if not proto:
            return False
        return await proto.start()

    async def stop_protocol(self, proto_id: str) -> bool:
        proto = self.get_protocol(proto_id)
        if not proto:
            return False
        return await proto.stop()

    async def restart_protocol(self, proto_id: str) -> bool:
        proto = self.get_protocol(proto_id)
        if not proto:
            return False
        return await proto.restart()

    async def update_traffic_cache(self) -> None:
        """Pull traffic stats from each running protocol backend and persist them
        to the Redis traffic hash (K_TRAFFIC) under a synthetic system-level key
        so the dashboard can show per-protocol totals even when clients don't
        self-report (e.g. native protocols like WireGuard, IKEv2, L2TP).

        The key used is  "system:<protocol>"  to distinguish server-measured
        traffic from client-reported traffic stored as  "<client_id>:<protocol>".
        """
        import logging
        logger = logging.getLogger("candyconnect")

        for pid in SUPPORTED_PROTOCOLS:
            proto = self.get_protocol(pid)
            if not proto:
                continue
            try:
                running = await proto.is_running()
                if not running:
                    continue
                traffic = await proto.get_traffic()
                # get_traffic() returns raw bytes for all protocols
                total_bytes = float(traffic.get("out", 0)) + float(traffic.get("in", 0))
                if total_bytes > 0:
                    # Store as an absolute snapshot (raw bytes) under "system:<proto>".
                    # We overwrite (hset) rather than increment so the value always
                    # reflects the real cumulative counter read from the daemon.
                    r = await db.get_redis()
                    await r.hset(db.K_TRAFFIC, f"system:{pid}", total_bytes)
            except Exception as e:
                logger.debug(f"Traffic cache update failed for {pid}: {e}")

    async def get_all_cores_info(self) -> List[dict]:
        """Collect basic information for all supported protocols.
        Returns a list of dicts: id, name, status, version, port, active_connections, uptime, total_traffic
        """
        import time
        from database import get_total_protocol_traffic
        infos: List[dict] = []
        for pid in SUPPORTED_PROTOCOLS:
            proto = self.get_protocol(pid)
            if not proto:
                continue
            status = await get_core_status(pid)
            try:
                running = await proto.is_running()
            except Exception:
                running = status.get("status") == "running"
            # Reconcile DB status if it changed
            new_status = "running" if running else "stopped"
            if status.get("status") != new_status:
                await set_core_status(pid, {
                    "status": new_status,
                    "pid": status.get("pid"),
                    "started_at": int(time.time()) if running else None,
                    "version": status.get("version", ""),
                })
                status["status"] = new_status
                if running: status["started_at"] = int(time.time())

            try:
                version = status.get("version") or await proto.get_version()
            except Exception:
                version = status.get("version", "")

            try:
                active = await proto.get_active_connections()
            except Exception:
                active = 0

            port = await self._get_protocol_port(pid)
            
            # Calculate uptime
            uptime = 0
            if running and status.get("started_at"):
                uptime = int(time.time()) - int(status["started_at"])
            
            # Get total traffic
            traffic = await get_total_protocol_traffic(pid)

            infos.append({
                "id": pid,
                "name": getattr(proto, "PROTOCOL_NAME", pid.upper()),
                "status": new_status,
                "version": version,
                "port": port,
                "active_connections": active,
                "uptime": uptime,
                "total_traffic": traffic,
            })
        return infos

    async def add_client_to_protocols(
        self,
        username: str,
        client_data: dict,
        enabled_protocols: dict,
        existing_data: Optional[dict] = None,
    ) -> dict:
        """Add a client to all enabled protocols. Returns protocol_data mapping."""
        result: Dict[str, dict] = {}
        for pid, enabled in (enabled_protocols or {}).items():
            if not enabled:
                continue
            proto = self.get_protocol(pid)
            if not proto:
                continue
            try:
                # Reuse existing keys/configs (WireGuard keys, DNSTT ssh password, ...),
                # but the current account data wins (e.g. a changed password).
                data_in = dict(client_data)
                for k, v in ((existing_data or {}).get(pid) or {}).items():
                    if k != "password":
                        data_in[k] = v
                pdata = await proto.add_client(username, data_in)
                if isinstance(pdata, dict):
                    result[pid] = pdata
            except Exception as e:
                # Skip failing protocol but continue others; keep old data so keys aren't lost
                logger.warning(f"add_client failed for {pid}/{username}: {e}")
                if existing_data and existing_data.get(pid):
                    result[pid] = existing_data[pid]
                continue
        return result

    async def sync_client(self, client: dict) -> dict:
        """Apply a client's current state to all backends and return its protocol_data.

        Enabled protocols get the client (re)added; protocols that were disabled,
        or every protocol when the account itself is disabled, get it removed.
        """
        enabled = dict(client.get("protocols") or {})
        if not client.get("enabled", True) or db.client_limit_reason(client):
            enabled = {}
        existing = client.get("protocol_data") or {}
        for pid, data in existing.items():
            if not enabled.get(pid):
                proto = self.get_protocol(pid)
                if proto:
                    try:
                        await proto.remove_client(client["username"], data or {})
                    except Exception as e:
                        logger.warning(f"remove_client failed for {pid}/{client['username']}: {e}")
        pdata = await self.add_client_to_protocols(
            client["username"], client, enabled, existing_data=existing,
        )
        # Keep stored data (keys, uuid) of disabled protocols so re-enabling restores the same config
        for pid, data in existing.items():
            pdata.setdefault(pid, data)
        return pdata

    async def remove_client_from_protocols(self, client: dict) -> None:
        """Remove a client from all protocols using stored protocol_data."""
        username = client.get("username")
        pdata = client.get("protocol_data", {}) or {}
        for pid, data in pdata.items():
            proto = self.get_protocol(pid)
            if not proto:
                continue
            try:
                await proto.remove_client(username, data)
            except Exception:
                continue

    async def get_client_configs(
        self,
        username: str,
        server_ip: str,
        enabled_protocols: dict,
        protocol_data: dict,
    ) -> dict:
        """Return per-protocol client config for all enabled protocols."""
        result: Dict[str, dict] = {}
        for pid, enabled in (enabled_protocols or {}).items():
            if not enabled:
                continue
            proto = self.get_protocol(pid)
            if not proto:
                continue
            try:
                pdata = (protocol_data or {}).get(pid, {})
                cfg = await proto.get_client_config(username, server_ip, pdata)
                if isinstance(cfg, dict) and cfg:
                    result[pid] = cfg
            except Exception:
                continue
        return result

    async def _get_protocol_port(self, pid: str) -> int:
        """Best-effort to read port from protocol config; fallback to DEFAULT_PORT."""
        proto = self.get_protocol(pid)
        default_port = getattr(proto, "DEFAULT_PORT", 0) if proto else 0
        try:
            cfg = await get_core_config(pid)
            if not cfg:
                return default_port
            if pid == "wireguard":
                return int(cfg.get("listen_port", default_port))
            elif pid == "openvpn":
                return int(cfg.get("port", default_port))
            elif pid == "ikev2":
                return int(cfg.get("port", default_port))
            elif pid == "l2tp":
                return int(cfg.get("port", default_port))
            elif pid == "dnstt":
                return int(cfg.get("listen_port", default_port))
            elif pid in ("slipstream", "trusttunnel"):
                return int(cfg.get("port", default_port))
            elif pid == "v2ray":
                # Parse first inbound port from JSON
                raw = cfg.get("config_json")
                if raw:
                    try:
                        obj = json.loads(raw)
                        for inbound in obj.get("inbounds", []):
                            if "port" in inbound:
                                return int(inbound.get("port", default_port))
                    except Exception:
                        pass
                return default_port
        except Exception:
            return default_port
        return default_port


# Singleton instance expected by main.py
protocol_manager = ProtocolManager()
