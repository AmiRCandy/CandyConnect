"""
CandyConnect Server - Client API Router
Endpoints used by the VPN client applications.
"""
import time
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

import database as db
import auth
import uuid
from system_info import get_public_ip
from protocols.manager import protocol_manager
from config import SUPPORTED_PROTOCOLS

router = APIRouter(tags=["client"])


class ClientLoginRequest(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
async def client_login(req: ClientLoginRequest):
    client = await db.verify_client(req.username, req.password)
    if not client:
        raise HTTPException(status_code=401, detail="Invalid username, password or account disabled")
    
    token = auth.create_client_token(req.username, client["id"])
    
    # Get panel config for server name and IP if possible
    panel_cfg = await db.get_core_config("candyconnect") or {}
    server_name = panel_cfg.get("server_name") or panel_cfg.get("panel_domain") or "CandyConnect Server"
    
    # Check if a custom server IP is set in config, otherwise auto-detect
    server_ip = panel_cfg.get("server_ip")
    if not server_ip:
        server_ip = await get_public_ip()

    return {
        "success": True, 
        "message": "Login successful", 
        "token": token,
        "server_info": {
            "hostname": server_name,
            "ip": server_ip,
            "version": "1.4.2"
        },
        "account": _format_client(client)
    }


def _format_client(client: dict) -> dict:
    """Consistently format client data for the API response."""
    return {
        "username": client["username"],
        "comment": client.get("comment", ""),
        "enabled": client["enabled"],
        "traffic_used": client["traffic_used"],
        "traffic_limit": client["traffic_limit"],
        "time_limit": client.get("time_limit", {"mode": "monthly", "value": 30, "onHold": False}),
        "time_used": client.get("time_used", 0),
        "created_at": client["created_at"],
        "expires_at": client["expires_at"],
        "protocols": client["protocols"],
        "last_connected_ip": client.get("last_connected_ip", ""),
        "last_connected_time": client.get("last_connected_time", ""),
        "connection_history": client.get("connection_history", [])
    }


@router.get("/account")
async def get_account(payload=Depends(auth.require_client)):
    client_id = payload.get("client_id")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    return {
        "success": True,
        "data": _format_client(client)
    }


@router.get("/protocols")
async def get_protocols(payload=Depends(auth.require_client)):
    """Return the list of protocol cores with their status, port, version, etc.
    Filtered by the client's allowed protocols."""
    client_id = payload.get("client_id")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    client_protocols = client.get("protocols", {})
    cores = await protocol_manager.get_all_cores_info()
    
    result = []
    icon_map = {
        "v2ray": "⚡", "wireguard": "🛡️", "openvpn": "🔒",
        "ikev2": "🔐", "l2tp": "📡", "dnstt": "🌐",
        "slipstream": "💨", "trusttunnel": "🏰",
    }
    for core in cores:
        pid = core["id"]
        enabled_for_user = client_protocols.get(pid, False)
        result.append({
            "id": pid,
            "name": core["name"],
            "status": core["status"],
            "version": core.get("version", ""),
            "port": core.get("port", 0),
            "active_connections": core.get("active_connections", 0),
            "icon": icon_map.get(pid, "🔌"),
            "enabled_for_user": enabled_for_user,
        })
    
    return {
        "success": True,
        "data": result
    }


@router.get("/configs")
async def get_all_configs(payload=Depends(auth.require_client)):
    """Return all VPN configs the client is entitled to use.
    This builds a list of individual connection configs from the enabled protocols,
    using the client's actual credentials (UUIDs, keys, etc.).
    """
    import json
    import logging
    logger = logging.getLogger("candyconnect.api")
    
    client_id = payload.get("client_id")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    # Get panel config for IP
    panel_cfg = await db.get_core_config("candyconnect") or {}
    server_ip = panel_cfg.get("server_ip") or await get_public_ip()
    # Normalize protocol keys to lowercase for easier matching
    raw_protocols = client.get("protocols", {})
    client_protocols = {str(k).lower(): v for k, v in raw_protocols.items()}
    protocol_data = client.get("protocol_data", {}) or {}
    
    configs = []
    cores = await protocol_manager.get_all_cores_info()
    core_map = {str(c["id"]).lower(): c for c in cores}
    
    logger.info(f"Building personalised configs for client {client_id}.")

    def is_enabled(proto_name: str) -> bool:
        return client_protocols.get(proto_name.lower()) is True

    # 1. V2Ray (Xray)
    if is_enabled("v2ray"):
        v2ray_cfg_meta = await db.get_core_config("v2ray")
        pdata = protocol_data.get("v2ray", {})
        client_uuid = pdata.get("uuid") or str(uuid.uuid5(uuid.NAMESPACE_DNS, client["username"]))
        
        added_v2ray = False
        if v2ray_cfg_meta:
            try:
                raw_json = v2ray_cfg_meta.get("config_json", "{}")
                xray_cfg = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
                inbounds = xray_cfg.get("inbounds", [])
                
                for inbound in inbounds:
                    tag = inbound.get("tag", "v2ray-default")
                    protocol = inbound.get("protocol", "vless")
                    port = inbound.get("port", 443)
                    stream = inbound.get("streamSettings", {})
                    network = stream.get("network", "tcp")
                    security = stream.get("security", "none")
                    
                    link_params = f"type={network}&security={security}"
                    if security == "tls":
                        tls_settings = stream.get("tlsSettings", {})
                        sni = tls_settings.get("serverName", "")
                        if sni: link_params += f"&sni={sni}"
                    
                    config_link = f"{protocol}://{client_uuid}@{server_ip}:{port}?{link_params}#CC-{protocol.upper()}-{network}"
                    
                    network_display = {
                        "ws": "WebSocket", "websocket": "WebSocket",
                        "grpc": "gRPC", "tcp": "TCP", "kcp": "mKCP",
                        "http": "HTTP/2", "quic": "QUIC",
                    }.get(network, network)
                    
                    configs.append({
                        "id": tag if "-" in tag else f"v2ray-{tag}",
                        "name": f"V2Ray {protocol.upper()} + {network_display}",
                        "protocol": "V2Ray",
                        "transport": network,
                        "security": security if security != "none" else "plain",
                        "address": server_ip,
                        "port": port,
                        "configLink": config_link,
                        "icon": "⚡",
                        "extraData": {"uuid": client_uuid, "protocol": protocol}
                    })
                    added_v2ray = True
            except Exception as e:
                logger.error(f"Failed to build V2Ray personalised link: {e}")

        if not added_v2ray:
            configs.append({
                "id": "v2ray-basic",
                "name": "V2Ray Basic",
                "protocol": "V2Ray",
                "transport": "tcp",
                "security": "tls",
                "address": server_ip,
                "port": core_map.get("v2ray", {}).get("port", 443),
                "configLink": f"vless://{client_uuid}@{server_ip}:443?type=tcp&security=tls#CC-Basic",
                "icon": "⚡",
                "extraData": {"uuid": client_uuid, "protocol": "vless"}
            })

    # 2. WireGuard
    if is_enabled("wireguard"):
        wg_cfg_meta = await db.get_core_config("wireguard")
        port = int((wg_cfg_meta or {}).get("listen_port", 51820))
        pdata = protocol_data.get("wireguard", {})
        privkey = pdata.get("private_key", "")
        
        # Link including private key if available
        link = f"wireguard://{server_ip}:{port}"
        if privkey:
            link = f"wireguard://{privkey}@{server_ip}:{port}"

        # Build extraData for WireGuard (the full config)
        wg_extra = {
            "private_key": privkey,
            "address": pdata.get("address", ""),
            "public_key": (wg_cfg_meta or {}).get("public_key", ""),
            "dns": (wg_cfg_meta or {}).get("dns", "1.1.1.1"),
            "mtu": (wg_cfg_meta or {}).get("mtu", 1420),
        }

        configs.append({
            "id": "wireguard-1",
            "name": "WireGuard",
            "protocol": "WireGuard",
            "transport": "udp",
            "security": "curve25519",
            "address": server_ip,
            "port": port,
            "configLink": link,
            "icon": "🛡️",
            "extraData": wg_extra
        })

    # 3. OpenVPN
    if is_enabled("openvpn"):
        ovpn_cfg = await db.get_core_config("openvpn")
        port = int((ovpn_cfg or {}).get("port", 1194))
        proto = (ovpn_cfg or {}).get("protocol", "udp")
        configs.append({
            "id": "openvpn-1",
            "name": f"OpenVPN ({proto.upper()})",
            "protocol": "OpenVPN",
            "transport": proto,
            "security": "tls",
            "address": server_ip,
            "port": port,
            "configLink": f"openvpn://{server_ip}:{port}?proto={proto}",
            "icon": "🔒",
            "extraData": {"proto": proto}
        })

    # 4. IKEv2
    if is_enabled("ikev2"):
        ike_cfg = await db.get_core_config("ikev2")
        port = int((ike_cfg or {}).get("port", 500))
        configs.append({
            "id": "ikev2-1",
            "name": "IKEv2/IPSec",
            "protocol": "IKEv2",
            "transport": "udp",
            "security": "ipsec",
            "address": server_ip,
            "port": port,
            "configLink": f"ikev2://{server_ip}:{port}",
            "icon": "🔐",
            "extraData": {"username": client["username"]}
        })

    # 5. L2TP
    if is_enabled("l2tp"):
        l2tp_cfg = await db.get_core_config("l2tp")
        port = int((l2tp_cfg or {}).get("port", 1701))
        configs.append({
            "id": "l2tp-1",
            "name": "L2TP/IPSec",
            "protocol": "L2TP",
            "transport": "udp",
            "security": "ipsec",
            "address": server_ip,
            "port": port,
            "configLink": f"l2tp://{server_ip}:{port}",
            "icon": "📡",
            "extraData": {"username": client["username"]}
        })

    # 6. DNSTT
    if is_enabled("dnstt"):
        dnstt_cfg = await db.get_core_config("dnstt")
        port = int((dnstt_cfg or {}).get("listen_port", 5300))
        domain = (dnstt_cfg or {}).get("domain", "dns.candyconnect.io")
        pdata = protocol_data.get("dnstt", {})
        ssh_user = pdata.get("ssh_username", f"dnstt_{client['username']}")
        
        configs.append({
            "id": "dnstt-1",
            "name": "DNSTT Tunnel",
            "protocol": "DNSTT",
            "transport": "dns",
            "security": "obfs",
            "address": server_ip,
            "port": port,
            "configLink": f"dnstt://{ssh_user}@{domain}:{port}",
            "icon": "🌐",
            "extraData": {
                "ssh_username": ssh_user,
                "ssh_password": pdata.get("ssh_password", ""),
                "public_key": (dnstt_cfg or {}).get("public_key", ""),
                "domain": domain
            }
        })

    # 7. SlipStream
    if is_enabled("slipstream"):
        slip_cfg = await db.get_core_config("slipstream")
        port = int((slip_cfg or {}).get("port", 8388))
        configs.append({
            "id": "slipstream-1",
            "name": "SlipStream",
            "protocol": "SlipStream",
            "transport": "tcp",
            "security": "tls",
            "address": server_ip,
            "port": port,
            "configLink": f"slipstream://{server_ip}:{port}",
            "icon": "💨",
        })

    # 8. TrustTunnel
    if is_enabled("trusttunnel"):
        tt_cfg = await db.get_core_config("trusttunnel")
        port = int((tt_cfg or {}).get("port", 9443))
        configs.append({
            "id": "trusttunnel-1",
            "name": "TrustTunnel",
            "protocol": "TrustTunnel",
            "transport": "tcp",
            "security": "tls",
            "address": server_ip,
            "port": port,
            "configLink": f"trusttunnel://{server_ip}:{port}",
            "icon": "🏰",
        })

    logger.info(f"Returning {len(configs)} personalised configs for client {client_id}")
    return {"success": True, "data": configs}


@router.get("/configs/{protocol}")
async def get_protocol_config(protocol: str, payload=Depends(auth.require_client)):
    client_id = payload.get("client_id")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    # Check normalized keys
    raw_protocols = client.get("protocols", {})
    client_protocols = {str(k).lower(): v for k, v in raw_protocols.items()}
    
    if not client_protocols.get(protocol.lower()):
        raise HTTPException(status_code=403, detail=f"Protocol {protocol} not allowed for this account")
    
    # Get panel config for IP
    panel_cfg = await db.get_core_config("candyconnect") or {}
    server_ip = panel_cfg.get("server_ip") or await get_public_ip()
    p_mgr = protocol_manager.get_protocol(protocol)
    if not p_mgr:
        raise HTTPException(status_code=404, detail="Protocol manager not found")
        
    pdata = (client.get("protocol_data", {}) or {}).get(protocol, {})
    config = await p_mgr.get_client_config(client["username"], server_ip, pdata)
    
    return {"success": True, "data": config}


class TrafficReport(BaseModel):
    bytes_sent: int = 0
    bytes_received: int = 0
    bytes_used: int = 0
    protocol: str


@router.post("/traffic")
async def report_traffic(req: TrafficReport, payload=Depends(auth.require_client)):
    client_id = payload.get("client_id")
    total_bytes = req.bytes_used or (req.bytes_sent + req.bytes_received)
    
    # Update client usage in DB (id, protocol, bytes)
    await db.update_client_traffic(client_id, req.protocol, total_bytes)
    return {"success": True, "message": "Traffic reported"}


class ConnectionEvent(BaseModel):
    protocol: str
    event: str = "connect"  # "connect" or "disconnect"
    ip: str = ""


@router.post("/connect")
async def report_connection(req: ConnectionEvent, payload=Depends(auth.require_client)):
    client_id = payload.get("client_id")
    username = payload.get("username", payload.get("sub", ""))
    ip = req.ip or "0.0.0.0"
    
    await db.add_connection_history(client_id, req.protocol, req.event, ip)
    return {"success": True, "message": f"Connection {req.event} logged"}


@router.get("/server")
async def get_server_info():
    # Get panel config for IP
    panel_cfg = await db.get_core_config("candyconnect") or {}
    ip = panel_cfg.get("server_ip") or await get_public_ip()
    hostname = panel_cfg.get("server_name") or panel_cfg.get("panel_domain") or "CandyConnect Server"
    return {
        "success": True, 
        "data": {
            "hostname": hostname,
            "ip": ip,
            "version": "1.4.2"
        }
    }


@router.get("/ping")
async def ping():
    """Health check for client connectivity."""
    return {"success": True, "message": "client pong", "timestamp": int(time.time())}


@router.get("/ping/{config_id}")
async def ping_config(config_id: str, payload=Depends(auth.require_client)):
    """Ping a specific config/protocol to measure latency.
    Returns a mock latency based on the real server processing time.
    In production, this would actually test the protocol endpoint.
    """
    start = time.monotonic()
    
    # Simulate real processing: check if the protocol is running
    protocol_id = config_id.split("-")[0] if "-" in config_id else config_id
    
    # Special case for generic server ping
    if protocol_id.lower() in ["server", "ping", "all"]:
        return {
            "success": True,
            "data": {
                "config_id": config_id,
                "latency": 0,
                "reachable": True,
                "protocol_status": "running",
            }
        }

    # Map config IDs to protocol IDs
    proto_map = {
        "vless": "v2ray", "vmess": "v2ray", "trojan": "v2ray", 
        "shadowsocks": "v2ray", "wireguard": "wireguard",
        "openvpn": "openvpn", "ikev2": "ikev2", "l2tp": "l2tp",
        "dnstt": "dnstt", "slipstream": "slipstream",
        "trusttunnel": "trusttunnel",
    }
    
    resolved_proto = proto_map.get(protocol_id.lower(), protocol_id.lower())
    
    core_status = await db.get_core_status(resolved_proto)
    is_running = core_status.get("status") == "running"
    
    # Calculate processing delay as base latency
    elapsed_ms = (time.monotonic() - start) * 1000
    
    if is_running:
        # Add a realistic mock network latency (server processing + simulated RTT)
        import random
        base_latency = elapsed_ms + random.uniform(15, 80)  # base processing
        # Different protocols have different typical latencies
        protocol_overhead = {
            "v2ray": random.uniform(10, 60),
            "wireguard": random.uniform(5, 30),
            "openvpn": random.uniform(20, 80),
            "ikev2": random.uniform(15, 50),
            "l2tp": random.uniform(25, 90),
            "dnstt": random.uniform(50, 200),
            "slipstream": random.uniform(15, 60),
            "trusttunnel": random.uniform(20, 70),
        }
        overhead = protocol_overhead.get(resolved_proto, random.uniform(20, 60))
        latency = int(base_latency + overhead)
        
        return {
            "success": True,
            "data": {
                "config_id": config_id,
                "latency": 0, # Client will measure real network RTT
                "reachable": True,
                "protocol_status": "running",
            }
        }
    else:
        return {
            "success": True,
            "data": {
                "config_id": config_id,
                "latency": 0,
                "reachable": False,
                "protocol_status": "stopped",
            }
        }


@router.post("/ping-all")
async def ping_all_configs(payload=Depends(auth.require_client)):
    """Ping all configs available to the logged in client.
    Returns latency results for every config entry.
    """
    client_id = payload.get("client_id")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    # Reuse the configs endpoint logic to get all config IDs
    # Get panel config for IP
    panel_cfg = await db.get_core_config("candyconnect") or {}
    server_ip = panel_cfg.get("server_ip") or await get_public_ip()
    
    raw_protocols = client.get("protocols", {})
    client_protocols = {str(k).lower(): v for k, v in raw_protocols.items()}
    
    cores = await protocol_manager.get_all_cores_info()
    core_map = {str(c["id"]).lower(): c for c in cores}
    
    results = []
    import random
    
    protocol_overhead = {
        "v2ray": (10, 60), "wireguard": (5, 30), "openvpn": (20, 80),
        "ikev2": (15, 50), "l2tp": (25, 90), "dnstt": (50, 200),
        "slipstream": (15, 60), "trusttunnel": (20, 70),
    }
    
    for proto_id, enabled in client_protocols.items():
        if not enabled:
            continue
        core_info = core_map.get(proto_id, {})
        is_running = core_info.get("status") == "running"
        
        results.append({
            "config_id": f"{proto_id}-1",
            "protocol": proto_id,
            "latency": 0 if is_running else 0,
            "reachable": is_running,
        })
    
    return {"success": True, "data": results}



