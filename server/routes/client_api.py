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
import tunnels as tunnels_mod
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
    reason = db.client_limit_reason(client)
    if reason:
        raise HTTPException(status_code=403, detail=reason)
    
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


async def _ensure_protocol_data(client: dict, pid: str, required_key: str) -> dict:
    """Create the client's backend data on demand (e.g. the client was created
    before the protocol was installed, so no keys were generated then)."""
    pdata_all = client.get("protocol_data") or {}
    pdata = pdata_all.get(pid) or {}
    if pdata.get(required_key):
        return pdata
    result = await protocol_manager.add_client_to_protocols(
        client["username"], client, {pid: True}, existing_data=pdata_all)
    if result.get(pid, {}).get(required_key):
        pdata_all[pid] = result[pid]
        await db.update_client(client["id"], {"protocol_data": pdata_all}, log=False)
        client["protocol_data"] = pdata_all
        return result[pid]
    return pdata


def _v2ray_share_link(protocol: str, inbound: dict, stream: dict, client_uuid: str,
                      password: str, server_ip: str, port, name: str) -> str:
    """Build a standard share link (importable in v2rayN / v2rayNG / Hiddify / sing-box)."""
    import base64, json
    from urllib.parse import urlencode, quote

    network = stream.get("network", "tcp")
    security = stream.get("security", "none")
    params = {"type": network, "security": security}
    path = host = ""
    if network == "ws":
        ws = stream.get("wsSettings", {}) or {}
        path = ws.get("path", "/")
        host = (ws.get("headers") or {}).get("Host", "") or ws.get("host", "")
    elif network == "grpc":
        params["serviceName"] = (stream.get("grpcSettings", {}) or {}).get("serviceName", "")
    elif network in ("httpupgrade", "splithttp", "xhttp"):
        hs = stream.get(f"{network}Settings", {}) or {}
        path, host = hs.get("path", "/"), hs.get("host", "")
    if path:
        params["path"] = path
    if host:
        params["host"] = host
    if security == "tls":
        tls = stream.get("tlsSettings", {}) or {}
        if tls.get("serverName"):
            params["sni"] = tls["serverName"]
        params["fp"] = tls.get("fingerprint", "chrome")
    elif security == "reality":
        from protocols.v2ray import V2RayProtocol
        rs = V2RayProtocol._client_stream_settings(stream).get("realitySettings", {})
        params.update({"sni": rs.get("serverName", ""), "pbk": rs.get("publicKey", ""),
                       "sid": rs.get("shortId", ""), "fp": rs.get("fingerprint", "chrome")})

    if protocol == "vmess":
        obj = {"v": "2", "ps": name, "add": server_ip, "port": str(port), "id": client_uuid,
               "aid": "0", "scy": "auto", "net": network, "type": "none", "host": host,
               "path": path, "tls": "tls" if security == "tls" else "", "sni": params.get("sni", "")}
        return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()
    if protocol == "shadowsocks":
        ss = inbound.get("settings", {}) or {}
        userinfo = base64.urlsafe_b64encode(
            f"{ss.get('method', 'aes-256-gcm')}:{ss.get('password', '')}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{server_ip}:{port}#{quote(name)}"
    if protocol == "trojan":
        return f"trojan://{quote(password, safe='')}@{server_ip}:{port}?{urlencode(params)}#{quote(name)}"
    # vless
    params["encryption"] = "none"
    for c in (inbound.get("settings", {}) or {}).get("clients", []) or []:
        if c.get("id") == client_uuid and c.get("flow"):
            params["flow"] = c["flow"]
    return f"vless://{client_uuid}@{server_ip}:{port}?{urlencode(params)}#{quote(name)}"


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
                    if protocol not in ("vless", "vmess", "trojan", "shadowsocks"):
                        continue  # api / dokodemo-door / socks inbounds are not client configs
                    port = inbound.get("port", 443)
                    stream = inbound.get("streamSettings", {}) or {}
                    config_link = _v2ray_share_link(
                        protocol, inbound, stream, client_uuid,
                        pdata.get("password") or client.get("password", ""),
                        server_ip, port, f"CC-{protocol.upper()}-{stream.get('network', 'tcp')}",
                    )
                    network = stream.get("network", "tcp")
                    security = stream.get("security", "none")

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

                    # Same inbound reached through each relay tunnel that forwards its port
                    for relay in await tunnels_mod.relays_for_port(port):
                        base_id = tag if "-" in tag else f"v2ray-{tag}"
                        configs.append({
                            "id": f"{base_id}~relay-{relay['id']}",
                            "name": f"V2Ray {protocol.upper()} + {network_display} (via {relay['name']})",
                            "protocol": "V2Ray",
                            "transport": network,
                            "security": security if security != "none" else "plain",
                            "address": relay["ip"],
                            "port": relay["listen_port"],
                            "configLink": _v2ray_share_link(
                                protocol, inbound, stream, client_uuid,
                                pdata.get("password") or client.get("password", ""),
                                relay["ip"], relay["listen_port"],
                                f"CC-{protocol.upper()}-{network}-{relay['name']}",
                            ),
                            "icon": "⚡",
                            "extraData": {"uuid": client_uuid, "protocol": protocol, "relay": relay["name"]},
                        })
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
        pdata = await _ensure_protocol_data(client, "wireguard", "private_key")
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

        # Try to get the personalised .ovpn config (with embedded certs) for this client
        ovpn_extra = {"proto": proto, "port": port}
        try:
            from protocols.manager import protocol_manager as _pm
            p_mgr = _pm.get_protocol("openvpn")
            if p_mgr:
                pdata_ovpn = protocol_data.get("openvpn", {})
                ovpn_client_cfg = await p_mgr.get_client_config(
                    client["username"], server_ip, pdata_ovpn
                )
                if ovpn_client_cfg and ovpn_client_cfg.get("ovpn_config"):
                    ovpn_extra["ovpn_config"] = ovpn_client_cfg["ovpn_config"]
                    ovpn_extra["username"] = client["username"]
        except Exception as _e:
            logger.warning(f"Could not fetch OpenVPN client config: {_e}")

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
            "extraData": ovpn_extra,
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
            "extraData": {"username": client["username"], "psk": (l2tp_cfg or {}).get("psk", "")}
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

    # 7. SlipStream (DNS tunnel; SSH account shared with DNSTT)
    if is_enabled("slipstream"):
        slip_cfg = await db.get_core_config("slipstream") or {}
        pdata = await _ensure_protocol_data(client, "slipstream", "ssh_username")
        domain = slip_cfg.get("domain", "")
        configs.append({
            "id": "slipstream-1",
            "name": "SlipStream DNS Tunnel",
            "protocol": "SlipStream",
            "transport": "dns",
            "security": "quic",
            "address": server_ip,
            "port": 53,
            "configLink": f"slipstream://{pdata.get('ssh_username', '')}@{domain}",
            "icon": "💨",
            "extraData": {
                "domain": domain,
                "congestion_control": slip_cfg.get("congestion_control", "bbr"),
                "tunnel_mode": "ssh",
                "ssh_username": pdata.get("ssh_username", ""),
                "ssh_password": pdata.get("ssh_password", ""),
            },
        })

    # 8. TrustTunnel (tt:// link is exported by the endpoint itself)
    if is_enabled("trusttunnel"):
        tt_mgr = protocol_manager.get_protocol("trusttunnel")
        tt = await tt_mgr.get_client_config(client["username"], server_ip, {"password": client.get("password", "")})
        configs.append({
            "id": "trusttunnel-1",
            "name": "TrustTunnel",
            "protocol": "TrustTunnel",
            "transport": "https",
            "security": "tls",
            "address": server_ip,
            "port": tt["port"],
            "configLink": tt.get("link") or f"tt://{server_ip}:{tt['port']}",
            "icon": "🏰",
            "extraData": {
                "hostname": tt.get("hostname", ""),
                "username": client["username"],
                "endpoint_config": tt.get("endpoint_config", ""),
            },
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
    raw_protocols = client.get("protocols", {}) or {}
    client_protocols = {str(k).lower(): v for k, v in raw_protocols.items()}

    # Mapping of sub-protocol IDs to core protocol IDs
    proto_map = {
        "vless": "v2ray", "vmess": "v2ray", "trojan": "v2ray", 
        "shadowsocks": "v2ray", "wireguard": "wireguard",
        "openvpn": "openvpn", "ikev2": "ikev2", "l2tp": "l2tp",
        "dnstt": "dnstt", "slipstream": "slipstream",
        "trusttunnel": "trusttunnel",
    }
    
    # 1. Identify core protocol
    # If protocol is "vless-tcp", root is "vless", which maps to "v2ray"
    # "<config id>~relay-<tunnel id>": same config, but connect through a relay server
    relay = None
    if "~relay-" in protocol:
        protocol, relay_id = protocol.split("~relay-", 1)
        relay = await db.get_tunnel(relay_id)
        if not relay or relay.get("status") != "installed":
            raise HTTPException(status_code=404, detail="Relay tunnel not found or not installed")

    proto_root = protocol.split("-")[0].lower()
    core_protocol = proto_map.get(proto_root, proto_root)
    if protocol_manager.get_protocol(core_protocol) is None:
        # Custom V2Ray inbound tags (e.g. "inbound-443") don't start with a protocol name
        core_protocol = "v2ray"
    
    # 2. Check if admin override (Admins have access to all)
    admin_user = await db.get_admin_username()
    is_admin = client["username"] == admin_user
    
    if not is_admin and not client_protocols.get(core_protocol):
        raise HTTPException(status_code=403, detail=f"Protocol {protocol} ({core_protocol}) not allowed for this account")
    
    # Get panel config for IP
    panel_cfg = await db.get_core_config("candyconnect") or {}
    server_ip = panel_cfg.get("server_ip") or await get_public_ip()
    
    # Use core_protocol to get the manager (v2ray, wireguard, etc.)
    p_mgr = protocol_manager.get_protocol(core_protocol)
    if not p_mgr:
        raise HTTPException(status_code=404, detail=f"Protocol manager for {core_protocol} not found")
        
    if core_protocol == "wireguard":
        pdata = await _ensure_protocol_data(client, "wireguard", "private_key")
    elif core_protocol == "slipstream":
        pdata = await _ensure_protocol_data(client, "slipstream", "ssh_username")
    elif core_protocol == "trusttunnel":
        pdata = {"password": client.get("password", "")}
    else:
        pdata = (client.get("protocol_data", {}) or {}).get(core_protocol, {})
    config = await p_mgr.get_client_config(client["username"], server_ip, pdata, config_id=protocol)
    if relay and config and core_protocol == "v2ray":
        # Point the outbound at the relay's forwarded port
        for ob in config.get("config_json", {}).get("outbounds", []):
            for key in ("vnext", "servers"):
                for srv in (ob.get("settings") or {}).get(key, []) or []:
                    matches = await tunnels_mod.relays_for_port(srv.get("port"))
                    hit = next((m for m in matches if m["id"] == relay["id"]), None)
                    if hit:
                        srv["address"], srv["port"] = relay["ip"], hit["listen_port"]
        config["server"] = relay["ip"]
    
    if not config:
        raise HTTPException(status_code=404, detail=f"No matching config found for '{protocol}'")
    
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


class HeartbeatRequest(BaseModel):
    protocol: str = ""
    ip: str = ""


@router.post("/heartbeat")
async def client_heartbeat(req: HeartbeatRequest, payload=Depends(auth.require_client)):
    """
    Clients call this every ~60s while connected to keep their online status alive.
    If no heartbeat is received within 5 minutes the server marks the client offline.
    """
    client_id = payload.get("client_id")
    ip = req.ip or "0.0.0.0"
    await db.add_connection_history(client_id, req.protocol or "unknown", "heartbeat", ip)
    return {"success": True, "message": "Heartbeat received"}


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


@router.get("/network-speed")
async def get_network_speed(payload=Depends(auth.require_client)):
    """Return real-time network I/O speed measured on the server using psutil.
    Uses a short delta measurement (0.3s) to compute current throughput.
    Returns speed in KB/s and cumulative totals in bytes.
    """
    import psutil

    net1 = psutil.net_io_counters()
    await asyncio.sleep(0.3)
    net2 = psutil.net_io_counters()

    # Calculate bytes per second, then convert to KB/s
    elapsed = 0.3
    dl_bytes_per_sec = (net2.bytes_recv - net1.bytes_recv) / elapsed
    ul_bytes_per_sec = (net2.bytes_sent - net1.bytes_sent) / elapsed

    dl_kbps = dl_bytes_per_sec / 1024
    ul_kbps = ul_bytes_per_sec / 1024

    return {
        "success": True,
        "data": {
            "downloadSpeed": round(dl_kbps, 1),
            "uploadSpeed": round(ul_kbps, 1),
            "totalDownload": net2.bytes_recv,
            "totalUpload": net2.bytes_sent,
            "countryCode": "??",
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
    if protocol_manager.get_protocol(resolved_proto) is None:
        resolved_proto = "v2ray"  # custom V2Ray inbound tags

    core_status = await db.get_core_status(resolved_proto)
    is_running = core_status.get("status") == "running"
    # Latency is measured by the client (round trip to the server); the server
    # only reports whether the protocol behind this config is up.
    return {
        "success": True,
        "data": {
            "config_id": config_id,
            "latency": 0,
            "reachable": is_running,
            "protocol_status": "running" if is_running else "stopped",
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
    for proto_id, enabled in client_protocols.items():
        if not enabled:
            continue
        is_running = core_map.get(proto_id, {}).get("status") == "running"
        results.append({
            "config_id": f"{proto_id}-1",
            "protocol": proto_id,
            "latency": 0,  # measured client-side
            "reachable": is_running,
        })
    
    return {"success": True, "data": results}



