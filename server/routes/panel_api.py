"""
CandyConnect Server - Panel API Router
Defines all endpoints for the web management panel.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Body, BackgroundTasks
from pydantic import BaseModel
import time
import logging
from starlette.concurrency import run_in_threadpool

import database as db
import auth
from config import SUPPORTED_PROTOCOLS, PANEL_PORT
from system_info import get_server_info
from protocols.manager import protocol_manager
import tunnels as tunnels_mod

router = APIRouter(tags=["panel"])
logger = logging.getLogger("candyconnect")

# ── Auth ──

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/auth/login")
async def login(req: LoginRequest):
    if await db.verify_admin(req.username, req.password):
        token = auth.create_admin_token(req.username)
        return {"success": True, "message": "Login successful", "token": token}
    raise HTTPException(status_code=401, detail="Invalid username or password")

# ── Dashboard ──

@router.get("/dashboard")
async def get_dashboard(limit: int = 10, user=Depends(auth.require_admin)):
    server_info = await get_server_info()
    
    # Enrich with database configuration
    panel_cfg = await db.get_core_config("candyconnect") or {}
    server_info["domain"] = panel_cfg.get("panel_domain") or ""
    
    # If a manual server_ip is set in database, prioritize it
    if panel_cfg.get("server_ip"):
        server_info["ip"] = panel_cfg["server_ip"]

    vpn_cores = await protocol_manager.get_all_cores_info()
    logs = await db.get_logs(limit)
    
    active_connections = sum(c.get("active_connections", 0) for c in vpn_cores)
    running_cores = sum(1 for c in vpn_cores if c.get("status") == "running")
    
    clients = await db.get_all_clients()
    online_count = sum(1 for c in clients if c.get("is_online"))

    return {
        "success": True,
        "message": "Dashboard data fetched",
        "data": {
            "server": server_info,
            "vpn_cores": vpn_cores,
            "logs": logs,
            "stats": {
                "total_clients": len(clients),
                "online_clients": online_count,
                "total_traffic": await db.get_total_traffic(),
                "active_connections": active_connections,
                "running_cores": running_cores,
                "total_cores": len(vpn_cores),
            }
        }
    }

# ── Clients ──

class CreateClientRequest(BaseModel):
    username: str
    password: str
    comment: str = ""
    enabled: bool = True
    group: Optional[str] = None
    traffic_limit: dict
    time_limit: dict
    protocols: dict

class UpdateClientRequest(BaseModel):
    password: Optional[str] = None
    comment: Optional[str] = None
    enabled: Optional[bool] = None
    group: Optional[str] = None
    traffic_limit: Optional[dict] = None
    time_limit: Optional[dict] = None
    protocols: Optional[dict] = None

@router.get("/clients")
async def list_clients(user=Depends(auth.require_admin)):
    clients = await db.get_all_clients()
    return {"success": True, "message": "Clients fetched", "data": clients}

@router.get("/clients/{id}")
async def get_client(id: str, user=Depends(auth.require_admin)):
    client = await db.get_client(id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"success": True, "message": "Client fetched", "data": client}

@router.post("/clients")
async def create_client(req: CreateClientRequest, user=Depends(auth.require_admin)):
    try:
        # Create in DB
        client = await db.create_client(req.model_dump())
        
        # Add to protocol backends
        pdata = await protocol_manager.sync_client(client)
        
        # Update DB with protocol-specific data (keys, etc)
        await db.update_client(client["id"], {"protocol_data": pdata}, log=False)
        client["protocol_data"] = pdata
        
        return {"success": True, "message": "Client created", "data": client}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/clients/{id}")
async def update_client(id: str, req: UpdateClientRequest, user=Depends(auth.require_admin)):
    existing = await db.get_client(id)
    if not existing:
        raise HTTPException(status_code=404, detail="Client not found")
    
    try:
        updated = await db.update_client(id, req.model_dump(exclude_unset=True))
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Update protocol backends (adds, re-applies password, removes disabled protocols).
    # The client record is already saved, so a backend error is reported as a warning.
    try:
        pdata = await protocol_manager.sync_client(updated)
        await db.update_client(id, {"protocol_data": pdata}, log=False)
        updated["protocol_data"] = pdata
    except Exception as e:
        logger.exception("Backend sync failed")
        return {"success": True, "message": f"Client saved, but applying it to the VPN services failed: {e}", "data": updated}
    return {"success": True, "message": "Client updated", "data": updated}

@router.delete("/clients/{id}")
async def delete_client(id: str, user=Depends(auth.require_admin)):
    client = await db.get_client(id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    await protocol_manager.remove_client_from_protocols(client)
    await db.delete_client(id)
    return {"success": True, "message": "Client deleted"}

# ── Logs ──

@router.get("/logs")
async def get_logs(limit: int = 100, source: Optional[str] = None, user=Depends(auth.require_admin)):
    logs = await db.get_logs(limit, source)
    return {"success": True, "message": "Logs fetched", "data": logs}

# ── Tunnels (Backhaul relays) ──

class TunnelRequest(BaseModel):
    ip: str
    port: int = 22                     # SSH port of the relay server
    name: str
    username: str = "root"
    password: Optional[str] = None
    tunnel_type: str = "backhaul"
    transport: str = "tcp"             # tcp, tcpmux, ws, wsmux
    tunnel_port: int = 3080            # Backhaul port on the relay
    ports: Optional[str] = None        # e.g. "443, 8080" (empty = all VPN TCP ports)
    accept_udp: bool = False

@router.get("/tunnels")
async def get_tunnels(user=Depends(auth.require_admin)):
    tunnels = await db.get_tunnels()
    for t in tunnels:
        t["local_running"] = tunnels_mod.local_running(t["id"])
    return {"success": True, "data": tunnels}

@router.post("/tunnels")
async def add_tunnel(req: TunnelRequest, tasks: BackgroundTasks, user=Depends(auth.require_admin)):
    if req.tunnel_type != "backhaul":
        raise HTTPException(status_code=400, detail="Only the 'backhaul' tunnel type is supported")
    if req.transport not in tunnels_mod.TRANSPORTS:
        raise HTTPException(status_code=400, detail=f"Transport must be one of {', '.join(tunnels_mod.TRANSPORTS)}")
    ports = tunnels_mod.parse_ports(req.ports) if req.ports else await tunnels_mod.default_ports()
    if not ports:
        raise HTTPException(status_code=400, detail="No ports to forward")
    if str(req.tunnel_port) in [p.split("=")[0].split(":")[-1] for p in ports]:
        raise HTTPException(status_code=400, detail="Tunnel port must differ from the forwarded ports")

    tunnel = await db.add_tunnel(req.ip.strip(), req.port, req.name.strip(), req.username, req.password or None,
                                 req.tunnel_type, req.transport, req.tunnel_port, ports, req.accept_udp)
    # Script for manual installation on the relay (shown when no SSH password is given)
    install_cmd = tunnels_mod.remote_install_script(tunnel)
    if req.password:
        tasks.add_task(tunnels_mod.install_tunnel, tunnel["id"])
    else:
        # Start our side now; the relay is installed manually with the script
        await db.update_tunnel(tunnel["id"], {"status": "installed"})
        tasks.add_task(tunnels_mod.start_local, {**tunnel, "status": "installed"})

    public = {k: v for k, v in tunnel.items() if k not in ("ssh_password", "token")}
    return {
        "success": True,
        "message": "Tunnel added. Installation started via SSH" if req.password
                   else "Tunnel added. Run the install script on the relay server as root",
        "data": public,
        "install_command": install_cmd,
    }

@router.post("/tunnels/{id}/reinstall")
async def reinstall_tunnel(id: str, tasks: BackgroundTasks, user=Depends(auth.require_admin)):
    t = await db.get_tunnel(id)
    if not t:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    tasks.add_task(tunnels_mod.install_tunnel, id)
    return {"success": True, "message": "Reinstall started"}

@router.delete("/tunnels/{id}")
async def delete_tunnel(id: str, user=Depends(auth.require_admin)):
    if not await db.get_tunnel(id):
        raise HTTPException(status_code=404, detail="Tunnel not found")
    await tunnels_mod.remove_tunnel(id)
    return {"success": True, "message": "Tunnel deleted"}

# ── VPN Cores ──

@router.get("/cores")
async def get_cores(user=Depends(auth.require_admin)):
    cores = await protocol_manager.get_all_cores_info()
    return {"success": True, "message": "Cores fetched", "data": cores}

@router.post("/cores/{id}/start")
async def start_core(id: str, user=Depends(auth.require_admin)):
    try:
        success = await protocol_manager.start_protocol(id, remember=True)
        if success:
            return {"success": True, "message": f"{id.upper()} started"}
        raise HTTPException(status_code=500, detail=f"Failed to start {id}. Check the logs for details.")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error starting {id}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cores/{id}/stop")
async def stop_core(id: str, user=Depends(auth.require_admin)):
    try:
        success = await protocol_manager.stop_protocol(id, remember=True)
        if success:
            return {"success": True, "message": f"{id.upper()} stopped"}
        raise HTTPException(status_code=500, detail=f"Failed to stop {id}. Check the logs for details.")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error stopping {id}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cores/{id}/restart")
async def restart_core(id: str, user=Depends(auth.require_admin)):
    try:
        success = await protocol_manager.restart_protocol(id)
        if success:
            return {"success": True, "message": f"{id.upper()} restarted"}
        raise HTTPException(status_code=500, detail=f"Failed to restart {id}. Check the logs for details.")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error restarting {id}")
        raise HTTPException(status_code=500, detail=str(e))

# ── Core Configs ──

@router.get("/configs")
async def get_configs(user=Depends(auth.require_admin)):
    configs = await db.get_core_configs()
    return {"success": True, "message": "Configs fetched", "data": configs}

@router.put("/configs/{section}")
async def update_config(section: str, data: dict = Body(...), user=Depends(auth.require_admin)):
    if section == "v2ray" and "config_json" in data:
        import json
        try:
            raw = data["config_json"]
            json.loads(raw) if isinstance(raw, str) else None
            if not isinstance(raw, str):
                data["config_json"] = json.dumps(raw, indent=2)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid V2Ray config JSON: {e}")
    await db.update_core_config(section, data)
    if section == "v2ray":
        # A pasted config usually has no users: put the clients back in
        await protocol_manager.get_protocol("v2ray").sync_clients(await db.get_all_clients())
    return {"success": True, "message": f"Config for {section} updated"}

# ── Panel ──

@router.get("/panel")
async def get_panel_info(user=Depends(auth.require_admin)):
    config = await db.get_panel_config()
    server = await get_server_info()
    admin_user = await db.get_admin_username()
    
    return {
        "success": True,
        "message": "Panel info fetched",
        "data": {
            "config": config,
            "server": server,
            "admin_username": admin_user,
            "total_clients": await db.get_client_count(),
            "total_cores": len(SUPPORTED_PROTOCOLS)
        }
    }

@router.put("/panel")
async def update_panel(data: dict = Body(...), user=Depends(auth.require_admin)):
    try:
        needs_restart = await db.update_panel_config(data)
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    if "panel_port" in data:
        import asyncio
        port = int(data["panel_port"])
        proc = await asyncio.create_subprocess_shell(
            f"iptables -C INPUT -p tcp --dport {port} -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport {port} -j ACCEPT; "
            f"command -v ufw >/dev/null && ufw status | grep -q 'Status: active' && ufw allow {port}/tcp >/dev/null; true",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.wait()
    msg = "Panel configuration saved. Restart the panel to apply it" if needs_restart else "Panel configuration updated"
    return {"success": True, "message": msg, "restart_required": needs_restart}

class PwdRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

@router.put("/panel/password")
async def change_panel_password(req: PwdRequest, user=Depends(auth.require_admin)):
    if req.new_password != req.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    
    success = await db.change_admin_password(req.current_password, req.new_password)
    if success:
        return {"success": True, "message": "Password changed successfully"}
    raise HTTPException(status_code=400, detail="Incorrect current password")

@router.post("/panel/restart")
async def restart_panel(user=Depends(auth.require_admin)):
    # In Docker, we can just exit and let restart: unless-stopped handle it
    # or just return success and let the user restart the container
    import os, signal
    # Graceful shutdown after returning response
    def shutdown():
        import time
        time.sleep(1)
        os.kill(os.getpid(), signal.SIGTERM)
    
    import threading
    threading.Thread(target=shutdown).start()
    
    return {"success": True, "message": "Panel restarting..."}
