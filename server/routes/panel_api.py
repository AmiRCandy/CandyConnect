"""
CandyConnect Server - Panel API Router
Defines all endpoints for the web management panel.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Body, BackgroundTasks
from pydantic import BaseModel
import paramiko
import time

from fastapi.responses import PlainTextResponse
import base64


import database as db
import auth
from config import SUPPORTED_PROTOCOLS
from system_info import get_server_info
from protocols.manager import protocol_manager

router = APIRouter(tags=["panel"])

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
        pdata = await protocol_manager.add_client_to_protocols(
            client["username"], client, client["protocols"]
        )
        
        # Update DB with protocol-specific data (keys, etc)
        await db.update_client(client["id"], {"protocol_data": pdata})
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
        
        # Update protocol backends
        pdata = await protocol_manager.add_client_to_protocols(
            updated["username"], updated, updated["protocols"], 
            existing_data=updated.get("protocol_data")
        )
        await db.update_client(id, {"protocol_data": pdata})
        updated["protocol_data"] = pdata
        
        return {"success": True, "message": "Client updated", "data": updated}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/clients/{id}/openvpn-config")
async def download_openvpn_config(id: str, user=Depends(auth.require_admin)):
    client = await db.get_client(id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    panel_cfg = await db.get_core_config("candyconnect") or {}
    server_ip = panel_cfg.get("server_ip") or (await get_server_info()).get("ip", "")
    p_mgr = protocol_manager.get_protocol("openvpn")
    pdata_ovpn = (client.get("protocol_data", {}) or {}).get("openvpn", {})
    cfg = await p_mgr.get_client_config(client["username"], server_ip, pdata_ovpn)
    ovpn = cfg.get("ovpn_config") if isinstance(cfg, dict) else None
    if not ovpn:
        raise HTTPException(status_code=404, detail="OpenVPN config not found")
    return PlainTextResponse(
        content=ovpn,
        headers={"Content-Disposition": f'attachment; filename="{client["username"]}.ovpn"'},
        media_type="application/x-openvpn-profile",
    )


@router.post("/clients/{id}/wireguard-qr")
async def generate_wireguard_qr(id: str, user=Depends(auth.require_admin)):
    client = await db.get_client(id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    panel_cfg = await db.get_core_config("candyconnect") or {}
    server_ip = panel_cfg.get("server_ip") or (await get_server_info()).get("ip", "")

    pdata = (client.get("protocol_data", {}) or {}).get("wireguard", {})
    wg = protocol_manager.get_protocol("wireguard")
    pdata = await wg.ensure_client_credentials(client["username"], pdata)
    all_pd = client.get("protocol_data", {}) or {}
    all_pd["wireguard"] = pdata
    await db.update_client(client["id"], {"protocol_data": all_pd})

    cfg = await wg.get_client_config(client["username"], server_ip, pdata)
    wg_config = (cfg or {}).get("wg_config", "")
    if not wg_config:
        raise HTTPException(status_code=500, detail="Failed to generate WireGuard config")

    qr_data_url = ""
    try:
        import qrcode
        from io import BytesIO
        img = qrcode.make(wg_config)
        buf = BytesIO()
        img.save(buf, format="PNG")
        qr_data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        qr_data_url = ""

    return {
        "success": True,
        "message": "WireGuard config generated",
        "data": {
            "wg_config": wg_config,
            "qr_data_url": qr_data_url,
            "status": "ready",
        },
    }


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

# ── Tunnels ──

class TunnelRequest(BaseModel):
    ip: str
    port: int
    name: str
    username: str = "root"
    password: Optional[str] = None
    tunnel_type: str = "backhaul"

@router.get("/tunnels")
async def get_tunnels(user=Depends(auth.require_admin)):
    tunnels = await db.get_tunnels()
    return {"success": True, "data": tunnels}

async def background_install_tunnel(tunnel_id: str, ip: str, port: int, username: str, password: str, cmd: str):
    await db.update_tunnel_status(tunnel_id, "installing")
    await db.add_log("INFO", "tunnel", f"Starting SSH installation for tunnel {tunnel_id} on {ip}...")

    def _sync_ssh():
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=username, password=password, timeout=15)
            # Execute command
            stdin, stdout, stderr = client.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()
            out_msg = stdout.read().decode().strip()
            err_msg = stderr.read().decode().strip()
            client.close()
            return exit_status == 0, out_msg, err_msg
        except Exception as e:
            return False, "", str(e)

    success, out, err = await auth.run_in_threadpool(_sync_ssh)
    
    if success:
        await db.update_tunnel_status(tunnel_id, "installed")
        await db.add_log("INFO", "tunnel", f"Tunnel {tunnel_id} installed successfully.")
    else:
        await db.update_tunnel_status(tunnel_id, "failed")
        await db.add_log("ERROR", "tunnel", f"Tunnel {tunnel_id} installation failed: {err}")

@router.post("/tunnels")
async def add_tunnel(req: TunnelRequest, tasks: BackgroundTasks, user=Depends(auth.require_admin)):
    tunnel = await db.add_tunnel(req.ip, req.port, req.name, req.username, req.password, req.tunnel_type)
    
    # Generate install command
    # Use current server IP as master
    server_info = await get_server_info()
    master_ip = server_info.get("ip", "YOUR_SERVER_IP")
    
    # Generates a command to run on the remote tunnel server
    install_cmd = f"curl -fsSL https://get.candyconnect.io/tunnel | sudo bash -s -- --master {master_ip}:8443 --secret {tunnel['id']} --type {req.tunnel_type}"
    
    if req.ip and req.password:
        tasks.add_task(background_install_tunnel, tunnel['id'], req.ip, req.port, req.username, req.password, install_cmd)
    
    return {
        "success": True, 
        "message": "Tunnel added. installation started via SSH" if req.password else "Tunnel added. password missing for SSH install", 
        "data": tunnel, 
        "install_command": install_cmd
    }

@router.delete("/tunnels/{id}")
async def delete_tunnel(id: str, user=Depends(auth.require_admin)):
    await db.delete_tunnel(id)
    return {"success": True, "message": "Tunnel deleted"}

# ── VPN Cores ──

@router.get("/cores")
async def get_cores(user=Depends(auth.require_admin)):
    cores = await protocol_manager.get_all_cores_info()
    return {"success": True, "message": "Cores fetched", "data": cores}

@router.post("/cores/{id}/start")
async def start_core(id: str, user=Depends(auth.require_admin)):
    try:
        success = await protocol_manager.start_protocol(id)
        if success:
            return {"success": True, "message": f"{id.upper()} started"}
        raise HTTPException(status_code=500, detail=f"Failed to start {id}")
    except Exception as e:
        logger.exception(f"Error starting {id}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cores/{id}/stop")
async def stop_core(id: str, user=Depends(auth.require_admin)):
    try:
        success = await protocol_manager.stop_protocol(id)
        if success:
            return {"success": True, "message": f"{id.upper()} stopped"}
        raise HTTPException(status_code=500, detail=f"Failed to stop {id}")
    except Exception as e:
        logger.exception(f"Error stopping {id}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cores/{id}/restart")
async def restart_core(id: str, user=Depends(auth.require_admin)):
    try:
        success = await protocol_manager.restart_protocol(id)
        if success:
            return {"success": True, "message": f"{id.upper()} restarted"}
        raise HTTPException(status_code=500, detail=f"Failed to restart {id}")
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
    await db.update_core_config(section, data)
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
    await db.update_panel_config(data)
    return {"success": True, "message": "Panel configuration updated"}

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
