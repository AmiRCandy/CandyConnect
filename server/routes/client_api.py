"""
CandyConnect Server - Client API Router
Endpoints used by the VPN client applications.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import database as db
import auth
from protocols.manager import protocol_manager

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
    return {
        "success": True, 
        "message": "Login successful", 
        "token": token,
        "username": client["username"]
    }

@router.get("/account")
async def get_account(payload=Depends(auth.require_client)):
    client_id = payload.get("client_id")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    return {
        "success": True,
        "data": {
            "username": client["username"],
            "traffic_used": client["traffic_used"],
            "traffic_limit": client["traffic_limit"],
            "expires_at": client["expires_at"],
            "enabled": client["enabled"]
        }
    }

@router.get("/protocols")
async def get_protocols(payload=Depends(auth.require_client)):
    client_id = payload.get("client_id")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    return {
        "success": True,
        "data": client["protocols"]
    }

@router.get("/configs")
async def get_all_configs(payload=Depends(auth.require_client)):
    client_id = payload.get("client_id")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    server_ip = await _get_server_ip()
    configs = await protocol_manager.get_client_configs(
        client["username"], server_ip, client["protocols"], client.get("protocol_data", {})
    )
    
    return {"success": True, "data": configs}

@router.get("/configs/{protocol}")
async def get_protocol_config(protocol: str, payload=Depends(auth.require_client)):
    client_id = payload.get("client_id")
    client = await db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    if not client["protocols"].get(protocol):
        raise HTTPException(status_code=403, detail=f"Protocol {protocol} not allowed for this account")
    
    server_ip = await _get_server_ip()
    p_mgr = protocol_manager.get_protocol(protocol)
    if not p_mgr:
        raise HTTPException(status_code=404, detail="Protocol manager not found")
        
    pdata = (client.get("protocol_data", {}) or {}).get(protocol, {})
    config = await p_mgr.get_client_config(client["username"], server_ip, pdata)
    
    return {"success": True, "data": config}

class TrafficReport(BaseModel):
    bytes_sent: int
    bytes_received: int
    protocol: str

@router.post("/traffic")
async def report_traffic(req: TrafficReport, payload=Depends(auth.require_client)):
    client_id = payload.get("client_id")
    total_bytes = req.bytes_sent + req.bytes_received
    
    # Update client usage in DB (id, protocol, bytes)
    await db.update_client_traffic(client_id, req.protocol, total_bytes)
    return {"success": True, "message": "Traffic reported"}

class ConnectionEvent(BaseModel):
    protocol: str
    event: str  # "connect" or "disconnect"
    ip: str

@router.post("/connect")
async def report_connection(req: ConnectionEvent, payload=Depends(auth.require_client)):
    client_id = payload.get("client_id")
    username = payload.get("username")
    
    await db.add_connection_history(client_id, req.protocol, req.event, req.ip)
    return {"success": True, "message": f"Connection {req.event} logged"}

@router.get("/server")
async def get_server_info():
    ip = await _get_server_ip()
    return {
        "success": True, 
        "data": {
            "ip": ip,
            "version": "1.4.2",
            "name": "CandyConnect VPN Server"
        }
    }

async def _get_server_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

@router.get("/ping")
async def ping():
    return {"success": True, "message": "client pong"}
