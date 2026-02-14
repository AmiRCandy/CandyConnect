"""
CandyConnect Server - Client API Router (minimal stub)
"""
from fastapi import APIRouter

router = APIRouter(tags=["client"])

@router.get("/ping")
async def ping():
    return {"success": True, "message": "client pong"}
