"""
CandyConnect Server - Panel API Router (minimal stub)
Defines the router object to prevent import-time errors and provide basic endpoints.
"""
from fastapi import APIRouter

router = APIRouter(tags=["panel"])

@router.get("/ping")
async def ping():
    return {"success": True, "message": "panel pong"}
