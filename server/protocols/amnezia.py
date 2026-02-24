"""CandyConnect - Amnezia Protocol Manager."""
import time
from protocols.base import BaseProtocol
from database import get_core_status, set_core_status, add_log


class AmneziaProtocol(BaseProtocol):
    PROTOCOL_ID = "amnezia"
    PROTOCOL_NAME = "Amnezia"
    DEFAULT_PORT = 51830

    async def install(self) -> bool:
        try:
            await add_log("INFO", self.PROTOCOL_NAME, "Installing Amnezia dependencies...")
            await self._apt_install("amneziawg-tools")
            return True
        except Exception as e:
            await add_log("ERROR", self.PROTOCOL_NAME, f"Installation error: {e}")
            return False

    async def start(self) -> bool:
        status = await get_core_status(self.PROTOCOL_ID)
        await set_core_status(self.PROTOCOL_ID, {
            "status": "running",
            "pid": status.get("pid"),
            "started_at": int(time.time()),
            "version": status.get("version", ""),
        })
        await add_log("INFO", self.PROTOCOL_NAME, "Amnezia marked as running")
        return True

    async def stop(self) -> bool:
        status = await get_core_status(self.PROTOCOL_ID)
        await set_core_status(self.PROTOCOL_ID, {
            "status": "stopped",
            "pid": None,
            "started_at": None,
            "version": status.get("version", ""),
        })
        await add_log("INFO", self.PROTOCOL_NAME, "Amnezia stopped")
        return True

    async def is_running(self) -> bool:
        status = await get_core_status(self.PROTOCOL_ID)
        return status.get("status") == "running"

    async def add_client(self, username: str, client_data: dict) -> dict:
        return {"username": username, "status": "ready"}

    async def remove_client(self, username: str, protocol_data: dict):
        return None

    async def get_client_config(self, username: str, server_ip: str, protocol_data: dict, config_id: str = None) -> dict:
        return {
            "type": "amnezia",
            "server": server_ip,
            "port": self.DEFAULT_PORT,
            "username": username,
        }
