"""
CandyConnect Server - Main Application
FastAPI backend serving both web panel and client APIs.
"""
import asyncio, os, sys, logging, time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError

from config import PANEL_PORT, PANEL_PATH, DATA_DIR, CORE_DIR, BACKUP_DIR, LOG_DIR
from database import init_db, close_redis, add_log
from protocols.manager import protocol_manager

# Global flag for database availability
_db_ready = False

# ── Logging ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("candyconnect")


# ── Background Tasks ──

async def traffic_updater():
    """Periodically update traffic cache."""
    while True:
        try:
            if _db_ready:
                await protocol_manager.update_traffic_cache()
        except Exception as e:
            logger.warning(f"Traffic updater error: {e}")
        await asyncio.sleep(30)


async def status_checker():
    """Periodically verify core statuses match reality and mark stale clients offline."""
    while True:
        try:
            if _db_ready:
                cores = await protocol_manager.get_all_cores_info()
                # Status verification happens inside get_all_cores_info

                # Mark clients offline if they haven't heartbeated in 5 minutes
                from database import mark_offline_stale_clients
                marked = await mark_offline_stale_clients(timeout_seconds=300)
                if marked > 0:
                    logger.info(f"Marked {marked} stale client(s) as offline")

                # Suspend expired / over-quota clients on the VPN backends
                await protocol_manager.enforce_limits()
        except Exception as e:
            logger.warning(f"Status checker error: {e}")
        await asyncio.sleep(60)


# ── App Lifecycle ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db_ready

    # Startup
    for d in [DATA_DIR, CORE_DIR, BACKUP_DIR, LOG_DIR]:
        os.makedirs(d, exist_ok=True)

    # Initialize database (graceful if Redis is unavailable)
    try:
        await init_db()
        _db_ready = True
    except Exception as e:
        logger.warning(f"init_db failed: {e}. Starting without Redis (degraded mode).")
        _db_ready = False

    if _db_ready:
        try:
            await add_log("INFO", "System", "CandyConnect server started")
            # Auto start protocols, then relay tunnels
            async def _boot():
                await protocol_manager.auto_start_protocols()
                import tunnels
                await tunnels.start_all()
            asyncio.create_task(_boot())
        except Exception:
            pass
    logger.info("CandyConnect server started")

    # Start background tasks (they check _db_ready before doing work)
    tasks = [
        asyncio.create_task(traffic_updater()),
        asyncio.create_task(status_checker()),
    ]

    yield

    # Shutdown
    for t in tasks:
        t.cancel()
    if _db_ready:
        try:
            await add_log("INFO", "System", "CandyConnect server shutting down")
        except Exception:
            pass
        await close_redis()


# ── FastAPI App ──

app = FastAPI(
    title="CandyConnect Server",
    version="1.4.2",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Return all errors in {success, message} format for frontend compatibility."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "message": str(exc.detail)},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return validation errors in the same {success, message} format."""
    parts = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", []) if x != "body")
        parts.append(f"{loc}: {err.get('msg', 'invalid')}" if loc else err.get("msg", "invalid"))
    return JSONResponse(
        status_code=422,
        content={"success": False, "message": "; ".join(parts) or "Invalid request"},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": "Internal server error"},
    )

# ── Register API Routers ──

from routes.panel_api import router as panel_router
from routes.client_api import router as client_router

app.include_router(panel_router, prefix="/api")
app.include_router(client_router, prefix="/client-api")

# ── Serve Web Panel Static Files ──

PANEL_DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web-panel", "dist")
PANEL_DIST = os.path.normpath(PANEL_DIST)

# Panel URL path from CC_PANEL_PATH (e.g. "/candyconnect"); the panel is built with
# relative asset URLs so it works under any path.
PANEL_URL = "/" + PANEL_PATH.strip().strip("/") if PANEL_PATH.strip().strip("/") else "/candyconnect"


@app.get(PANEL_URL, include_in_schema=False)
async def panel_root_redirect():
    # Trailing slash is required so "./assets/..." resolves under the panel path
    return RedirectResponse(url=PANEL_URL + "/")


@app.get(PANEL_URL + "/{rest_of_path:path}", include_in_schema=False)
async def serve_panel(rest_of_path: str = ""):
    if not os.path.isdir(PANEL_DIST):
        return JSONResponse(
            status_code=503,
            content={"error": "Panel not built. Run: cd web-panel && npm run build"},
        )
    # Serve real files (assets, favicon, ...)
    if rest_of_path:
        file_path = os.path.normpath(os.path.join(PANEL_DIST, rest_of_path))
        # Prevent path traversal
        if file_path.startswith(PANEL_DIST + os.sep) and os.path.isfile(file_path):
            return FileResponse(file_path)
        if rest_of_path.startswith("assets/"):
            return JSONResponse(status_code=404, content={"success": False, "message": "Not found"})

    # Otherwise return index.html for SPA routing
    index = os.path.join(PANEL_DIST, "index.html")
    if os.path.exists(index):
        return FileResponse(index, headers={"Cache-Control": "no-cache"})
    return JSONResponse(
        status_code=503,
        content={"error": "Panel not built. Run: cd web-panel && npm run build"},
    )


@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url=PANEL_URL + "/")


# ── Health Check ──

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.4.2", "timestamp": int(time.time())}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PANEL_PORT,
        log_level="info",
        reload=False,
    )
