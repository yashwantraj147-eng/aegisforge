import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from backend.app.core.config import settings
from backend.app.core.ws_manager import ws_manager
from backend.app.core.safety_guard import SafetyViolationException
from backend.app.core.rate_limiter import RateLimitMiddleware
from backend.app.core.database import db
from backend.app.core.metrics import metrics
from backend.app.core.logger import get_logger
from backend.app.models.schemas import HealthResponse

logger = get_logger("main")

from backend.app.api.routes_recon import router as recon_router
from backend.app.api.routes_netarena import router as netarena_router
from backend.app.api.routes_exploit import router as exploit_router
from backend.app.api.routes_fuzz_re import router as fuzz_router
from backend.app.api.routes_maltriage import router as maltriage_router
from backend.app.api.routes_scenarios import router as scenarios_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize persistent SQLite DB & broadcast boot event
    await db.init_db()
    heartbeat_task = asyncio.create_task(ws_manager.start_heartbeat(30))
    logger.info("AegisForge Cyber Range backend started in %s mode.", settings.MODE.value)
    await ws_manager.broadcast_event(
        module="SYSTEM",
        event_type="SYSTEM_BOOT",
        severity="INFO",
        message=f"AegisForge Cyber Range backend started in {settings.MODE.value} mode.",
        data={"version": settings.VERSION, "mode": settings.MODE.value}
    )
    yield
    # Shutdown
    heartbeat_task.cancel()
    logger.info("AegisForge backend shutting down gracefully.")
    await ws_manager.broadcast_event(
        module="SYSTEM",
        event_type="SYSTEM_SHUTDOWN",
        severity="INFO",
        message="AegisForge backend shutting down gracefully."
    )

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Industry-Grade Purple-Team Cyber Range & Vulnerability Workbench API",
    lifespan=lifespan
)

# CORS Middleware (scoped to local development and sandbox origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Rate Limiter Middleware
app.add_middleware(
    RateLimitMiddleware,
    max_requests_per_minute=settings.RATE_LIMIT_PER_MINUTE
)

# Global Safety Guard Exception Handler
@app.exception_handler(SafetyViolationException)
async def safety_violation_handler(request: Request, exc: SafetyViolationException):
    return JSONResponse(
        status_code=400,
        content={
            "error": "SAFETY_GUARD_VIOLATION",
            "message": exc.message,
            "target": exc.target,
            "policy": "RFC1918 / Localhost sandbox target restriction strictly enforced."
        }
    )

# WebSocket Telemetry Bus
@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep socket alive and accept ping/query messages from frontend
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# Health & Status Endpoint
@app.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
def health_check():
    return HealthResponse(
        status="ONLINE",
        version=settings.VERSION,
        mode=settings.MODE.value,
        safety_guard_active=settings.ENFORCE_SAFETY_GUARD,
        active_websockets=len(ws_manager.active_connections),
        timestamp=datetime.now(timezone.utc).isoformat()
    )

# Telemetry Metrics Endpoints
@app.get("/api/v1/metrics", tags=["Telemetry & Metrics"])
def get_metrics_summary():
    """Returns JSON operational metrics summary for telemetry dashboards."""
    return metrics.get_summary()

@app.get("/metrics", response_class=PlainTextResponse, tags=["Telemetry & Metrics"])
def get_prometheus_metrics():
    """Returns Prometheus standard exposition text format metrics."""
    return metrics.get_prometheus_format()

# Include Core Engine Routers
app.include_router(recon_router, prefix=settings.API_V1_STR)
app.include_router(netarena_router, prefix=settings.API_V1_STR)
app.include_router(exploit_router, prefix=settings.API_V1_STR)
app.include_router(fuzz_router, prefix=settings.API_V1_STR)
app.include_router(maltriage_router, prefix=settings.API_V1_STR)
app.include_router(scenarios_router, prefix=settings.API_V1_STR)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
