import json
import asyncio
from datetime import datetime, timezone
from typing import Dict, Set
from fastapi import WebSocket

class WebSocketManager:
    """
    Manages real-time telemetry connections across all frontend dashboard clients.
    Broadcasts operational events, threat feed updates, and module-specific metrics.
    """
    def __init__(self):
        # Maps module or 'global' to active WebSockets
        self.active_connections: Set[WebSocket] = set()
        self.event_history: list[dict] = []
        self._max_history = 100

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "message": "Connected to AegisForge Telemetry Bus",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "history_count": len(self.event_history)
        })

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast_event(
        self,
        module: str,
        event_type: str,
        severity: str,
        message: str,
        data: dict = None
    ):
        """
        Broadcasts an operational or security event to all connected clients.
        severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
        """
        payload = {
            "module": module,
            "event_type": event_type,
            "severity": severity.upper(),
            "message": message,
            "data": data or {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Keep ring buffer of recent events for new clients
        self.event_history.append(payload)
        if len(self.event_history) > self._max_history:
            self.event_history.pop(0)

        # Broadcast concurrently to active sockets
        dead_connections = set()
        for connection in list(self.active_connections):
            try:
                await connection.send_json(payload)
            except Exception:
                dead_connections.add(connection)

        for dead in dead_connections:
            self.active_connections.discard(dead)

    def get_recent_events(self, limit: int = 50) -> list[dict]:
        return self.event_history[-limit:]

    async def start_heartbeat(self, interval_seconds: int = 30):
        """Periodically broadcasts keepalive pings to connected sockets and cleans stale connections."""
        while True:
            try:
                await asyncio.sleep(interval_seconds)
                if self.active_connections:
                    dead = set()
                    for conn in list(self.active_connections):
                        try:
                            await conn.send_json({
                                "type": "HEARTBEAT",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "active_clients": len(self.active_connections)
                            })
                        except Exception:
                            dead.add(conn)
                    for d in dead:
                        self.active_connections.discard(d)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

ws_manager = WebSocketManager()
