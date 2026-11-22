import time
from collections import defaultdict
from typing import Dict, List
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from backend.app.core.metrics import metrics

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    In-memory sliding-window rate limiter middleware for AegisForge API.
    Enforces a strict upper threshold on requests per minute per client IP.
    """
    def __init__(self, app, max_requests_per_minute: int = 120):
        super().__init__(app)
        self.max_requests = max_requests_per_minute
        self.requests_log: Dict[str, List[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Exclude WebSockets and health checks from rate limiting
        path = request.url.path
        if path.startswith("/ws") or path == "/api/v1/health":
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        window_start = now - 60.0

        # Filter out timestamps older than 60 seconds
        timestamps = [t for t in self.requests_log[client_ip] if t > window_start]

        if len(timestamps) >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": f"Rate limit of {self.max_requests} requests/minute exceeded. Please cool down.",
                    "retry_after_seconds": 60
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(self.max_requests),
                    "X-RateLimit-Remaining": "0"
                }
            )

        timestamps.append(now)
        self.requests_log[client_ip] = timestamps
        metrics.record_request()

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self.max_requests - len(timestamps)))
        return response
