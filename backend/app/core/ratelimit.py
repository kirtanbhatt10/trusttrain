"""In-process sliding-window rate limiter.

Suitable for a single API instance. Multi-instance deployments should enforce
limits at the reverse proxy as well (see docs/DEPLOYMENT.md).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, general_limit: int, auth_limit: int) -> None:
        super().__init__(app)
        self.general = SlidingWindowLimiter(general_limit)
        self.auth = SlidingWindowLimiter(auth_limit)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client = request.client.host if request.client else "unknown"
        limiter = self.auth if request.url.path.startswith("/api/auth/") else self.general
        if not limiter.allow(client):
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429, headers={"Retry-After": "60"})
        return await call_next(request)
