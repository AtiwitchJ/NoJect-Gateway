"""
FastAPI & Starlette Middleware Integration for NoJect
"""

from typing import Callable, Optional, List
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from noject.guard import NoJectGuard

class NoJectFastAPIMiddleware(BaseHTTPMiddleware):
    """
    Automatic In-Process WAF and AI Security Shield for FastAPI applications.
    """

    def __init__(self, app, guard: Optional[NoJectGuard] = None, exclude_paths: Optional[List[str]] = None):
        super().__init__(app)
        self.guard = guard or NoJectGuard()
        self.exclude_paths = exclude_paths or ["/healthz", "/metrics", "/docs", "/openapi.json"]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # 1. Inspect Query String with WAF
        if request.url.query:
            verdict = self.guard.waf.inspect(request.url.query) if self.guard.waf else None
            if verdict and verdict.blocked:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Forbidden by NoJect Security Guard",
                        "threat_category": verdict.threat_type,
                        "reason": verdict.reason,
                        "standard_code": verdict.standard_code
                    }
                )

        # 2. Inspect Body if JSON
        body_bytes = await request.body()
        if body_bytes:
            body_text = body_bytes.decode("utf-8", errors="ignore")
            verdict = self.guard.inspect_prompt(body_text)
            if verdict.is_blocked:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Blocked by NoJect AI Security Shield",
                        "threat_category": verdict.threat_category,
                        "reason": verdict.reason,
                        "standard_code": verdict.standard_code
                    }
                )

        return await call_next(request)
