"""Centralized localhost security middleware for the local API.

Three cooperating layers, all fail-closed:

1. HostAllowlistMiddleware
   The desktop app is served on 127.0.0.1/localhost only. A request whose
   Host header is not on the allowlist (DNS-rebinding, crafted requests)
   gets 403 before any route logic runs. Health endpoints stay open so the
   Electron shell's readiness probe keeps working.

2. APIAuthMiddleware
   Every /api request (except the health check) must carry the local
   bearer token. This runs IN ADDITION to the FastAPI router dependency
   (require_api_token_header) — defense in depth, so a newly mounted
   router without the dependency still cannot be reached anonymously.
   Validation logic is shared with the dependency via check_bearer_token()
   — the rules can never drift apart.

3. CookieOriginMiddleware
   State-changing requests that authenticate with the session cookie (the
   /auth and /api/gmail surface) must present a same-site Origin/Referer.
   Browsers always send Origin on cross-site POSTs, so CSRF from a malicious
   website is rejected with 403. The Electron window, the Vite dev proxy
   and curl (no Origin header at all) are unaffected. Bearer-authenticated
   /api requests are not covered by this layer (their credential is not
   ambient, so CSRF does not apply to them).
"""

from __future__ import annotations

from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from ..config import settings
from .api_auth import check_bearer_token


def _allowed_hosts() -> set[str]:
    hosts = {h.lower() for h in settings.ALLOWED_LOCAL_HOSTS}
    for origin in (settings.LOCAL_APP_ORIGIN, settings.FRONTEND_URL):
        parsed = urlparse(origin or "")
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    return hosts


def _allowed_host_headers() -> set[str]:
    """Concrete Host header values the app accepts (host[:port])."""
    allowed = set()
    for origin in (settings.LOCAL_APP_ORIGIN, settings.FRONTEND_URL):
        parsed = urlparse(origin or "")
        if parsed.netloc:
            allowed.add(parsed.netloc.lower())
    # Also accept the loopback names on the backend port.
    for host in _allowed_hosts():
        allowed.add(f"{host}:{settings.BACKEND_PORT}")
    return allowed


def _is_local_http_host(host_header: str) -> bool:
    """True for Host headers that name THIS machine on the backend port."""
    host_header = (host_header or "").lower()
    if host_header in _allowed_host_headers():
        return True
    host, _, port = host_header.partition(":")
    if host in _allowed_hosts() and port in ("", str(settings.BACKEND_PORT)):
        return True
    return False


class HostAllowlistMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Host header does not name the local app."""

    async def dispatch(self, request: Request, call_next):
        host_header = request.headers.get("host", "")
        if not _is_local_http_host(host_header):
            return JSONResponse(
                status_code=403,
                content={"detail": "Forbidden: unknown host"},
            )
        return await call_next(request)


class APIAuthMiddleware(BaseHTTPMiddleware):
    """Bearer-token gate for the /api surface (health check exempt)."""

    OPEN_PATHS = {"/api/health"}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in self.OPEN_PATHS:
            return await call_next(request)
        if path == "/api" or path.startswith("/api/"):
            try:
                check_bearer_token(request.headers.get("authorization"))
            except Exception:
                # check_bearer_token raises HTTPException; convert to a plain
                # JSON 401 (middleware responses bypass FastAPI handlers).
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Missing or invalid bearer token"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
        return await call_next(request)


class CookieOriginMiddleware(BaseHTTPMiddleware):
    """Enforce same-site Origin on cookie-authenticated state-changing requests."""

    PROTECTED_PREFIXES = ("/auth/", "/api/gmail/")

    @staticmethod
    def _allowed_origins() -> set[str]:
        origins = set()
        for origin in (settings.LOCAL_APP_ORIGIN, settings.FRONTEND_URL):
            if origin:
                origins.add(origin.rstrip("/").lower())
        # The concrete loopback variants on the backend port.
        for host in _allowed_hosts():
            origins.add(f"http://{host}:{settings.BACKEND_PORT}")
        return origins

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method.upper()
        if method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)
        if not any(path == p or path.startswith(p) for p in self.PROTECTED_PREFIXES):
            return await call_next(request)

        origin = (request.headers.get("origin") or "").rstrip("/").lower()
        if not origin:
            # Non-browser clients (curl, Electron main process) send no
            # Origin; they are not subject to CSRF. Browsers always send
            # Origin on cross-site state-changing fetches, so this is safe.
            return await call_next(request)

        referer = request.headers.get("referer")
        candidates = {origin}
        if referer:
            parsed = urlparse(referer)
            if parsed.scheme and parsed.netloc:
                candidates.add(f"{parsed.scheme}://{parsed.netloc}".lower())

        if candidates & self._allowed_origins():
            return await call_next(request)

        return JSONResponse(status_code=403, content={"detail": "Cross-origin request rejected"})
