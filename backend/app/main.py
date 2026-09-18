"""
PhishGuard — Explainable Email Phishing & Threat Detection Platform
FastAPI Application Entry Point
"""

import sys
import os

# Add project root to Python path so we can import detection package
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .ai.routes import router as ai_router

from .config import settings
from .database.connection import init_db
from .api.analysis import router as analysis_router
from .auth.google import router as auth_router
from .gmail.api import router as gmail_router

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="Explainable Email Phishing & Threat Detection Platform",
    version=settings.APP_VERSION,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(analysis_router, prefix="/api")
app.include_router(auth_router)
app.include_router(gmail_router)
app.include_router(ai_router)

from .mailbuddy.routes import router as mailbuddy_router  # noqa: E402
app.include_router(mailbuddy_router)


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    init_db()
    # MailBuddy tables (app_settings, notification_log) plus the new priority
    # columns — create_all + additive migration are idempotent.
    from .database.connection import Base, engine
    from .models.email import AppSetting, NotificationLog  # noqa: F401
    Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------------------------
# Static frontend serving (Phase 2a — desktop packaging preparation).
#
# When a production frontend build exists (frontend/dist), the backend serves
# it so the packaged desktop app only needs http://localhost:8000 — same
# origin for the API, session cookies and the OAuth callback. When the build
# is absent (development) nothing is mounted and the vite dev server on
# :5173 keeps serving the frontend exactly as before.
# ---------------------------------------------------------------------------
def _resolve_frontend_dist() -> Path | None:
    """Locate the React production build.

    Dev:     <project>/frontend/dist (Phase 2a behavior, unchanged).
    Frozen:  <_MEIPASS>/frontend_dist (PyInstaller bundle data).
    Returns None when no build exists (development without dist).
    """
    if getattr(sys, "frozen", False):  # PyInstaller runtime
        candidate = Path(getattr(sys, "_MEIPASS", "")) / "frontend_dist"
        return candidate if (candidate / "index.html").is_file() else None
    candidate = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    return candidate if (candidate / "index.html").is_file() else None


_FRONTEND_DIST = _resolve_frontend_dist()
_HAS_FRONTEND_BUILD = _FRONTEND_DIST is not None

if _HAS_FRONTEND_BUILD:
    # Vite emits hashed assets under /assets; other static files (favicon,
    # etc.) are served by the SPA fallback below. Registering the mount here
    # does not affect API/auth routers — FastAPI matches specific routes first.
    _assets_dir = _FRONTEND_DIST / "assets"
    if _assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=_assets_dir), name="frontend-assets")


@app.get("/")
async def root():
    """Root endpoint: the React app shell in production mode, service metadata in development."""
    if _HAS_FRONTEND_BUILD:
        return FileResponse(_FRONTEND_DIST / "index.html")
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/api/health",
    }


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "PhishGuard API"}


if _HAS_FRONTEND_BUILD:
    @app.get("/{spa_path:path}", include_in_schema=False)
    async def spa_fallback(spa_path: str):
        """SPA fallback for BrowserRouter paths (/emails, /emails/:id, /settings, ...).

        Registered LAST (after every API/auth route) so real routes always
        match first — FastAPI/Starlette matches in registration order. The
        guard means a mistyped API/auth path still returns a JSON 404 instead
        of HTML, and the traversal check keeps file serving inside dist.
        """
        if spa_path.startswith(("api/", "auth/")) or spa_path in ("api", "auth"):
            raise HTTPException(status_code=404, detail="Not found")
        candidate = (_FRONTEND_DIST / spa_path).resolve()
        if (
            spa_path
            and candidate.is_file()
            and candidate.is_relative_to(_FRONTEND_DIST.resolve())  # path-traversal guard
        ):
            return FileResponse(candidate)
        return FileResponse(_FRONTEND_DIST / "index.html")
