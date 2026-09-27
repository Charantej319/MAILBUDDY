"""
PhishGuard Configuration
Loads settings from environment variables with sensible defaults.
"""

from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from pathlib import Path
import os

# Export backend/.env values into os.environ so non-pydantic modules that read
# configuration via os.getenv (e.g. app.ai.verifier) see them too. Real
# environment variables always win (load_dotenv does not override by default).
#
# Desktop packaging (Phase 2a): when PHISHGUARD_DATA_DIR is set, mutable
# application data (.env, phishguard.db, uploads, logs) is resolved from that
# per-user directory instead of the install/source directory. When unset, the
# development behavior below is preserved exactly.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# Per-user data directory override. Unset during development -> the .env next
# to this file, the backend-anchored DATABASE_URL and uploads/ are used, as
# before. The packaged desktop app will set PHISHGUARD_DATA_DIR to
# %APPDATA%\PhishGuard so no mutable data is written into the install dir.
_DATA_DIR = Path(os.environ["PHISHGUARD_DATA_DIR"]).expanduser() if os.getenv("PHISHGUARD_DATA_DIR") else None
if _DATA_DIR is not None:
    # Created only when the override is active; dev layout is never touched.
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    (_DATA_DIR / "uploads").mkdir(parents=True, exist_ok=True)
    (_DATA_DIR / "logs").mkdir(parents=True, exist_ok=True)
    load_dotenv(_DATA_DIR / ".env")  # desktop config (GROQ_API_KEY, OAuth client, ...)


class Settings(BaseSettings):
    APP_NAME: str = "PhishGuard"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Database — anchored to the backend directory (development) or to
    # PHISHGUARD_DATA_DIR (desktop packaging) so the same SQLite file is used
    # regardless of the working directory uvicorn/pytest is started from.
    DATABASE_URL: str = (
        f"sqlite:///{_DATA_DIR / 'phishguard.db'}" if _DATA_DIR
        else f"sqlite:///{Path(__file__).resolve().parent.parent / 'phishguard.db'}"
    )

    # Google OAuth 2.0
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"

    # Frontend base URL (OAuth callback redirects here). Must match the origin
    # registered as an Authorized JavaScript origin in Google Cloud Console.
    FRONTEND_URL: str = "http://localhost:5173"

    # Local API surface hardening (desktop app): the only origins/hosts the
    # backend considers legitimate. Derived from the registered OAuth
    # redirect URI port so a changed port stays consistent everywhere.
    BACKEND_PORT: int = 8000
    LOCAL_APP_ORIGIN: str = ""  # empty -> derived from GOOGLE_REDIRECT_URI port
    ALLOWED_LOCAL_HOSTS: list[str] = ["localhost", "127.0.0.1"]
    GOOGLE_SCOPES: list[str] = [
        "https://www.googleapis.com/auth/gmail.readonly",
    ]

    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # Upload settings — under PHISHGUARD_DATA_DIR when desktop packaging sets it.
    MAX_UPLOAD_SIZE_MB: int = 10
    UPLOAD_DIR: Path = (_DATA_DIR / "uploads") if _DATA_DIR else Path("uploads")

    # Detection engine
    MAX_EMAILS_FETCH: int = 100

    # Gmail polling
    GMAIL_POLL_INTERVAL: int = 60  # seconds
    GMAIL_INITIAL_SYNC_COUNT: int = 50

    class Config:
        # Anchor to this file's directory so .env is found regardless of the
        # working directory uvicorn is started from.
        env_file = str(Path(__file__).resolve().parent.parent / ".env")
        env_file_encoding = "utf-8"
        # .env also carries keys consumed directly via os.getenv elsewhere
        # (AI_ENABLED, AI_PROVIDER, GROQ_API_KEY, AI_MODEL). Ignore them here
        # instead of failing validation with "extra inputs are not permitted".
        extra = "ignore"


settings = Settings()

# Effective local app origin (host:port the backend is actually served on).
# Used by the Host allowlist middleware and the OAuth redirect allowlist.
if not settings.LOCAL_APP_ORIGIN:
    from urllib.parse import urlparse

    _redirect = urlparse(settings.GOOGLE_REDIRECT_URI)
    _port = _redirect.port or settings.BACKEND_PORT
    settings.LOCAL_APP_ORIGIN = f"http://localhost:{_port}"
