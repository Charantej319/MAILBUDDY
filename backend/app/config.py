"""
PhishGuard Configuration
Loads settings from environment variables with sensible defaults.
"""

from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from pathlib import Path

# Export backend/.env values into os.environ so non-pydantic modules that read
# configuration via os.getenv (e.g. app.ai.verifier) see them too. Real
# environment variables always win (load_dotenv does not override by default).
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


class Settings(BaseSettings):
    APP_NAME: str = "PhishGuard"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Database — anchored to the backend directory so the same SQLite file is
    # used regardless of the working directory uvicorn/pytest is started from.
    DATABASE_URL: str = f"sqlite:///{Path(__file__).resolve().parent.parent / 'phishguard.db'}"

    # Google OAuth 2.0
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/google/callback"

    # Frontend base URL (OAuth callback redirects here). Must match the origin
    # registered as an Authorized JavaScript origin in Google Cloud Console.
    FRONTEND_URL: str = "http://localhost:5173"
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

    # Upload settings
    MAX_UPLOAD_SIZE_MB: int = 10
    UPLOAD_DIR: Path = Path("uploads")

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
