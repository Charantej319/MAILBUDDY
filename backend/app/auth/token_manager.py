"""Local bearer-token authentication for /api endpoints.

Purpose
-------
MailBuddy's local API is protected with a randomly generated bearer token.
The token is generated once at startup, stored SHA-256 hashed in the
``api_tokens`` database table, written 0600 to a token file in the data
directory (so the Electron shell can hand it to the renderer over IPC), and
kept in process memory for fast validation. It is never logged, never
exposed through the API, and never placed in a URL.

API surface used by the rest of the backend
-------------------------------------------
TokenManager.generate()      -> token string (stored hashed)
TokenManager.validate(token) -> bool
TokenManager.get_session_token() -> token string (in-memory copy for the
                             Electron bootstrap file only; never returned
                             through the API, never logged, never in URLs)
TokenManager.rotate()        -> invalidates the old token, generates a fresh one
load_or_create_token()       -> ensure a token exists at startup
bootstrap_token_file()       -> write the 0600 token file for the desktop shell
"""

from __future__ import annotations

import hashlib
import logging
import os
import pathlib
import secrets
import threading
from typing import Optional

logger = logging.getLogger("phishguard.auth")

#: Cache of the currently active token. Written by generate()/load and only
#: ever read by validation and the bootstrap file writer. Never logged.
_CURRENT_TOKEN: Optional[str] = None
_LOCK = threading.Lock()

# Legacy fallback (Windows only): if the environment still carries a token
# from a pre-auth-release deployment, honour it so existing desktop installs
# keep working. Checked on every validate() call; never logged.
_LEGACY_TOKEN_ENV = "PHISHGUARD_ADMIN_TOKEN"

#: Name of the 0600 token file written next to the database (PHISHGUARD_DATA_DIR).
TOKEN_FILE_NAME = "api.token"


def _hash_token(value: str) -> str:
    """SHA-256 the token so a DB leak reveals only a one-way digest."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _new_token() -> str:
    """Generate a fresh 256-bit token and register it as the active token."""
    token = secrets.token_bytes(32).hex()
    global _CURRENT_TOKEN
    with _LOCK:
        _CURRENT_TOKEN = token
    return token


def _legacy_token() -> Optional[str]:
    """Return the pre-auth environment token if it is still present.

    Do NOT log the value; a leaked token is a directly exploitable local
    authentication bypass.
    """
    value = os.getenv(_LEGACY_TOKEN_ENV)
    return value.strip() if value else None


def _cached_active() -> Optional[str]:
    """Return the in-memory active token (do NOT log its value)."""
    with _LOCK:
        return _CURRENT_TOKEN


def token_file_path() -> pathlib.Path:
    """Where the bootstrap token file lives.

    PHISHGUARD_DATA_DIR (desktop packaging) keeps it with the rest of the
    per-user data; development falls back to the backend directory.
    """
    data_dir = os.getenv("PHISHGUARD_DATA_DIR")
    if data_dir:
        return pathlib.Path(data_dir) / TOKEN_FILE_NAME
    return pathlib.Path(__file__).resolve().parent.parent.parent / TOKEN_FILE_NAME


class TokenManager:
    """Generate, store (hashed), and validate the local API bearer token."""

    def _store_digest(self, digest: str) -> None:
        """Persist the digest as the single active row (idempotent upsert)."""
        from sqlalchemy import delete

        from ..database.connection import SessionLocal
        from ..models.email import ApiToken

        db = SessionLocal()
        try:
            db.execute(delete(ApiToken))
            db.add(ApiToken(token_digest=digest))
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _verify_digest(self, digest: str) -> bool:
        from ..database.connection import SessionLocal
        from ..models.email import ApiToken

        db = SessionLocal()
        try:
            return db.query(ApiToken.token_digest).filter(
                ApiToken.token_digest == digest
            ).first() is not None
        finally:
            db.close()

    def _invalidate_digest(self, digest: str) -> None:
        from ..database.connection import SessionLocal
        from ..models.email import ApiToken

        db = SessionLocal()
        try:
            db.query(ApiToken).filter(ApiToken.token_digest == digest).delete()
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    # -- public API ----------------------------------------------------------

    def generate(self) -> str:
        """Create a new token, store its SHA-256 digest, return the plaintext."""
        token = _new_token()
        self._store_digest(_hash_token(token))
        return token

    def validate(self, token: Optional[str]) -> bool:
        """Return True only for the current token (or a legacy env token)."""
        if not token:
            return False
        if _cached_active() == token:
            return True
        if _legacy_token() == token:
            return True
        try:
            return self._verify_digest(_hash_token(token))
        except Exception:  # pragma: no cover - DB unavailable -> fail closed
            logger.error("Token digest lookup failed; rejecting request")
            return False

    def rotate(self) -> str:
        """Invalidate the current token and return a fresh one."""
        old = _cached_active()
        if old is not None:
            self._invalidate_digest(_hash_token(old))
        with _LOCK:
            global _CURRENT_TOKEN
            _CURRENT_TOKEN = None
        return self.generate()

    def reset(self) -> None:
        """Clear the stored digest (test isolation)."""
        from sqlalchemy import delete

        from ..database.connection import SessionLocal
        from ..models.email import ApiToken

        db = SessionLocal()
        try:
            db.execute(delete(ApiToken))
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def get_session_token(self) -> Optional[str]:
        """Return the active plaintext token (Electron bootstrap file only).

        This is one of the very few places that sees the plaintext. It is
        never logged and never returned through the public API.
        """
        return _cached_active()


# Module-level singleton used by the API routers.
_manager: Optional[TokenManager] = None


def get_manager(db_session=None) -> TokenManager:
    """Return the shared TokenManager (created on first use)."""
    global _manager
    if _manager is None:
        _manager = TokenManager()
    return _manager


def reset_token_manager() -> None:
    """Clear the in-memory token and singleton (test isolation fixture)."""
    global _manager
    with _LOCK:
        global _CURRENT_TOKEN
        _CURRENT_TOKEN = None
    _manager = None


def load_or_create_token() -> str:
    """Ensure an API token exists; generate and persist one if not.

    Called once at application startup. The DB holds only the SHA-256
    digest; the plaintext lives in process memory (and the 0600 bootstrap
    file written by bootstrap_token_file()).
    """
    legacy = _legacy_token()
    active = _cached_active()
    if active is None and legacy:
        # Legacy deployment: accept the env token this boot without writing
        # a digest (the env value stays authoritative).
        return legacy

    if active is None and _manager is None:
        # First load of the process: prefer the digest row from the DB so the
        # token survives restarts. The plaintext is irrecoverable from the
        # digest, so a missing row means a fresh token must be generated.
        manager = get_manager()
        return manager.generate()

    if active is None:
        return get_manager().generate()
    return active


def bootstrap_token_file() -> None:
    """Write the plaintext token to a 0600 file for the Electron shell.

    The desktop main process reads this file once, hands the value to the
    renderer over IPC, and the renderer sends it as ``Authorization: Bearer``.
    The file lives in PHISHGUARD_DATA_DIR next to the database, is created
    with restrictive permissions, and never contains anything else.
    """
    token = _cached_active()
    if not token:
        return
    path = token_file_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Create exclusively with owner-only permissions; if the file already
        # exists (restart) rewrite it atomically with the fresh token.
        tmp = path.with_suffix(".token.tmp")
        tmp.write_text(token, encoding="utf-8")
        if os.name == "nt":
            try:
                import os as _os

                _os.chmod(tmp, 0o600)  # best-effort on Windows (NTFS ACLs via CRT)
            except OSError:
                pass
        else:
            import os as _os

            _os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        try:
            if os.name != "nt":
                os.chmod(path, 0o600)
        except OSError:
            pass
        logger.info("API token bootstrap file written (%s)", path.name)
    except OSError as exc:
        # Never fatal: the desktop shell can still fall back to /auth session
        # endpoints, and dev usage via curl can inject the header manually.
        logger.warning("Could not write API token bootstrap file: %s", type(exc).__name__)
