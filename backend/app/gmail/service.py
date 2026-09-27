"""
Gmail API service with server-side token management.
Tokens are retrieved from the database (encrypted at rest), never from the
frontend, and are decrypted only inside this service before use.
"""

import base64
import logging

import httpx
from contextlib import asynccontextmanager
from datetime import datetime

from ..config import settings
from ..database.connection import SessionLocal
from ..models.email import GmailToken
from ..parser.email_parser import parse_gmail_message

logger = logging.getLogger("phishguard.gmail")
from ..auth.token_storage import TokenDecryptionError, TokenStorage, migrate_tokens


GMAIL_API_BASE = "https://www.googleapis.com/gmail/v1/users/me"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Plaintext tokens live only in memory inside this service; they never touch
# the database in plaintext and never appear in logs.


def _decrypt(encrypted: str) -> str:
    """Decrypt a stored token value through the canonical storage layer.

    Decryption failures propagate (fail closed, loud): a corrupt token is
    never silently converted to "". Callers translate TokenDecryptionError
    into a clear 'reconnect your account' error.
    """
    if not encrypted:
        raise TokenDecryptionError("no stored token")
    return TokenStorage.decrypt(encrypted)


class GmailService:
    """Service for interacting with the Gmail API using server-side tokens."""

    def __init__(self, user_email: str):
        self.user_email = user_email
        self._access_token = None
        self._shared_client = None  # F-30: optional shared AsyncClient
        self._load_token()

    # ---- F-30: connection reuse ------------------------------------------------
    # A sync/poll loop issues one GET per message. Reusing ONE AsyncClient for
    # the whole loop avoids a fresh TCP+TLS handshake per message. Default
    # behavior (no sharing) is unchanged: every call still gets its own
    # short-lived client, exactly as before.
    def use_shared_client(self) -> None:
        """Opt into one shared AsyncClient for many requests (ingestion loops)."""
        if self._shared_client is None:
            self._shared_client = httpx.AsyncClient()

    async def aclose(self) -> None:
        """Close the shared client (no-op when sharing was never enabled)."""
        if self._shared_client is not None:
            await self._shared_client.aclose()
            self._shared_client = None

    @asynccontextmanager
    async def _http(self):
        """Yield the shared client when enabled, else a per-call client."""
        if self._shared_client is not None:
            yield self._shared_client
        else:
            async with httpx.AsyncClient() as client:
                yield client

    def _load_token(self):
        """Load token from database.

        Values are decrypted on the fly; plaintext is held in memory only and
        never written to the database, never logged, and never returned.
        """
        db = SessionLocal()
        try:
            record = db.query(GmailToken).filter(
                GmailToken.user_email == self.user_email
            ).first()
            if record:
                try:
                    self._access_token = _decrypt(record.access_token)
                    self._refresh_token = (
                        _decrypt(record.refresh_token) if record.refresh_token else None
                    )
                except TokenDecryptionError:
                    # Fail closed with a clear signal; never fall back to "".
                    logger.exception(
                        "Stored Gmail token for %s could not be decrypted", self.user_email
                    )
                    raise ValueError(
                        "Stored Gmail credentials could not be decrypted. Please reconnect your account in Settings."
                    )
                self._token_expiry = record.token_expiry
            else:
                raise ValueError(f"No Gmail token found for {self.user_email}")
        finally:
            db.close()

    async def _ensure_valid_token(self):
        """Refresh token if expired."""
        if self._token_expiry and self._token_expiry < datetime.utcnow():
            await self._refresh_access_token()

    async def _refresh_access_token(self):
        """Refresh the access token using the refresh token."""
        if not self._refresh_token:
            raise ValueError("No refresh token available")

        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            raise ValueError("Google OAuth not configured")

        token_data = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "refresh_token": self._refresh_token,
            "grant_type": "refresh_token",
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(GOOGLE_TOKEN_URL, data=token_data)
            if response.status_code != 200:
                raise ValueError("Failed to refresh token")

            new_tokens = response.json()

        self._access_token = new_tokens.get("access_token")
        expires_in = new_tokens.get("expires_in", 3600)
        self._token_expiry = datetime.utcnow().replace(
            second=0, microsecond=0
        ) + __import__("datetime").timedelta(seconds=expires_in)

        # Update in database (encrypted at rest; in-memory plaintext only).
        db = SessionLocal()
        try:
            record = db.query(GmailToken).filter(
                GmailToken.user_email == self.user_email
            ).first()
            if record:
                record.access_token = TokenStorage.encrypt(self._access_token)
                record.token_expiry = self._token_expiry
                record.updated_at = datetime.utcnow()
                db.commit()
        finally:
            db.close()

    @property
    def headers(self):
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
        }

    async def get_profile(self) -> dict:
        """Get the authenticated user's Gmail profile."""
        await self._ensure_valid_token()
        async with self._http() as client:
            response = await client.get(
                f"{GMAIL_API_BASE}/profile",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def list_messages(self, query: str = "", max_results: int = 50) -> list[dict]:
        """List email messages with optional query filter."""
        await self._ensure_valid_token()
        params = {"maxResults": max_results}
        if query:
            params["q"] = query

        async with self._http() as client:
            response = await client.get(
                f"{GMAIL_API_BASE}/messages",
                headers=self.headers,
                params=params,
            )
            response.raise_for_status()
            data = response.json()

        return data.get("messages", [])

    async def get_message(self, message_id: str, format: str = "full") -> dict:
        """Get a full email message by ID."""
        await self._ensure_valid_token()
        async with self._http() as client:
            response = await client.get(
                f"{GMAIL_API_BASE}/messages/{message_id}",
                headers=self.headers,
                params={"format": format},
            )
            response.raise_for_status()
            return response.json()

    async def get_message_raw(self, message_id: str) -> str:
        """Get a message in raw (RFC 2822) format."""
        await self._ensure_valid_token()
        async with self._http() as client:
            response = await client.get(
                f"{GMAIL_API_BASE}/messages/{message_id}",
                headers=self.headers,
                params={"format": "raw"},
            )
            response.raise_for_status()
            data = response.json()

        raw_data = data.get("raw", "")
        return base64.urlsafe_b64decode(raw_data + "==").decode("utf-8", errors="replace")

    async def fetch_and_parse(self, message_id: str) -> tuple[dict, object]:
        """Fetch a Gmail message and parse it into ParsedEmail."""
        message = await self.get_message(message_id, format="full")
        parsed = parse_gmail_message(message)
        return message, parsed
