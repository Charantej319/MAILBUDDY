"""
Google OAuth 2.0 authentication for Gmail API access.
Tokens stored server-side in SQLite, encrypted at rest via TokenStorage.
Frontend never sees tokens.
"""

import logging
import os
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from urllib.parse import urlencode
import httpx

from ..config import settings
from ..database.connection import SessionLocal
from ..models.email import GmailToken
from .sessions import create_session, get_session_user, remove_session, create_oauth_state, consume_oauth_state
from .token_storage import encrypt as encrypt_token

logger = logging.getLogger("phishguard.auth")

router = APIRouter(prefix="/auth")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GMAIL_API_BASE = "https://www.googleapis.com/gmail/v1/users/me"

# Short timeout for the best-effort revocation call on disconnect.
_REVOKE_TIMEOUT = 5.0


def _frontend_url(path: str, params: dict | None = None) -> str:
    """Build a URL on the configured FRONTEND_URL (used for email/notification links)."""
    url = f"{settings.FRONTEND_URL}{path}"
    if params:
        url = f"{url}?{urlencode(params)}"
    return url


def _allowed_callback_origins() -> list[str]:
    """Origins the OAuth callback is permitted to redirect back to.

    Derived from the configured local application origin (backend port +
    the loopback hosts the app actually binds/serves), never from an
    attacker-controlled request header.
    """
    from urllib.parse import urlparse

    redirect_origin = urlparse(settings.GOOGLE_REDIRECT_URI)
    origins = set()
    if redirect_origin.scheme and redirect_origin.netloc:
        origins.add(f"{redirect_origin.scheme}://{redirect_origin.netloc}")
    # The registered local app origin(s): localhost + 127.0.0.1 on the
    # configured backend port.
    port = redirect_origin.port or 8000
    origins.add(f"http://localhost:{port}")
    origins.add(f"http://127.0.0.1:{port}")
    return sorted(origins)


def _callback_origin(request: Request) -> str:
    """Allowlisted same-origin base URL for the post-OAuth redirect.

    The Host / X-Forwarded-Proto headers are only ever matched against the
    configured allowlist (settings.LOCAL_APP_ORIGIN plus the registered
    OAuth redirect origin). An unexpected Host can NOT influence the
    redirect target — it falls back to the configured origin.
    """
    host = (request.headers.get("host") or "").lower()
    forwarded = request.headers.get("x-forwarded-proto")
    candidates = []
    if forwarded:
        for scheme in forwarded.split(","):
            scheme = scheme.strip()
            if scheme and host:
                candidates.append(f"{scheme}://{host}")
    if host:
        candidates.append(f"http://{host}")

    allowed = set(_allowed_callback_origins())
    local = settings.LOCAL_APP_ORIGIN
    if local:
        allowed.add(local)

    for candidate in candidates:
        if candidate in allowed:
            return candidate

    # Not on the allowlist (e.g. Host: evil.example) → configured origin.
    return local or f"http://localhost:{settings.BACKEND_PORT}"


def _post_auth_redirect(request: Request, params: dict | None = None) -> str:
    """Redirect target after OAuth (success or failure).

    Desktop/packaged mode (PHISHGUARD_DATA_DIR set by the Electron shell): the
    SPA is served by this same FastAPI origin, so redirect back to the
    allowlisted local origin — never to the configured FRONTEND_URL (e.g. the
    Vite dev server :5173), which does not exist in the packaged app.
    Dev mode (PHISHGUARD_DATA_DIR unset): unchanged — FRONTEND_URL (:5173).
    The Host header can never steer the redirect to a foreign origin.
    """
    if os.environ.get("PHISHGUARD_DATA_DIR"):
        url = f"{_callback_origin(request)}/settings"
    else:
        url = _frontend_url("/settings")
    if params:
        url = f"{url}?{urlencode(params)}"
    return url


def _log_and_redirect(request: Request, error_code: str, detail: str):
    """Log a callback failure (safe fields only) and redirect to the app's own frontend."""
    # NEVER log access/refresh tokens, client secrets, authorization codes or cookies.
    logger.error("Gmail OAuth callback failed: %s (%s)", error_code, detail)
    return RedirectResponse(url=_post_auth_redirect(request, {"error": error_code}))


@router.get("/google")
async def google_login(request: Request):
    """Redirect user to Google OAuth consent screen."""
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        logger.error("Gmail OAuth attempted but GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET are not set")
        # Redirect to the app's own error state instead of returning raw JSON.
        return RedirectResponse(url=_post_auth_redirect(request, {"error": "oauth_not_configured"}))

    state = create_oauth_state()

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(settings.GOOGLE_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
        "include_granted_scopes": "true",
    }

    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    logger.info("Gmail OAuth: redirecting user to Google consent screen")
    return RedirectResponse(url=auth_url)


@router.get("/google/callback")
async def google_callback(
    request: Request,
    code: str | None = None,
    error: str | None = None,
    state: str | None = None,
):
    """Handle Google OAuth callback. Store encrypted tokens server-side."""
    # 1. User cancelled / denied consent at the Google screen.
    if error:
        return _log_and_redirect(request, error, "Google returned an OAuth error")

    if not code:
        return _log_and_redirect(request, "missing_code", "No authorization code received")

    # 2. CSRF state validation (single use, 10 minute TTL).
    if not consume_oauth_state(state):
        return _log_and_redirect(request, "invalid_state", "Missing, expired or already-used state parameter")

    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        logger.error("Gmail OAuth callback but GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET are not set")
        return RedirectResponse(url=_post_auth_redirect(request, {"error": "oauth_not_configured"}))

    # 3. Exchange authorization code for tokens.
    token_data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            token_response = await client.post(GOOGLE_TOKEN_URL, data=token_data)
    except httpx.RequestError as exc:
        logger.error("Gmail OAuth: token exchange network failure: %s", type(exc).__name__)
        return _log_and_redirect(request, "network_error", "Could not reach Google token endpoint")

    if token_response.status_code != 200:
        # Log only the OAuth error code, never the response body (contains secrets).
        token_error = token_response.json().get("error", "unknown") if token_response.headers.get("content-type", "").startswith("application/json") else "non_json_response"
        logger.error("Gmail OAuth: token exchange failed with HTTP %s (%s)", token_response.status_code, token_error)
        return _log_and_redirect(request, "token_exchange_failed", f"Google rejected the authorization code (HTTP {token_response.status_code})")

    tokens = token_response.json()

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    expires_in = tokens.get("expires_in", 3600)

    if not access_token:
        return _log_and_redirect(request, "token_exchange_failed", "No access token in Google response")

    # 4. Identify the account via the Gmail profile endpoint.
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            profile_response = await client.get(
                f"{GMAIL_API_BASE}/profile",
                headers={"Authorization": f"Bearer {access_token}"},
            )
    except httpx.RequestError as exc:
        logger.error("Gmail OAuth: profile fetch network failure: %s", type(exc).__name__)
        return _log_and_redirect(request, "network_error", "Could not reach Gmail API")

    if profile_response.status_code == 403:
        # Most common cause: Gmail API not enabled on the Google Cloud project.
        logger.error("Gmail OAuth: Gmail API returned 403 for profile (is the Gmail API enabled on the Google Cloud project?)")
        return _log_and_redirect(request, "gmail_api_disabled", "Gmail API is not enabled for this Google Cloud project (HTTP 403)")

    if profile_response.status_code != 200:
        logger.error("Gmail OAuth: Gmail profile fetch failed with HTTP %s", profile_response.status_code)
        return _log_and_redirect(request, "profile_failed", f"Gmail profile lookup failed (HTTP {profile_response.status_code})")

    user_email = profile_response.json().get("emailAddress")
    if not user_email:
        return _log_and_redirect(request, "profile_failed", "Gmail profile did not include an email address")

    # 5. Encrypt BEFORE persistence (never store plaintext OAuth tokens).
    access_encrypted = encrypt_token(access_token)
    refresh_encrypted = encrypt_token(refresh_token) if refresh_token else None

    db = SessionLocal()
    try:
        existing = db.query(GmailToken).filter(GmailToken.user_email == user_email).first()
        if existing:
            existing.access_token = access_encrypted
            if refresh_encrypted:
                existing.refresh_token = refresh_encrypted
            existing.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
            existing.updated_at = datetime.utcnow()
        else:
            db.add(GmailToken(
                user_email=user_email,
                access_token=access_encrypted,
                refresh_token=refresh_encrypted,
                token_expiry=datetime.utcnow() + timedelta(seconds=expires_in),
            ))
        db.commit()
        logger.info("Gmail OAuth: encrypted tokens stored for %s", user_email)
    finally:
        db.close()

    # 6. Create session (stored in DB, survives server restarts/reloads).
    session_id = create_session(user_email)

    # 7. Redirect back to the allowlisted app origin (same-origin in dev and
    #    desktop) with the session cookie.
    response = RedirectResponse(url=_post_auth_redirect(request, {"connected": "true"}))
    response.set_cookie(
        key="phishguard_session",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=86400 * 7,  # 7 days
    )
    return response


async def revoke_google_token(token_value: str | None) -> bool:
    """Best-effort revocation of a Google OAuth grant.

    Calls Google's official revocation endpoint with a short timeout.
    Returns True only when Google confirmed (HTTP 200). Never logs the
    token. Failures are logged by type only; the caller decides whether
    local cleanup still proceeds (it must — disconnect stays usable).
    """
    if not token_value:
        return False
    try:
        async with httpx.AsyncClient(timeout=_REVOKE_TIMEOUT) as client:
            response = await client.post(
                GOOGLE_REVOKE_URL,
                data={"token": token_value},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if response.status_code == 200:
            logger.info("Google OAuth grant revoked")
            return True
        logger.warning("Google OAuth revoke returned HTTP %s", response.status_code)
        return False
    except httpx.RequestError as exc:
        logger.warning("Google OAuth revoke network failure: %s", type(exc).__name__)
        return False


@router.post("/google/refresh")
async def refresh_token_endpoint(request: Request):
    """Refresh an expired access token using the stored refresh token."""
    session_id = request.cookies.get("phishguard_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="No active session")

    user_email = get_session_user(session_id)
    if not user_email:
        raise HTTPException(status_code=401, detail="Invalid session")

    db = SessionLocal()
    try:
        token_record = db.query(GmailToken).filter(GmailToken.user_email == user_email).first()
        if not token_record or not token_record.refresh_token:
            raise HTTPException(status_code=401, detail="No refresh token available")

        refresh_plaintext = decrypt_stored_token(token_record.refresh_token)

        token_data = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "refresh_token": refresh_plaintext,
            "grant_type": "refresh_token",
        }

        async with httpx.AsyncClient(timeout=15) as client:
            token_response = await client.post(GOOGLE_TOKEN_URL, data=token_data)

        if token_response.status_code != 200:
            logger.error("Gmail token refresh failed with HTTP %s", token_response.status_code)
            raise HTTPException(status_code=502, detail="Failed to refresh Gmail token")

        new_tokens = token_response.json()

        token_record.access_token = encrypt_token(new_tokens.get("access_token"))
        token_record.token_expiry = datetime.utcnow() + timedelta(
            seconds=new_tokens.get("expires_in", 3600)
        )
        token_record.updated_at = datetime.utcnow()
        db.commit()

        return {"status": "refreshed"}
    finally:
        db.close()


def decrypt_stored_token(encrypted_value: str | None) -> str:
    """Decrypt a stored token through the canonical TokenStorage layer.

    Raises TokenDecryptionError on failure — callers convert that into a
    clear 401 ("reconnect your account") instead of silently using "".
    """
    from .token_storage import TokenDecryptionError, TokenStorage

    if not encrypted_value:
        raise TokenDecryptionError("no stored token")
    return TokenStorage.decrypt(encrypted_value)


@router.post("/google/disconnect")
async def disconnect_gmail(request: Request):
    """Disconnect Gmail: revoke the Google grant, then remove local state."""
    session_id = request.cookies.get("phishguard_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="No active session")

    user_email = get_session_user(session_id)
    if user_email:
        db = SessionLocal()
        try:
            token_record = db.query(GmailToken).filter(GmailToken.user_email == user_email).first()
            if token_record:
                # Revoke BEFORE deleting the local row. Prefer the refresh
                # token (it revokes the whole grant incl. access tokens);
                # fall back to the access token.
                from .token_storage import TokenDecryptionError, TokenStorage

                revoke_value = None
                try:
                    if token_record.refresh_token:
                        revoke_value = TokenStorage.decrypt(token_record.refresh_token)
                    elif token_record.access_token:
                        revoke_value = TokenStorage.decrypt(token_record.access_token)
                except TokenDecryptionError:
                    revoke_value = None  # undecryptable -> nothing usable to revoke

                await revoke_google_token(revoke_value)

                # Local cleanup ALWAYS happens, even when revocation failed
                # (Google unreachable): never leave the credential behind.
                db.delete(token_record)
                db.commit()
        finally:
            db.close()

    remove_session(session_id)

    response = JSONResponse(content={"status": "disconnected"})
    response.delete_cookie("phishguard_session")
    return response
