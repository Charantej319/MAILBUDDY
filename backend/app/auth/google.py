"""
Google OAuth 2.0 authentication for Gmail API access.
Tokens stored server-side in SQLite. Frontend never sees tokens.
"""

import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from urllib.parse import urlencode
import httpx

from ..config import settings
from ..database.connection import SessionLocal
from ..models.email import GmailToken
from .sessions import create_session, get_session_user, remove_session, create_oauth_state, consume_oauth_state

logger = logging.getLogger("phishguard.auth")

router = APIRouter(prefix="/auth")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_API_BASE = "https://www.googleapis.com/gmail/v1/users/me"


def _frontend_url(path: str, params: dict | None = None) -> str:
    """Build a frontend URL (e.g. http://localhost:5173/settings?connected=true)."""
    url = f"{settings.FRONTEND_URL}{path}"
    if params:
        url = f"{url}?{urlencode(params)}"
    return url


def _log_and_redirect(error_code: str, detail: str):
    """Log a callback failure (safe fields only) and redirect to the frontend."""
    # NEVER log access/refresh tokens, client secrets, authorization codes or cookies.
    logger.error("Gmail OAuth callback failed: %s (%s)", error_code, detail)
    return RedirectResponse(url=_frontend_url("/settings", {"error": error_code}))


@router.get("/google")
async def google_login():
    """Redirect user to Google OAuth consent screen."""
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        logger.error("Gmail OAuth attempted but GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET are not set")
        raise HTTPException(
            status_code=503,
            detail="Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in backend/.env"
        )

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
    """Handle Google OAuth callback. Store tokens server-side."""
    # 1. User cancelled / denied consent at the Google screen.
    if error:
        return _log_and_redirect(error, "Google returned an OAuth error")

    if not code:
        return _log_and_redirect("missing_code", "No authorization code received")

    # 2. CSRF state validation (single use, 10 minute TTL).
    if not consume_oauth_state(state):
        return _log_and_redirect("invalid_state", "Missing, expired or already-used state parameter")

    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        logger.error("Gmail OAuth callback but GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET are not set")
        raise HTTPException(status_code=503, detail="Google OAuth not configured")

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
        return _log_and_redirect("network_error", "Could not reach Google token endpoint")

    if token_response.status_code != 200:
        # Log only the OAuth error code, never the response body (contains secrets).
        token_error = token_response.json().get("error", "unknown") if token_response.headers.get("content-type", "").startswith("application/json") else "non_json_response"
        logger.error("Gmail OAuth: token exchange failed with HTTP %s (%s)", token_response.status_code, token_error)
        return _log_and_redirect("token_exchange_failed", f"Google rejected the authorization code (HTTP {token_response.status_code})")

    tokens = token_response.json()

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    expires_in = tokens.get("expires_in", 3600)

    if not access_token:
        return _log_and_redirect("token_exchange_failed", "No access token in Google response")

    # 4. Identify the account via the Gmail profile endpoint.
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            profile_response = await client.get(
                f"{GMAIL_API_BASE}/profile",
                headers={"Authorization": f"Bearer {access_token}"},
            )
    except httpx.RequestError as exc:
        logger.error("Gmail OAuth: profile fetch network failure: %s", type(exc).__name__)
        return _log_and_redirect("network_error", "Could not reach Gmail API")

    if profile_response.status_code == 403:
        # Most common cause: Gmail API not enabled on the Google Cloud project.
        logger.error("Gmail OAuth: Gmail API returned 403 for profile (is the Gmail API enabled on the Google Cloud project?)")
        return _log_and_redirect("gmail_api_disabled", "Gmail API is not enabled for this Google Cloud project (HTTP 403)")

    if profile_response.status_code != 200:
        logger.error("Gmail OAuth: Gmail profile fetch failed with HTTP %s", profile_response.status_code)
        return _log_and_redirect("profile_failed", f"Gmail profile lookup failed (HTTP {profile_response.status_code})")

    user_email = profile_response.json().get("emailAddress")
    if not user_email:
        return _log_and_redirect("profile_failed", "Gmail profile did not include an email address")

    # 5. Store tokens server-side (never sent to the frontend).
    db = SessionLocal()
    try:
        existing = db.query(GmailToken).filter(GmailToken.user_email == user_email).first()
        if existing:
            existing.access_token = access_token
            if refresh_token:
                existing.refresh_token = refresh_token
            existing.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
            existing.updated_at = datetime.utcnow()
        else:
            db.add(GmailToken(
                user_email=user_email,
                access_token=access_token,
                refresh_token=refresh_token,
                token_expiry=datetime.utcnow() + timedelta(seconds=expires_in),
            ))
        db.commit()
        logger.info("Gmail OAuth: tokens stored for %s", user_email)
    finally:
        db.close()

    # 6. Create session (stored in DB, survives server restarts/reloads).
    session_id = create_session(user_email)

    # 7. Redirect back to the frontend with the session cookie.
    response = RedirectResponse(url=_frontend_url("/settings", {"connected": "true"}))
    response.set_cookie(
        key="phishguard_session",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=86400 * 7,  # 7 days
    )
    return response


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

        token_data = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "refresh_token": token_record.refresh_token,
            "grant_type": "refresh_token",
        }

        async with httpx.AsyncClient(timeout=15) as client:
            token_response = await client.post(GOOGLE_TOKEN_URL, data=token_data)

        if token_response.status_code != 200:
            logger.error("Gmail token refresh failed with HTTP %s", token_response.status_code)
            raise HTTPException(status_code=502, detail="Failed to refresh Gmail token")

        new_tokens = token_response.json()

        token_record.access_token = new_tokens.get("access_token")
        token_record.token_expiry = datetime.utcnow() + timedelta(
            seconds=new_tokens.get("expires_in", 3600)
        )
        token_record.updated_at = datetime.utcnow()
        db.commit()

        return {"status": "refreshed"}
    finally:
        db.close()


@router.post("/google/disconnect")
async def disconnect_gmail(request: Request):
    """Disconnect Gmail and remove stored tokens."""
    session_id = request.cookies.get("phishguard_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="No active session")

    user_email = get_session_user(session_id)
    if user_email:
        db = SessionLocal()
        try:
            token_record = db.query(GmailToken).filter(GmailToken.user_email == user_email).first()
            if token_record:
                db.delete(token_record)
                db.commit()
        finally:
            db.close()

    remove_session(session_id)

    response = JSONResponse(content={"status": "disconnected"})
    response.delete_cookie("phishguard_session")
    return response
