"""
Regression tests for the Gmail OAuth callback flow.

Covers the post-approval blank-page bug: in desktop mode the callback used to
redirect to FRONTEND_URL (the Vite dev server :5173), which does not exist in
the packaged app. The fix redirects to the origin the flow started from.

All Google token/profile endpoints are MOCKED — no real credentials needed.
"""

import os
import sys
import uuid
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi.testclient import TestClient

TEST_EMAIL = "gauth-test@example.com"


@pytest.fixture(scope="module")
def client():
    from backend.app.database.connection import init_db
    from backend.app.main import app
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def cleanup_test_rows():
    """Remove every DB row these tests create (tokens/sessions for TEST_EMAIL)."""
    yield
    from backend.app.database.connection import SessionLocal
    from backend.app.models.email import GmailToken
    from backend.app.auth.sessions import OAuthSession
    db = SessionLocal()
    try:
        db.query(GmailToken).filter(GmailToken.user_email == TEST_EMAIL).delete()
        db.query(OAuthSession).filter(OAuthSession.user_email == TEST_EMAIL).delete()
        db.commit()
    finally:
        db.close()


def _mock_google(token_payload=None, token_status=200, profile_payload=None,
                 profile_status=200, post_exc=None):
    """Patch httpx.AsyncClient inside the auth module with canned responses."""
    token_resp = SimpleNamespace(
        status_code=token_status,
        json=lambda: token_payload or {},
        headers={"content-type": "application/json"},
    )
    profile_resp = SimpleNamespace(
        status_code=profile_status,
        json=lambda: profile_payload or {},
        headers={"content-type": "application/json"},
    )

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, data=None):
            if post_exc:
                raise post_exc
            return token_resp

        async def get(self, url, headers=None):
            return profile_resp

    return patch("backend.app.auth.google.httpx.AsyncClient", FakeAsyncClient)


def _get_state(client) -> str:
    """Start a real OAuth flow and extract the state from the consent URL."""
    r = client.get("/auth/google", follow_redirects=False)
    assert r.status_code in (302, 307), r.status_code
    qs = parse_qs(urlparse(r.headers["location"]).query)
    return qs["state"][0]


def _success_creds(client, monkeypatch):
    """Deterministic OAuth client credentials for the callback logic."""
    from backend.app.config import settings
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "test-client-secret")


SUCCESS_TOKEN = {"access_token": "at-test-123", "refresh_token": "rt-test-123",
                 "expires_in": 3600}
SUCCESS_PROFILE = {"emailAddress": TEST_EMAIL}


# ─────────────────────────── success paths ───────────────────────────

def test_callback_success_desktop_same_origin(client, monkeypatch):
    """Desktop mode: approval → tokens stored → session cookie → same-origin
    redirect (NOT FRONTEND_URL/:5173) → /api/gmail/status reports connected."""
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", os.environ.get("PHISHGUARD_DATA_DIR", "desktop-mode-under-test"))
    _success_creds(client, monkeypatch)
    state = _get_state(client)

    with _mock_google(SUCCESS_TOKEN, profile_payload=SUCCESS_PROFILE):
        r = client.get(f"/auth/google/callback?code=abc123&state={state}",
                       follow_redirects=False)

    assert r.status_code in (302, 307)
    loc = r.headers["location"]
    assert ":5173" not in loc, f"desktop redirect must never target the dev server: {loc}"
    assert loc in ("http://testserver/settings?connected=true",
                   "https://testserver/settings?connected=true"), loc

    # Session cookie issued on the callback response
    session_id = r.cookies.get("phishguard_session")
    assert session_id, "callback must set the phishguard_session cookie"

    # Credentials persisted server-side
    from backend.app.database.connection import SessionLocal
    from backend.app.models.email import GmailToken
    db = SessionLocal()
    try:
        row = db.query(GmailToken).filter(GmailToken.user_email == TEST_EMAIL).first()
        assert row is not None, "Gmail tokens must be persisted"
        assert row.access_token  # never exposed to the frontend
    finally:
        db.close()

    # Frontend verifies real connection status through the backend
    status = client.get("/api/gmail/status", cookies={"phishguard_session": session_id}).json()
    assert status["connected"] is True
    assert status["email"] == TEST_EMAIL


def test_callback_success_dev_mode_keeps_frontend_url(client, monkeypatch):
    """Dev mode (PHISHGUARD_DATA_DIR unset): legacy FRONTEND_URL redirect is
    preserved — cookie still lands (localhost cookies are port-agnostic)."""
    monkeypatch.delenv("PHISHGUARD_DATA_DIR", raising=False)
    _success_creds(client, monkeypatch)
    state = _get_state(client)

    with _mock_google(SUCCESS_TOKEN, profile_payload=SUCCESS_PROFILE):
        r = client.get(f"/auth/google/callback?code=abc123&state={state}",
                       follow_redirects=False)

    loc = r.headers["location"]
    assert loc.startswith("http://localhost:5173/settings?connected=true"), loc
    assert r.cookies.get("phishguard_session")


# ─────────────────────────── failure paths ───────────────────────────

def test_callback_denial_redirects_to_settings_error(client, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    r = client.get("/auth/google/callback?error=access_denied&state=x",
                   follow_redirects=False)
    loc = r.headers["location"]
    assert r.status_code in (302, 307)
    assert "error=access_denied" in loc and ":5173" not in loc


def test_callback_missing_code(client, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    r = client.get("/auth/google/callback?state=whatever", follow_redirects=False)
    assert "error=missing_code" in r.headers["location"]


def test_callback_invalid_state(client, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    r = client.get("/auth/google/callback?code=abc&state=bogus-state",
                   follow_redirects=False)
    assert "error=invalid_state" in r.headers["location"]


def test_callback_expired_state(client, monkeypatch):
    """A state past its 10-minute TTL must be rejected."""
    from datetime import datetime, timedelta
    from backend.app.auth.sessions import create_oauth_state
    from backend.app.database.connection import SessionLocal
    from backend.app.auth.sessions import OAuthState

    state = create_oauth_state()
    db = SessionLocal()
    try:
        row = db.get(OAuthState, state)
        row.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()

    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    r = client.get(f"/auth/google/callback?code=abc&state={state}",
                   follow_redirects=False)
    assert "error=invalid_state" in r.headers["location"]


def test_callback_token_exchange_rejected(client, monkeypatch):
    """Google returns non-200 for the authorization code (invalid code)."""
    _success_creds(client, monkeypatch)
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    state = _get_state(client)

    with _mock_google(token_status=400, token_payload={"error": "invalid_grant"}):
        r = client.get(f"/auth/google/callback?code=bad-code&state={state}",
                       follow_redirects=False)

    loc = r.headers["location"]
    assert "error=token_exchange_failed" in loc
    assert "bad-code" not in loc  # authorization code never leaks into the URL


def test_callback_token_endpoint_unreachable(client, monkeypatch):
    _success_creds(client, monkeypatch)
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    state = _get_state(client)

    with _mock_google(post_exc=httpx.ConnectError("connection refused")):
        r = client.get(f"/auth/google/callback?code=abc&state={state}",
                       follow_redirects=False)

    assert "error=network_error" in r.headers["location"]


def test_callback_profile_failure(client, monkeypatch):
    _success_creds(client, monkeypatch)
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    state = _get_state(client)

    with _mock_google(SUCCESS_TOKEN, profile_status=500):
        r = client.get(f"/auth/google/callback?code=abc&state={state}",
                       follow_redirects=False)

    assert "error=profile_failed" in r.headers["location"]


def test_callback_gmail_api_disabled(client, monkeypatch):
    """HTTP 403 from the Gmail profile endpoint = Gmail API not enabled."""
    _success_creds(client, monkeypatch)
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    state = _get_state(client)

    with _mock_google(SUCCESS_TOKEN, profile_status=403):
        r = client.get(f"/auth/google/callback?code=abc&state={state}",
                       follow_redirects=False)

    assert "error=gmail_api_disabled" in r.headers["location"]


def test_login_unconfigured_client_friendly_redirect(client, monkeypatch):
    """No OAuth client configured → friendly redirect to the app's error state,
    never a raw JSON 503 and never :5173 in desktop mode."""
    from backend.app.config import settings
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "")

    r = client.get("/auth/google", follow_redirects=False)
    loc = r.headers["location"]
    assert r.status_code in (302, 307)
    assert "error=oauth_not_configured" in loc and ":5173" not in loc


def test_callback_unconfigured_client_friendly_redirect(client, monkeypatch):
    from backend.app.config import settings
    from backend.app.auth.sessions import create_oauth_state
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "")

    # State validation precedes the config check (by design), so supply a
    # valid state to actually reach the unconfigured branch.
    state = create_oauth_state()
    r = client.get(f"/auth/google/callback?code=abc&state={state}", follow_redirects=False)
    assert "error=oauth_not_configured" in r.headers["location"]


def test_success_redirect_leaks_no_secrets(client, monkeypatch):
    """The redirect URL must contain neither authorization codes nor tokens."""
    _success_creds(client, monkeypatch)
    monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
    state = _get_state(client)

    with _mock_google(SUCCESS_TOKEN, profile_payload=SUCCESS_PROFILE):
        r = client.get(f"/auth/google/callback?code=abc123&state={state}",
                       follow_redirects=False)

    loc = r.headers["location"]
    assert "abc123" not in loc
    assert "at-test-123" not in loc and "rt-test-123" not in loc
    assert "test-client-secret" not in loc
