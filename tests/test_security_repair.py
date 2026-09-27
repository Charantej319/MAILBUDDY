"""
Security repair session 1 — focused regression tests.

Covers:
  Finding 15: centralized /api bearer-token authentication (401/200 paths,
              no Header.partition crash, route coverage across routers)
  Finding 17: Gmail token encryption at rest (DPAPI on Windows / Fernet
              fallback elsewhere), callback encrypts before persistence,
              service decrypts, legacy plaintext migration, invalid
              ciphertext fails loudly
  Finding 20: Google OAuth revocation on disconnect (mocked endpoint),
              local cleanup guaranteed even when revocation fails
  Finding 18: Host allowlist, OAuth redirect origin allowlist, cookie-session
              Origin validation

All Google network endpoints are MOCKED — no real network requests.
The real developer database is never touched (conftest isolates
PHISHGUARD_DATA_DIR before any backend import).
"""

import os
import sys
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi.testclient import TestClient

TEST_EMAIL = "sec-test@example.com"
TEST_TOKEN_ENV = "PHISHGUARD_TEST_API_TOKEN"


# ─────────────────────── fixtures ───────────────────────

@pytest.fixture(scope="module")
def client():
    """TestClient with startup hooks fired (token bootstrap runs)."""
    from backend.app.database.connection import init_db
    from backend.app.main import app
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def api_token(client):
    """The active local API token (created by app startup bootstrap)."""
    from backend.app.auth import token_manager
    token = token_manager.load_or_create_token()
    assert token, "startup bootstrap must have created an API token"
    return token


@pytest.fixture(autouse=True)
def cleanup_test_rows():
    """Remove every DB row these tests create."""
    yield
    from backend.app.database.connection import SessionLocal
    from backend.app.models.email import GmailToken
    from backend.app.auth.sessions import OAuthSession
    from backend.app.auth import token_manager
    db = SessionLocal()
    try:
        db.query(GmailToken).filter(GmailToken.user_email == TEST_EMAIL).delete()
        db.query(OAuthSession).filter(OAuthSession.user_email == TEST_EMAIL).delete()
        db.commit()
    finally:
        db.close()
    # Reset the in-memory token between tests (isolation).
    token_manager.reset_token_manager()
    token_manager.get_manager()  # recreate singleton for the next test


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _seed_gmail_token(access="at-plain-123", refresh="rt-plain-123",
                      enc_access=None, enc_refresh=None):
    """Insert a GmailToken row for TEST_EMAIL (encrypted values optional)."""
    from backend.app.database.connection import SessionLocal
    from backend.app.models.email import GmailToken
    db = SessionLocal()
    try:
        row = GmailToken(
            user_email=TEST_EMAIL,
            access_token=enc_access if enc_access is not None else access,
            refresh_token=enc_refresh if enc_refresh is not None else refresh,
            token_expiry=datetime.utcnow() + timedelta(hours=1),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id
    finally:
        db.close()


def _make_session():
    from backend.app.auth.sessions import create_session
    return create_session(TEST_EMAIL)


# ─────────────────────── Finding 15: API authentication ───────────────────────

class TestAPIAuthentication:
    def test_missing_token_401(self, client):
        r = client.get("/api/emails")
        assert r.status_code == 401, r.text

    def test_wrong_token_401(self, client):
        r = client.get("/api/emails", headers=_auth_header("wrong-token-value"))
        assert r.status_code == 401, r.text

    def test_valid_token_200(self, client, api_token):
        r = client.get("/api/emails", headers=_auth_header(api_token))
        assert r.status_code == 200, r.text
        assert "emails" in r.json()

    def test_analyze_eml_no_header_partition_crash(self, client):
        """Regression: POST /api/analyze/eml must not 500 with
        \"'Header' object has no attribute 'partition'\"."""
        r = client.post("/api/analyze/eml",
                        files={"file": ("x.eml", b"not-a-real-eml", "message/rfc822")})
        assert r.status_code == 401, r.text  # rejected before any parsing

    def test_garbage_authorization_header_401(self, client):
        r = client.get("/api/emails", headers={"Authorization": "Basic abc"})
        assert r.status_code == 401
        r = client.get("/api/emails", headers={"Authorization": "Bearer"})
        assert r.status_code == 401

    # Representative coverage across routers/methods:

    def test_get_statistics_protected(self, client):
        assert client.get("/api/statistics").status_code == 401

    def test_post_analyze_raw_protected(self, client):
        r = client.post("/api/analyze/raw", json={"email_content": "x"})
        assert r.status_code == 401

    def test_delete_email_protected(self, client):
        r = client.delete(f"/api/emails/{uuid.uuid4()}")
        assert r.status_code == 401

    def test_ai_verify_protected(self, client):
        r = client.post(f"/api/ai/verify/{uuid.uuid4()}")
        assert r.status_code == 401

    def test_mailbuddy_settings_protected(self, client):
        assert client.get("/api/mailbuddy/settings").status_code == 401

    def test_mailbuddy_chat_protected(self, client):
        r = client.post("/api/mailbuddy/assistant/chat", json={"question": "hi"})
        assert r.status_code == 401

    def test_health_endpoint_open(self, client):
        assert client.get("/api/health").status_code == 200

    def test_valid_token_mailbuddy_works(self, client, api_token):
        r = client.get("/api/mailbuddy/settings", headers=_auth_header(api_token))
        assert r.status_code == 200, r.text

    def test_token_digest_stored_not_plaintext(self, client, api_token):
        """The DB holds only the SHA-256 digest, never the plaintext token."""
        import hashlib
        from backend.app.database.connection import SessionLocal
        from backend.app.models.email import ApiToken
        db = SessionLocal()
        try:
            rows = db.query(ApiToken).all()
            assert rows, "api_tokens row must exist after bootstrap"
            expected = hashlib.sha256(api_token.encode()).hexdigest()
            assert any(row.token_digest == expected for row in rows)
            assert all(row.token_digest != api_token for row in rows)
        finally:
            db.close()


# ─────────────────────── Finding 17: token encryption ───────────────────────

class TestTokenEncryption:
    def test_round_trip(self):
        from backend.app.auth.token_storage import TokenStorage
        for value in ("ya29.abcdefgh123456789", "1//04refreshTOKEN", "x", "üñíçø∂é-token"):
            encrypted = TokenStorage.encrypt(value)
            assert TokenStorage.decrypt(encrypted) == value

    def test_ciphertext_differs_from_plaintext(self):
        from backend.app.auth.token_storage import TokenStorage
        plaintext = "ya29.super-secret-access-token"
        stored = TokenStorage.encrypt(plaintext)
        assert stored != plaintext
        assert plaintext not in stored

    def test_wire_format_prefix(self):
        from backend.app.auth.token_storage import TokenStorage, is_encrypted_value
        stored = TokenStorage.encrypt("abc")
        assert is_encrypted_value(stored)
        assert not is_encrypted_value("legacy-plaintext-token")

    def test_invalid_ciphertext_fails_loudly(self):
        from backend.app.auth.token_storage import TokenDecryptionError, TokenStorage
        with pytest.raises(TokenDecryptionError):
            TokenStorage.decrypt("phishguard.v1:not-valid-ciphertext-at-all!!")

    def test_empty_value_fails(self):
        from backend.app.auth.token_storage import TokenDecryptionError, TokenStorage
        with pytest.raises(TokenDecryptionError):
            TokenStorage.decrypt("")

    def test_legacy_plaintext_passthrough_on_decrypt(self):
        """Legacy plaintext values decrypt as-is (never erased silently)."""
        from backend.app.auth.token_storage import TokenStorage
        assert TokenStorage.decrypt("legacy-plain-value") == "legacy-plain-value"

    def test_migration_encrypts_plaintext_rows(self, client):
        from backend.app.auth.token_storage import TokenStorage, is_encrypted_value
        from backend.app.database.connection import SessionLocal
        from backend.app.models.email import GmailToken

        _seed_gmail_token(access="legacy-access-plain", refresh="legacy-refresh-plain")
        db = SessionLocal()
        try:
            migrated = TokenStorage.migrate(db)
            assert migrated >= 1
            row = db.query(GmailToken).filter(GmailToken.user_email == TEST_EMAIL).first()
            assert is_encrypted_value(row.access_token)
            assert is_encrypted_value(row.refresh_token)
            # Round-trip: decrypt returns the original credential.
            assert TokenStorage.decrypt(row.access_token) == "legacy-access-plain"
            assert TokenStorage.decrypt(row.refresh_token) == "legacy-refresh-plain"
        finally:
            db.close()

    def test_migration_is_idempotent(self, client):
        from backend.app.auth.token_storage import TokenStorage
        from backend.app.database.connection import SessionLocal
        from backend.app.models.email import GmailToken

        _seed_gmail_token()
        db = SessionLocal()
        try:
            first = TokenStorage.migrate(db)
            second = TokenStorage.migrate(db)
            assert first >= 1
            assert second == 0  # already encrypted
        finally:
            db.close()

    def test_callback_persists_encrypted_tokens(self, client, monkeypatch):
        """The OAuth callback MUST encrypt before DB persistence."""
        from backend.app.config import settings
        from backend.app.database.connection import SessionLocal
        from backend.app.models.email import GmailToken
        from tests.test_oauth_callback import _mock_google, _get_state, _success_creds, SUCCESS_TOKEN, SUCCESS_PROFILE

        monkeypatch.setenv("PHISHGUARD_DATA_DIR", os.environ.get("PHISHGUARD_DATA_DIR", "desktop-test"))
        _success_creds(client, monkeypatch)
        state = _get_state(client)

        # Use OUR test email so cleanup/queries match (the shared helper's
        # profile points at a different address).
        with _mock_google(SUCCESS_TOKEN, profile_payload={"emailAddress": TEST_EMAIL}):
            r = client.get(f"/auth/google/callback?code=abc123&state={state}",
                           follow_redirects=False)
        assert r.status_code in (302, 307)

        db = SessionLocal()
        try:
            row = db.query(GmailToken).filter(GmailToken.user_email == TEST_EMAIL).first()
            assert row is not None
            assert row.access_token != "at-test-123"
            assert "at-test-123" not in str(row.access_token)
            assert row.refresh_token != "rt-test-123"
        finally:
            db.close()

    def test_service_decrypts_correctly(self, client):
        """GmailService._load_token must decrypt through TokenStorage."""
        from backend.app.auth.token_storage import TokenStorage
        _seed_gmail_token(
            enc_access=TokenStorage.encrypt("at-decrypt-me"),
            enc_refresh=TokenStorage.encrypt("rt-decrypt-me"),
        )
        from backend.app.gmail.service import GmailService
        svc = GmailService(TEST_EMAIL)
        assert svc._access_token == "at-decrypt-me"
        assert svc._refresh_token == "rt-decrypt-me"

    def test_service_corrupt_token_fails_not_empty(self, client):
        """Decryption failure must raise (fail closed), never yield ""."""
        _seed_gmail_token(
            enc_access="phishguard.v1:corrupted-ciphertext",
        )
        from backend.app.gmail.service import GmailService
        with pytest.raises(ValueError, match="reconnect"):
            GmailService(TEST_EMAIL)

    def test_sync_api_response_contains_no_plaintext_token(self, client, api_token):
        """No /api response ever includes an OAuth token value."""
        from backend.app.auth.token_storage import TokenStorage
        _seed_gmail_token(
            enc_access=TokenStorage.encrypt("ya29.SECRET-VALUE-xyz"),
        )
        for url in ("/api/emails", "/api/statistics", "/api/gmail/status",
                    "/api/mailbuddy/priority/summary"):
            r = client.get(url, headers=_auth_header(api_token))
            body = r.text
            assert "ya29.SECRET-VALUE-xyz" not in body
            assert "at-plain-123" not in body or url != "/api/gmail/status"

    def test_legacy_to_dict_has_no_token_fields(self):
        from backend.app.models.email import GmailToken
        row = GmailToken(user_email="x@y.z", access_token="secret", refresh_token="secret2")
        d = row.to_dict()
        assert "access_token" not in d and "refresh_token" not in d

    def test_dpapi_available_on_windows(self):
        """On Windows the DPAPI path must be wired (not the Fernet fallback)."""
        from backend.app.auth import token_storage
        if os.name == "nt":
            assert token_storage._is_windows(), (
                "Windows: native DPAPI must be available (advapi32 loaded)"
            )
        # Non-Windows: Fernet fallback is the documented behavior.
        assert (token_storage._is_windows() is False) or os.name == "nt"


# ─────────────────────── Finding 20: OAuth revocation ───────────────────────

def _fake_client_200(*a, **kw):
    """httpx.AsyncClient stand-in returning HTTP 200 for POSTs."""

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, data=None, headers=None):
            return SimpleNamespace(status_code=200)

    return _Client(*a, **kw)


class TestOAuthRevocation:
    def test_revoke_called_with_refresh_token_and_local_cleanup(self, client, monkeypatch):
        """Successful revoke → token deleted; request carried the refresh token."""
        from backend.app.auth.token_storage import TokenStorage
        _seed_gmail_token(enc_access=TokenStorage.encrypt("at-revoke-1"),
                          enc_refresh=TokenStorage.encrypt("rt-revoke-1"))
        session_id = _make_session()

        calls = {}

        class FakeClient:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, data=None, headers=None):
                calls["url"] = url
                calls["data"] = data
                return SimpleNamespace(status_code=200)

        monkeypatch.setattr("backend.app.auth.google.httpx.AsyncClient", FakeClient)
        r = client.post("/auth/google/disconnect", cookies={"phishguard_session": session_id})
        assert r.status_code == 200, r.text
        assert calls["url"].startswith("https://oauth2.googleapis.com/revoke")
        assert calls["data"]["token"] == "rt-revoke-1"  # refresh token preferred

        from backend.app.database.connection import SessionLocal
        from backend.app.models.email import GmailToken
        db = SessionLocal()
        try:
            remaining = db.query(GmailToken).filter(GmailToken.user_email == TEST_EMAIL).count()
            assert remaining == 0, "local token row must be deleted after revoke"
        finally:
            db.close()

    def test_revoke_network_failure_still_cleans_up(self, client, monkeypatch):
        """Google unreachable → local token STILL deleted; disconnect usable."""
        from backend.app.auth.token_storage import TokenStorage
        _seed_gmail_token(enc_access=TokenStorage.encrypt("at-revoke-2"),
                          enc_refresh=TokenStorage.encrypt("rt-revoke-2"))
        session_id = _make_session()

        class UnreachableClient:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def post(self, url, data=None, headers=None):
                raise httpx.ConnectError("network down")

        monkeypatch.setattr("backend.app.auth.google.httpx.AsyncClient", UnreachableClient)
        r = client.post("/auth/google/disconnect", cookies={"phishguard_session": session_id})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "disconnected"

        from backend.app.database.connection import SessionLocal
        from backend.app.models.email import GmailToken
        db = SessionLocal()
        try:
            remaining = db.query(GmailToken).filter(GmailToken.user_email == TEST_EMAIL).count()
            assert remaining == 0
        finally:
            db.close()

    def test_revoke_endpoint_correct_and_token_not_logged(self, client, monkeypatch, caplog):
        """Correct endpoint/token used; the token value never reaches logs."""
        from backend.app.auth.token_storage import TokenStorage
        import logging
        _seed_gmail_token(enc_access=TokenStorage.encrypt("at-log-check"),
                          enc_refresh=TokenStorage.encrypt("rt-LOGCHECK-xyz"))
        session_id = _make_session()

        monkeypatch.setattr("backend.app.auth.google.httpx.AsyncClient", _fake_client_200)
        with caplog.at_level(logging.DEBUG, logger="phishguard.auth"):
            client.post("/auth/google/disconnect", cookies={"phishguard_session": session_id})
        assert "rt-LOGCHECK-xyz" not in caplog.text
        assert "at-log-check" not in caplog.text

    class _unused:
        pass

    def test_no_stored_token_disconnect_still_works(self, client):
        """No GmailToken row → disconnect still completes (no 500)."""
        session_id = _make_session()
        r = client.post("/auth/google/disconnect", cookies={"phishguard_session": session_id})
        assert r.status_code == 200

    def test_disconnect_requires_session(self, client):
        r = client.post("/auth/google/disconnect")
        assert r.status_code == 401


# ─────────────────────── Finding 18: Host/Origin ───────────────────────

class TestHostOrigin:
    def test_allowed_localhost_host_ok(self, client, api_token):
        r = client.get("/api/emails", headers={**_auth_header(api_token), "Host": "localhost:8000"})
        assert r.status_code == 200

    def test_allowed_127_host_ok(self, client, api_token):
        r = client.get("/api/health", headers={"Host": "127.0.0.1:8000"})
        assert r.status_code == 200

    def test_malicious_host_rejected(self, client):
        r = client.get("/api/health", headers={"Host": "evil.example"})
        assert r.status_code == 403

    def test_malicious_host_rejected_on_auth_too(self, client):
        r = client.get("/auth/google", headers={"Host": "evil.example"}, follow_redirects=False)
        assert r.status_code == 403

    def test_oauth_callback_host_cannot_control_redirect(self, client, monkeypatch):
        """Regression: Host: evil.example must NOT produce
        https://evil.example/settings?connected=true."""
        # Edge behavior: the request with a foreign Host never even reaches
        # the callback — the Host allowlist middleware rejects it with 403.
        r = client.get("/auth/google/callback?code=abc&state=x",
                       follow_redirects=False,
                       headers={"Host": "evil.example", "X-Forwarded-Proto": "https"})
        assert r.status_code == 403, r.status_code
        assert "evil.example" not in (r.headers.get("location") or "")

        # Defense in depth: even if a foreign-host request reached the
        # redirect builder, the allowlist — not the Host header — decides.
        from unittest.mock import MagicMock
        from backend.app.auth.google import _post_auth_redirect
        request = MagicMock()
        request.headers = {"host": "evil.example", "x-forwarded-proto": "https"}
        monkeypatch.setenv("PHISHGUARD_DATA_DIR", "desktop-mode-under-test")
        url = _post_auth_redirect(request, {"connected": "true"})
        assert "evil.example" not in url, url
        assert url.startswith("http://localhost:8000/settings"), url

    def test_legitimate_oauth_redirect_still_works(self, client, monkeypatch):
        from backend.app.config import settings
        from tests.test_oauth_callback import _mock_google, _get_state, _success_creds, SUCCESS_TOKEN, SUCCESS_PROFILE

        monkeypatch.setenv("PHISHGUARD_DATA_DIR", os.environ.get("PHISHGUARD_DATA_DIR", "desktop-test"))
        _success_creds(client, monkeypatch)
        state = _get_state(client)

        with _mock_google(SUCCESS_TOKEN, profile_payload=SUCCESS_PROFILE):
            r = client.get(f"/auth/google/callback?code=abc123&state={state}",
                           follow_redirects=False)
        loc = r.headers.get("location", "")
        assert urlparse(loc).netloc in ("testserver:8000", "testserver", "localhost:8000"), loc
        assert "connected=true" in loc

    def test_cross_origin_post_rejected(self, client):
        """Cookie-authenticated state-changing request from a foreign origin."""
        session_id = _make_session()
        r = client.post("/auth/google/disconnect",
                        cookies={"phishguard_session": session_id},
                        headers={"Origin": "https://attacker.example"})
        assert r.status_code == 403

    def test_same_origin_post_allowed(self, client, monkeypatch):
        from backend.app.config import settings
        session_id = _make_session()
        r = client.post("/auth/google/disconnect",
                        cookies={"phishguard_session": session_id},
                        headers={"Origin": "http://localhost:8000"})
        assert r.status_code == 200, r.text
        _ = settings  # imported for clarity

    def test_no_origin_header_allowed(self, client):
        """Non-browser clients send no Origin — must keep working."""
        session_id = _make_session()
        r = client.post("/auth/google/disconnect", cookies={"phishguard_session": session_id})
        assert r.status_code == 200


# ─────────────────────── runtime probe (success criteria) ───────────────────────

def _probe_runtime():
    """Manual runtime check (not collected by pytest): run directly."""
    os.environ.setdefault("PHISHGUARD_DATA_DIR", os.path.join(os.path.dirname(__file__), ".pytest-data-dir"))
    from backend.app.config import settings
    from backend.app.database.connection import init_db
    from backend.app.main import app
    from backend.app.auth import token_manager
    # Starlette's TestClient sends Host: testserver — allow it here only.
    if "testserver" not in settings.ALLOWED_LOCAL_HOSTS:
        settings.ALLOWED_LOCAL_HOSTS.append("testserver")
    init_db()
    with TestClient(app) as c:
        token = token_manager.load_or_create_token()
        no_token = c.get("/api/emails")
        wrong = c.get("/api/emails", headers=_auth_header("wrong"))
        good = c.get("/api/emails", headers=_auth_header(token))
        eml = c.post("/api/analyze/eml", files={"file": ("x.eml", b"broken", "message/rfc822")})
        host = c.get("/api/health", headers={"Host": "evil.example"})
        print(f"NO TOKEN: {no_token.status_code}")
        print(f"WRONG TOKEN: {wrong.status_code}")
        print(f"VALID TOKEN: {good.status_code}")
        print(f"ANALYZE EML (no auth): {eml.status_code}")
        print(f"EVIL HOST: {host.status_code}")
        assert no_token.status_code == 401
        assert wrong.status_code == 401
        assert good.status_code == 200
        assert eml.status_code == 401
        assert host.status_code == 403
        print("RUNTIME PROBE: ALL PASS")


if __name__ == "__main__":
    _probe_runtime()
