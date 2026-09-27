"""
Shared pytest fixtures.

AI/Groq isolation: backend/.env may carry a real GROQ_API_KEY and
AI_PROVIDER=groq. Automated tests must NEVER call the real Groq API and must
NEVER depend on locally configured credentials, so every AI/Groq environment
variable is removed before each test. Tests that need a provider configure it
explicitly with mocked/fake endpoints.
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest


# ── Test-client Host allowlist ───────────────────────────────────────
# Starlette's TestClient sends Host: testserver. The app's Host allowlist
# middleware rejects unknown hosts, so tests register the testserver host as
# an allowed local host. Production behavior is unchanged (this runs only
# under pytest because conftest.py is loaded before any backend import).
if "PYTEST_CURRENT_TEST" not in os.environ:  # collection time under pytest
    os.environ.setdefault("PYTEST_RUN", "1")


def _register_testserver_host():
    from backend.app.config import settings
    if "testserver" not in settings.ALLOWED_LOCAL_HOSTS:
        settings.ALLOWED_LOCAL_HOSTS.append("testserver")


@pytest.fixture(scope="session", autouse=True)
def _allow_testserver_host():
    _register_testserver_host()

# ── Test-database isolation ─────────────────────────────────────────
# backend/phishguard.db is the developer's real database. pytest must never
# read or write it. backend.app.config resolves DATABASE_URL at import time
# from PHISHGUARD_DATA_DIR, so the override has to be in place before any
# backend import — which session-scoped fixtures guarantee only AFTER module
# collection. Therefore the env var is set here, at conftest import time,
# before the first test module imports the backend package.
_DEV_DB = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "backend", "phishguard.db")
)
if not os.environ.get("PHISHGUARD_DATA_DIR"):
    os.environ["PHISHGUARD_DATA_DIR"] = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".pytest-data-dir"
    )
    os.makedirs(os.environ["PHISHGUARD_DATA_DIR"], exist_ok=True)


@pytest.fixture(scope="session", autouse=True)
def _guard_dev_database():
    """Fail the suite if the real backend/phishguard.db was modified.

    Hashed before and after the session; a change means a test wrote to the
    developer database and must be fixed, not tolerated. WAL/SHM sidecars are
    not part of the database content and are ignored.
    """
    def _digest():
        if not os.path.exists(_DEV_DB):
            return None
        h = hashlib.sha256()
        with open(_DEV_DB, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    before = _digest()
    yield
    after = _digest()
    assert before == after, (
        "REGRESSION: backend/phishguard.db changed during the test suite "
        f"({before} -> {after}). Tests must use the isolated PHISHGUARD_DATA_DIR "
        "database, never the developer database."
    )

AI_ENV_VARS = (
    "AI_ENABLED",
    "AI_PROVIDER",
    "AI_MODEL",
    "GROQ_API_KEY",
    "PHISHGUARD_AI_PROVIDER",
    "PHISHGUARD_AI_ENDPOINT",
    "PHISHGUARD_AI_MODEL",
    "PHISHGUARD_AI_API_KEY",
    "PHISHGUARD_AI_TIMEOUT",
)


@pytest.fixture(autouse=True)
def _isolate_ai_env(monkeypatch):
    """Remove every AI/Groq env var for the duration of each test.

    importing backend.app.config triggers load_dotenv(backend/.env), which may
    place a real GROQ_API_KEY into os.environ. monkeypatch.delenv restores the
    original value (if any) after the test, so the real key is never mutated.
    """
    for var in AI_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    yield


def _ai_env(**values):
    """Return a pytest monkeypatch callback that sets AI env vars for a test."""
    def _apply(monkeypatch):
        for key, val in values.items():
            monkeypatch.setenv(key, val)
    return _apply


# ── Local API bearer-token helper ───────────────────────────────────
# /api routes require the local bearer token (Finding 15). Tests that call
# protected endpoints use this helper to authenticate — exercising the real
# auth path instead of bypassing it.


def api_auth_headers() -> dict:
    """Authorization header with the active local API token."""
    from backend.app.auth import token_manager
    token = token_manager.load_or_create_token()
    assert token, "API token bootstrap failed; cannot authenticate test client"
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def db_session():
    """Real database session for MailBuddy tests, with cleanup of test rows.

    Test rows are identified by the 'mb-' email_id/id prefix convention so
    real user data is never touched.
    """
    from backend.app.database.connection import SessionLocal, init_db
    from backend.app.models.email import EmailAnalysis, NotificationLog, AppSetting
    from sqlalchemy import text as _text

    init_db()
    db = SessionLocal()
    yield db
    try:
        db.rollback()
        db.query(EmailAnalysis).filter(
            (EmailAnalysis.email_id.like("mb-%")) | (EmailAnalysis.id.like("mb-%"))
        ).delete(synchronize_session=False)
        db.query(NotificationLog).filter(NotificationLog.email_id.like("mb-%")).delete(synchronize_session=False)
        db.query(AppSetting).filter(AppSetting.key == "assistant_enabled").delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
