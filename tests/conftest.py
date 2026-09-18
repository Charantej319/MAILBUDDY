"""
Shared pytest fixtures.

AI/Groq isolation: backend/.env may carry a real GROQ_API_KEY and
AI_PROVIDER=groq. Automated tests must NEVER call the real Groq API and must
NEVER depend on locally configured credentials, so every AI/Groq environment
variable is removed before each test. Tests that need a provider configure it
explicitly with mocked/fake endpoints.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

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
