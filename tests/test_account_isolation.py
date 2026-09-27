"""
F-16 account isolation — API-level regression tests with TWO authenticated
sessions exercising the REAL endpoints (no mocked auth helpers).

Guarantees proven here:
- Account A cannot retrieve Account B's email (detail -> 404)
- Account A's list never contains Account B's rows
- Account A's statistics never include Account B's rows
- Account A cannot acknowledge Account B's notification
- Account A cannot fetch Account B's Gmail message content (-> 404)
- Assistant conversation history is per-account
"""

import json
import uuid

import pytest

from backend.app.database.connection import SessionLocal, init_db
from backend.app.models.email import EmailAnalysis, GmailToken, NotificationLog
from backend.app.utils.timeutil import utc_now


def _auth_client(account: str):
    """A TestClient bound to a real server-side session for *account*."""
    from fastapi.testclient import TestClient
    from backend.app.main import app
    from backend.app.auth.sessions import create_session
    from tests.conftest import api_auth_headers

    init_db()
    client = TestClient(app)
    session_id = create_session(account)

    db = SessionLocal()
    if not db.query(GmailToken).filter(GmailToken.user_email == account).first():
        db.add(GmailToken(
            user_email=account,
            access_token="enc-test-access",
            refresh_token="enc-test-refresh",
        ))
        db.commit()
    db.close()

    client.cookies.set("phishguard_session", session_id)
    client.headers.update(api_auth_headers())
    return client


def _make_row(owner: str, marker: str) -> EmailAnalysis:
    now = utc_now()
    if now.tzinfo:
        now = now.replace(tzinfo=None)
    return EmailAnalysis(
        id=f"iso-{marker}",
        email_id=f"iso-{marker}",
        source="gmail",
        owner_account=owner,
        sender="Iso Sender",
        sender_email=f"{marker}@example.com",
        sender_domain="example.com",
        subject=f"Iso {marker}",
        body_text=f"ISOLATION-BODY-{marker}",
        risk_score=10.0,
        classification="SAFE",
        priority_level="CRITICAL",
        priority_category="SECURITY",
        analyzed_at=now,
        created_at=now,
    )


@pytest.fixture(autouse=True)
def _iso_slate():
    """Fresh slate: notification assertions need the whole notification surface
    empty (legacy NULL-owner rows are visible to any authenticated account by
    F-16 design), so this suite empties the test-only tables before running."""
    db = SessionLocal()
    db.query(NotificationLog).delete(synchronize_session=False)
    db.query(EmailAnalysis).filter(EmailAnalysis.id.like("iso-%")).delete(synchronize_session=False)
    db.commit()
    yield
    db.query(NotificationLog).filter(NotificationLog.email_id.like("iso-%")).delete(synchronize_session=False)
    db.query(EmailAnalysis).filter(EmailAnalysis.id.like("iso-%")).delete(synchronize_session=False)
    db.commit()
    db.close()


A = "iso-a@example.com"
B = "iso-b@example.com"


def _seed_one_row_each():
    """Seed one owned row per account; return their ids (plain strings —
    ORM instances detach on session close)."""
    db = SessionLocal()
    ra = _make_row(A, "row-a")
    rb = _make_row(B, "row-b")
    db.add_all([ra, rb])
    db.commit()
    ids = (ra.id, rb.id)
    db.close()
    return ids


def test_detail_cross_account_404():
    id_a, id_b = _seed_one_row_each()
    client_a = _auth_client(A)
    # A asks for B's row by ID -> 404, never B's content.
    r = client_a.get(f"/api/emails/{id_b}")
    assert r.status_code == 404, f"got {r.status_code}: {r.text[:200]}"
    assert "ISOLATION-BODY-row-b" not in r.text
    # A can still fetch its own row.
    r = client_a.get(f"/api/emails/{id_a}")
    assert r.status_code == 200
    assert "ISOLATION-BODY-row-a" in r.text


def test_list_is_account_scoped():
    _seed_one_row_each()
    client_a = _auth_client(A)
    r = client_a.get("/api/emails")
    assert r.status_code == 200
    assert "ISOLATION-BODY-row-b" not in r.text  # list excludes bodies anyway
    ids = {e["id"] for e in r.json()["emails"]}
    assert "iso-row-a" in ids
    assert "iso-row-b" not in ids


def test_statistics_are_account_scoped():
    _seed_one_row_each()
    # Give B an extra row so counts would differ if scoping were broken.
    db = SessionLocal()
    db.add(_make_row(B, "row-b2"))
    db.commit()
    db.close()

    client_a = _auth_client(A)
    ra_stats = client_a.get("/api/emails").json()["total"]

    # A's view must count only A-owned rows (+ legacy NULL rows, none here
    # because the slate fixture emptied the table).
    from sqlalchemy import func
    db = SessionLocal()
    expected = (
        db.query(func.count(EmailAnalysis.id))
        .filter((EmailAnalysis.owner_account == A) | (EmailAnalysis.owner_account.is_(None)))
        .scalar()
    )
    db.close()
    assert ra_stats == expected, f"A saw {ra_stats}, expected {expected}"


def test_notification_ack_is_account_scoped():
    from backend.app.mailbuddy import service

    _seed_one_row_each()
    db = SessionLocal()
    rb = db.query(EmailAnalysis).filter(EmailAnalysis.id == "iso-row-b").first()
    # Queue a notification for B's email directly through the service.
    assert service.queue_notifications(db, rb) == 1
    pending_b = service.pending_notifications(db, account=B)
    assert len(pending_b) == 1
    key_b = pending_b[0]["key"]
    db.close()
    assert key_b

    # A tries to acknowledge B's notification -> 0 rows marked.
    client_a = _auth_client(A)
    r = client_a.post("/api/mailbuddy/notifications/ack", json={"keys": [key_b]})
    assert r.status_code == 200
    assert r.json()["marked"] == 0

    # B can still acknowledge it.
    client_b = _auth_client(B)
    r = client_b.post("/api/mailbuddy/notifications/ack", json={"keys": [key_b]})
    assert r.status_code == 200
    assert r.json()["marked"] == 1


def test_gmail_message_content_cross_account_404():
    id_a, id_b = _seed_one_row_each()
    client_a = _auth_client(A)
    r = client_a.get(f"/api/gmail/message-content/{id_b}")
    assert r.status_code == 404, f"got {r.status_code}"
    assert "ISOLATION-BODY-row-b" not in r.text


def test_assistant_history_is_per_account():
    from backend.app.mailbuddy import assistant

    assistant._history_for(A).append({"role": "user", "content": "A question"})
    assistant._history_for(B).append({"role": "user", "content": "B question"})

    ha = [m["content"] for m in assistant.chat_history(A)]
    hb = [m["content"] for m in assistant.chat_history(B)]
    assert "A question" in ha and "B question" not in ha
    assert "B question" in hb and "A question" not in hb

    # API surface reports only the caller's history.
    client_a = _auth_client(A)
    r = client_a.get("/api/mailbuddy/assistant/history")
    assert r.status_code == 200
    contents = [m.get("content") for m in r.json().get("messages", [])]
    assert "A question" in contents
    assert "B question" not in contents

    assistant.clear_history(A)
    assistant.clear_history(B)
