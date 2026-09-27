"""
Tests for old-email detail content retrieval (Phase: old email bodies).

Older Gmail analyses have no stored body. The detail flow must:
- Detect missing bodies and fetch them from Gmail on demand using the
  existing server-side session/token
- Only fetch messages that were ALREADY analyzed (ID resolved from the
  stored row, never from user input)
- Never create duplicate analysis records
- Never modify the deterministic analysis result
- Fall back to a clear unavailable message when Gmail is unavailable
"""

import sys
import os
import json
import uuid
from unittest.mock import patch, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.app.database.connection import SessionLocal
from backend.app.models.email import EmailAnalysis
from backend.app.utils.timeutil import utc_now
from backend.app.parser.email_parser import ParsedEmail


def _seed(db, **overrides):
    row = EmailAnalysis(
        id=str(uuid.uuid4()),
        email_id=f"old-{uuid.uuid4()}",
        source="gmail",
        sender="Old Sender",
        sender_email="old@example.com",
        sender_domain="example.com",
        subject="Old email without body",
        risk_score=30.0,
        classification="LOW RISK",
        confidence_level="MEDIUM",
        confidence_numeric=0.5,
        detection_findings=json.dumps([]),
        extracted_urls=json.dumps([]),
        attachment_info=json.dumps([]),
        header_findings=json.dumps([]),
        analyzed_at=utc_now(),
        created_at=utc_now(),
    )
    for k, v in overrides.items():
        setattr(row, k, v)
    db.add(row)
    db.commit()
    return row


def _auth_client(app):
    """TestClient with a phishguard_session cookie for a seeded user."""
    from fastapi.testclient import TestClient
    from backend.app.database.connection import init_db
    init_db()  # ensure oauth_sessions/gmail_tokens tables exist
    from backend.app.auth.sessions import create_session
    from backend.app.models.email import GmailToken
    from tests.conftest import api_auth_headers

    client = TestClient(app)
    user = f"content-test-{uuid.uuid4()}@example.com"
    session_id = create_session(user)

    # Seed a Gmail token so GmailService(user) resolves (fetch is mocked).
    db = SessionLocal()
    db.add(GmailToken(
        user_email=user,
        access_token="test-access-token",
        refresh_token="test-refresh-token",
    ))
    db.commit()
    db.close()

    client.cookies.set("phishguard_session", session_id)
    # /api routes require the local bearer token (Finding 15).
    client.headers.update(api_auth_headers())
    return client, user, session_id


def test_new_email_with_body_needs_no_fetch():
    """A newly synced email (body stored) returns cached content immediately."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    db = SessionLocal()
    row = _seed(db, body_text="Fresh body", body_html="<p>Fresh</p>")
    client, user, session_id = _auth_client(app)
    try:
        resp = client.get(f"/api/gmail/message-content/{row.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is True
        assert data["cached"] is True
        assert data["body_text"] == "Fresh body"
        # No extra rows created
        count = db.query(EmailAnalysis).filter(EmailAnalysis.id == row.id).count()
        assert count == 1
    finally:
        db.delete(row)
        db.commit()
        db.close()
    print("[PASS]  test_new_email_with_body_needs_no_fetch passed")


def test_old_email_body_refetched_without_duplicates():
    """
    Old email without body: content is fetched from Gmail, stored on the
    EXISTING row, and the analysis result is untouched.
    """
    from fastapi.testclient import TestClient
    from backend.app.main import app

    db = SessionLocal()
    row = _seed(db, risk_score=55.0, classification="SUSPICIOUS")
    original_analyzed_at = row.analyzed_at
    client, user, session_id = _auth_client(app)

    parsed = ParsedEmail(
        sender="Old Sender <old@example.com>",
        sender_email="old@example.com",
        sender_domain="example.com",
        subject="Old email without body",
        body_text="Recovered body text",
        body_html="<html><body><p>Recovered HTML</p></body></html>",
    )

    async def fake_fetch(message_id):
        assert message_id == row.email_id  # uses the STORED Gmail message ID
        return {"id": message_id, "threadId": "t1"}, parsed

    try:
        with patch("backend.app.gmail.api.GmailService") as MockService:
            MockService.return_value.fetch_and_parse = AsyncMock(side_effect=fake_fetch)
            resp = client.get(f"/api/gmail/message-content/{row.id}")

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["available"] is True
        assert data["cached"] is False
        assert data["body_text"] == "Recovered body text"

        db.refresh(row)
        # Same single record, same analysis, only body fields filled in
        assert row.body_text == "Recovered body text"
        assert row.risk_score == 55.0  # analysis untouched
        assert row.classification == "SUSPICIOUS"
        assert row.analyzed_at == original_analyzed_at
        total = db.query(EmailAnalysis).filter(EmailAnalysis.email_id == row.email_id).count()
        assert total == 1, "Duplicate analysis record created!"
    finally:
        db.delete(row)
        db.commit()
        db.close()
    print("[PASS]  test_old_email_body_refetched_without_duplicates passed")


def test_old_email_gmail_unavailable_fallback():
    """When Gmail is unreachable, a safe fallback message is returned."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    db = SessionLocal()
    row = _seed(db)
    client, user, session_id = _auth_client(app)

    async def fake_fetch(message_id):
        raise OSError("network down")

    try:
        with patch("backend.app.gmail.api.GmailService") as MockService:
            MockService.return_value.fetch_and_parse = AsyncMock(side_effect=fake_fetch)
            resp = client.get(f"/api/gmail/message-content/{row.id}")

        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is False
        assert data["message"] == "Email content is currently unavailable. The stored security analysis is still available."

        db.refresh(row)
        assert not row.body_text and not row.body_html  # nothing fabricated
    finally:
        db.delete(row)
        db.commit()
        db.close()
    print("[PASS]  test_old_email_gmail_unavailable_fallback passed")


def test_old_email_deleted_from_gmail_fallback():
    """404 from Gmail (message gone) → unavailable, no crash, no fabrication."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    db = SessionLocal()
    row = _seed(db)
    client, user, session_id = _auth_client(app)

    async def fake_fetch(message_id):
        raise Exception("404 message not found")

    try:
        with patch("backend.app.gmail.api.GmailService") as MockService:
            MockService.return_value.fetch_and_parse = AsyncMock(side_effect=fake_fetch)
            resp = client.get(f"/api/gmail/message-content/{row.id}")

        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is False
        assert "unavailable" in data["message"].lower()
    finally:
        db.delete(row)
        db.commit()
        db.close()
    print("[PASS]  test_old_email_deleted_from_gmail_fallback passed")


def test_message_content_requires_session():
    """No session cookie → 401; tokens are never exposed."""
    from fastapi.testclient import TestClient
    from backend.app.main import app
    from tests.conftest import api_auth_headers

    db = SessionLocal()
    row = _seed(db)
    client = TestClient(app)  # no cookie
    client.headers.update(api_auth_headers())  # bearer OK, session still required
    try:
        resp = client.get(f"/api/gmail/message-content/{row.id}")
        assert resp.status_code == 401
        body = resp.json()
        assert "token" not in json.dumps(body).lower()
        assert "access_token" not in json.dumps(body).lower()
    finally:
        db.delete(row)
        db.commit()
        db.close()
    print("[PASS]  test_message_content_requires_session passed")


def test_message_content_non_gmail_source_rejected():
    """.eml analyses have no Gmail message; endpoint must not pretend."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    db = SessionLocal()
    row = _seed(db, source="eml", body_text=None, body_html=None)
    client, user, session_id = _auth_client(app)
    try:
        resp = client.get(f"/api/gmail/message-content/{row.id}")
        assert resp.status_code == 404
    finally:
        db.delete(row)
        db.commit()
        db.close()
    print("[PASS]  test_message_content_non_gmail_source_rejected passed")


def test_full_flow_old_email_then_display():
    """
    End-to-end shape check: list → detail (no body) → content fetch →
    detail now has body. Verifies the UI data contract at each step.
    """
    from fastapi.testclient import TestClient
    from backend.app.main import app

    db = SessionLocal()
    row = _seed(db)
    client, user, session_id = _auth_client(app)

    parsed = ParsedEmail(
        sender="Old Sender <old@example.com>",
        sender_email="old@example.com",
        sender_domain="example.com",
        subject="Old email without body",
        body_text="E2E recovered body",
    )

    async def fake_fetch(message_id):
        return {"id": message_id}, parsed

    try:
        # 1. Detail initially has no body
        detail = client.get(f"/api/emails/{row.id}").json()
        assert not detail["body_text"] and not detail["body_html"]
        assert detail["ai"] is not None  # AI block always present

        # 2. Content fetch
        with patch("backend.app.gmail.api.GmailService") as MockService:
            MockService.return_value.fetch_and_parse = AsyncMock(side_effect=fake_fetch)
            content = client.get(f"/api/gmail/message-content/{row.id}").json()
        assert content["available"] is True

        # 3. Detail now serves the body
        detail2 = client.get(f"/api/emails/{row.id}").json()
        assert detail2["body_text"] == "E2E recovered body"
        # Analysis fields unchanged
        assert detail2["risk_score"] == 30.0
    finally:
        db.delete(row)
        db.commit()
        db.close()
    print("[PASS]  test_full_flow_old_email_then_display passed")


if __name__ == '__main__':
    test_new_email_with_body_needs_no_fetch()
    test_old_email_body_refetched_without_duplicates()
    test_old_email_gmail_unavailable_fallback()
    test_old_email_deleted_from_gmail_fallback()
    test_message_content_requires_session()
    test_message_content_non_gmail_source_rejected()
    test_full_flow_old_email_then_display()
    print("\nAll old-email content tests passed!")
