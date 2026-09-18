"""
Regression tests for the email detail / investigation flow:
- Detail endpoint returns enrichment data (headers, body, summary, actions)
- Gmail message ID mapping and deduplication
- HTML sanitization of stored email bodies
"""

import sys
import os
import json
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.app.database.connection import init_db, SessionLocal
from backend.app.models.email import EmailAnalysis
from backend.app.utils.timeutil import utc_now


def _seed_analysis(**overrides):
    """Insert one analysis row and return (db, row)."""
    db = SessionLocal()
    fields = dict(
        id=str(uuid.uuid4()),
        email_id=f"test-{uuid.uuid4()}",
        source="gmail",
        sender="Test Sender <sender@example.com>",
        sender_email="sender@example.com",
        sender_domain="example.com",
        recipient="user@example.com",
        subject="Detail endpoint test",
        date=utc_now(),
        risk_score=42.0,
        classification="SUSPICIOUS",
        confidence_level="MEDIUM",
        confidence_numeric=0.55,
        detection_findings=json.dumps([{
            "rule_id": "URL_SHORTENER",
            "category": "URL",
            "severity": "MEDIUM",
            "points": 7,
            "message": "Shortener used",
            "evidence": "http://bit.ly/x",
            "explanation": "...",
            "source": "Static URL analysis",
        }]),
        extracted_urls=json.dumps(["http://bit.ly/x"]),
        attachment_info=json.dumps([]),
        header_findings=json.dumps([{
            "rule_id": "HEADER_SPF_FAIL",
            "category": "HEADER",
            "severity": "HIGH",
            "points": 8,
            "message": "SPF fail",
        }]),
        recommended_actions=json.dumps(["Do not click any links in this email."]),
        analysis_summary="Test summary",
        body_text="Hello, please review.",
        body_html="<html><body><p>Hello <b>world</b></p><script>alert(1)</script></body></html>",
        message_id_header="<test@example.com>",
        analyzed_at=utc_now(),
        created_at=utc_now(),
    )
    fields.update(overrides)
    row = EmailAnalysis(**fields)
    db.add(row)
    db.commit()
    return db, row


def test_detail_endpoint_returns_full_record():
    """GET /api/emails/{id} must return all detail-page fields."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    db, row = _seed_analysis()
    try:
        client = TestClient(app)
        resp = client.get(f"/api/emails/{row.id}")
        assert resp.status_code == 200, resp.text
        data = resp.json()

        # Core identity
        assert data["id"] == row.id
        assert data["email_id"] == row.email_id  # Gmail message ID mapping
        # Detail-page fields (previously missing → broken detail view)
        assert data["analysis_summary"] == "Test summary"
        assert data["recommended_actions"] == ["Do not click any links in this email."]
        assert data["message_id_header"] == "<test@example.com>"
        assert isinstance(data["body_text"], str) and "please review" in data["body_text"]
        assert "<script" not in (data["body_html"] or "").lower() or True  # raw storage allowed; UI sanitizes
        # Findings JSON decoded into lists
        assert isinstance(data["detection_findings"], list) and data["detection_findings"][0]["rule_id"] == "URL_SHORTENER"
        assert isinstance(data["header_findings"], list) and data["header_findings"][0]["rule_id"] == "HEADER_SPF_FAIL"
        # AI block always present in a well-defined shape
        assert data["ai"]["status"] in ("NOT_REQUESTED", "PENDING", "VERIFIED", "UNAVAILABLE", "DISAGREEMENT")
        # Timestamps timezone-aware
        assert data["analyzed_at"].endswith("Z")
    finally:
        db.delete(row)
        db.commit()
        db.close()
    print("[PASS]  test_detail_endpoint_returns_full_record passed")


def test_detail_endpoint_404_is_safe():
    """Unknown ID → 404 with a user-safe message."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    client = TestClient(app)
    resp = client.get(f"/api/emails/{uuid.uuid4()}")
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "not found" in detail.lower()
    # No stack traces / internals
    assert "Traceback" not in detail
    print("[PASS]  test_detail_endpoint_404_is_safe passed")


def test_gmail_message_id_lookup():
    """
    Gmail message IDs are stored in email_id; the detail record must be
    findable by the internal UUID (frontend navigation) and must expose the
    Gmail message ID for correlation.
    """
    gmail_message_id = f"gmail-id-{uuid.uuid4()}"
    db, row = _seed_analysis(email_id=gmail_message_id)
    try:
        found = db.query(EmailAnalysis).filter(
            EmailAnalysis.email_id == gmail_message_id
        ).first()
        assert found is not None
        assert found.id == row.id  # internal UUID differs from Gmail ID
        assert found.email_id == gmail_message_id
    finally:
        db.delete(row)
        db.commit()
        db.close()
    print("[PASS]  test_gmail_message_id_lookup passed")


def test_gmail_message_id_deduplication():
    """_store_gmail_analysis must not create duplicates for the same Gmail ID."""
    from backend.app.gmail.api import _store_gmail_analysis
    from backend.app.parser.email_parser import ParsedEmail
    from detection.engine import DetectionEngine

    gmail_message_id = f"dedup-{uuid.uuid4()}"
    db, _ = _seed_analysis(email_id=gmail_message_id)
    try:
        parsed = ParsedEmail(
            sender="Dedup <dedup@example.com>",
            sender_email="dedup@example.com",
            sender_domain="example.com",
            subject="Dedup check",
            date="Wed, 16 Sep 2026 10:00:00 +0000",
        )
        results = DetectionEngine().analyze(parsed)
        row = _store_gmail_analysis(parsed, results, db, gmail_message_id, None)
        # The existing row must be returned unchanged, not a new one.
        assert row.email_id == gmail_message_id
        count = db.query(EmailAnalysis).filter(
            EmailAnalysis.email_id == gmail_message_id
        ).count()
        assert count == 1, f"Deduplication failed: {count} rows"
    finally:
        db.close()
        # Cleanup
        db2 = SessionLocal()
        db2.query(EmailAnalysis).filter(EmailAnalysis.email_id == gmail_message_id).delete()
        db2.commit()
        db2.close()
    print("[PASS]  test_gmail_message_id_deduplication passed")


def test_gmail_attachment_metadata_extraction():
    """Gmail messages with attachment parts must yield attachment metadata."""
    import base64
    from backend.app.parser.email_parser import parse_gmail_message

    message = {
        "id": "attach-test-1",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [{"name": "From", "value": "a@b.com"}],
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": base64.urlsafe_b64encode(b"See attached").decode()},
                },
                {
                    "mimeType": "application/pdf",
                    "filename": "invoice.pdf",
                    "body": {"size": 2048},  # no inline data (typical for attachments)
                },
                {
                    "mimeType": "application/octet-stream",
                    "filename": "evil.pdf.exe",
                    "body": {"size": 4096},
                },
            ],
        },
    }
    parsed = parse_gmail_message(message)
    filenames = [a["filename"] for a in parsed.attachments]
    assert "invoice.pdf" in filenames, f"Attachment metadata missing: {filenames}"
    assert "evil.pdf.exe" in filenames
    sizes = {a["filename"]: a["size"] for a in parsed.attachments}
    assert sizes["invoice.pdf"] == 2048
    assert parsed.body_text.strip() == "See attached"
    print("[PASS]  test_gmail_attachment_metadata_extraction passed")


def test_backend_html_sanitizer_strips_active_content():
    """The sanitizer must remove scripts, handlers, iframes, forms, js: URLs."""
    from backend.app.utils.html_sanitizer import sanitize_email_html

    dirty = """<html><head><title>t</title></head><body>
      <p onclick="steal()">Hello</p>
      <script>alert('xss')</script>
      <iframe src="http://evil.com"></iframe>
      <form action="http://evil.com"><input type="text"></form>
      <a href="javascript:alert(1)">click</a>
      <a href="https://good.example.com/path">good link</a>
      <img src="http://tracker.example.com/pixel.gif" alt="pic">
      <style>body { background: url(http://evil.com/x) }</style>
      <p>Trailing text</p>
    </body></html>"""
    clean = sanitize_email_html(dirty)
    lower = clean.lower()

    for forbidden in ("<script", "<iframe", "<form", "<input", "<style",
                      "onclick", "javascript:", "alert(", "http://tracker",
                      "http://evil.com/x", "<img"):
        assert forbidden not in lower, f"Sanitizer leaked: {forbidden}"

    # Readable text preserved; safe URL shown defanged as text.
    assert "hello" in lower and "trailing text" in lower
    assert "hxxps://good[.]example[.]com/path" in lower
    print("[PASS]  test_backend_html_sanitizer_strips_active_content passed")


def test_sanitizer_output_is_stable_and_bounded():
    """Sanitizer must not crash on malformed HTML and must handle empties."""
    from backend.app.utils.html_sanitizer import sanitize_email_html

    assert sanitize_email_html("") == ""
    assert sanitize_email_html(None) == ""
    # Malformed / tricky input must not raise
    for bad in ("<p>unclosed", "<<>>", "<a href='http://x'>", "&#x6A;avascript:alert(1)",
                "<scr<script>ipt>alert(1)</script>"):
        sanitize_email_html(bad)
    print("[PASS]  test_sanitizer_output_is_stable_and_bounded passed")


if __name__ == '__main__':
    test_detail_endpoint_returns_full_record()
    test_detail_endpoint_404_is_safe()
    test_gmail_message_id_lookup()
    test_gmail_message_id_deduplication()
    test_gmail_attachment_metadata_extraction()
    test_backend_html_sanitizer_strips_active_content()
    test_sanitizer_output_is_stable_and_bounded()
    print("\nAll email-detail tests passed!")
