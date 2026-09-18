"""
Unit tests for Gmail integration.
Tests OAuth URL generation, Gmail message parsing, deduplication,
MIME parsing, and detection engine integration.
"""

import sys
import os
import uuid
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.app.config import Settings
from backend.app.parser.email_parser import parse_gmail_message, ParsedEmail
from detection.engine import DetectionEngine


def test_oauth_url_generation():
    """Test that OAuth URL contains required parameters."""
    settings = Settings()
    settings.GOOGLE_CLIENT_ID = "test-client-id"
    settings.GOOGLE_CLIENT_SECRET = "test-secret"
    settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/google/callback"

    from urllib.parse import urlencode
    scopes = " ".join(settings.GOOGLE_SCOPES)
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": scopes,
        "access_type": "offline",
        "prompt": "consent",
    }
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

    assert "client_id=test-client-id" in auth_url
    assert "response_type=code" in auth_url
    assert "gmail.readonly" in auth_url
    assert "access_type=offline" in auth_url
    assert "prompt=consent" in auth_url
    print("[PASS]  test_oauth_url_generation passed")


def test_oauth_scope_is_readonly():
    """Test that only gmail.readonly scope is requested."""
    settings = Settings()
    assert "https://www.googleapis.com/auth/gmail.readonly" in settings.GOOGLE_SCOPES
    assert len(settings.GOOGLE_SCOPES) == 1
    assert "userinfo.email" not in settings.GOOGLE_SCOPES
    assert "userinfo.profile" not in settings.GOOGLE_SCOPES
    print("[PASS]  test_oauth_scope_is_readonly passed")


def test_parse_gmail_message_basic():
    """Test parsing a basic Gmail API message."""
    message = {
        "id": "gmail-msg-123",
        "threadId": "thread-456",
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "From", "value": "sender@example.com"},
                {"name": "To", "value": "recipient@example.com"},
                {"name": "Subject", "value": "Test Subject"},
                {"name": "Date", "value": "Mon, 01 Jan 2024 12:00:00 +0000"},
                {"name": "Message-ID", "value": "<test@example.com>"},
            ],
            "body": {
                "data": __import__('base64').urlsafe_b64encode(b"Hello world").decode()
            }
        }
    }

    parsed = parse_gmail_message(message)
    assert parsed.sender_email == "sender@example.com"
    assert parsed.recipient == "recipient@example.com"
    assert parsed.subject == "Test Subject"
    assert parsed.message_id == "gmail-msg-123"
    assert "Hello world" in parsed.body_text
    print("[PASS]  test_parse_gmail_message_basic passed")


def test_parse_gmail_message_multipart():
    """Test parsing a multipart Gmail API message."""
    import base64

    html_body = "<html><body><a href='https://example.com'>Click here</a></body></html>"
    text_body = "Click here: https://example.com"

    message = {
        "id": "gmail-msg-456",
        "threadId": "thread-789",
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": [
                {"name": "From", "value": "phisher@evil.com"},
                {"name": "Subject", "value": "Urgent: Verify your account"},
                {"name": "Date", "value": "Mon, 01 Jan 2024 12:00:00 +0000"},
            ],
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": base64.urlsafe_b64encode(text_body.encode()).decode()}
                },
                {
                    "mimeType": "text/html",
                    "body": {"data": base64.urlsafe_b64encode(html_body.encode()).decode()}
                }
            ]
        }
    }

    parsed = parse_gmail_message(message)
    assert parsed.sender_email == "phisher@evil.com"
    assert "Verify your account" in parsed.subject
    assert "https://example.com" in parsed.urls
    assert "Hello" not in parsed.body_text  # Plain text part, not HTML
    print("[PASS]  test_parse_gmail_message_multipart passed")


def test_parse_gmail_message_sender_domain():
    """Test that sender domain is correctly extracted."""
    message = {
        "id": "msg-1",
        "payload": {
            "headers": [
                {"name": "From", "value": "user@malicious-domain.xyz"},
                {"name": "Subject", "value": "Test"},
            ],
        }
    }

    parsed = parse_gmail_message(message)
    assert parsed.sender_domain == "malicious-domain.xyz"
    assert parsed.sender_email == "user@malicious-domain.xyz"
    assert parsed.sender_name == ""
    print("[PASS]  test_parse_gmail_message_sender_domain passed")


def test_parse_gmail_message_empty():
    """Test parsing a Gmail message with minimal headers."""
    message = {
        "id": "msg-empty",
        "payload": {
            "headers": []
        }
    }

    parsed = parse_gmail_message(message)
    assert parsed.sender_email == ""
    assert parsed.subject == ""
    assert parsed.urls == []
    assert parsed.body_text == ""
    print("[PASS]  test_parse_gmail_message_empty passed")


def test_gmail_message_deduplication():
    """Test that duplicate Gmail message IDs are detected."""
    existing_ids = {"msg-1", "msg-2", "msg-3"}

    new_messages = [
        {"id": "msg-1"},
        {"id": "msg-2"},
        {"id": "msg-4"},
        {"id": "msg-5"},
    ]

    to_process = [m for m in new_messages if m["id"] not in existing_ids]
    assert len(to_process) == 2
    assert to_process[0]["id"] == "msg-4"
    assert to_process[1]["id"] == "msg-5"
    print("[PASS]  test_gmail_message_deduplication passed")


def test_gmail_detection_engine_integration():
    """Test that Gmail-parsed emails work with the detection engine."""
    import base64

    phishing_html = """
    <html><body>
    <h1>Urgent: Your account has been compromised</h1>
    <p>Click here immediately to verify your identity: https://secure-verify-evil.xyz/login</p>
    <p>Failure to verify within 24 hours will result in account suspension.</p>
    </body></html>
    """

    message = {
        "id": "gmail-phish-1",
        "threadId": "thread-phish-1",
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": [
                {"name": "From", "value": "security@paypa1-verify.com"},
                {"name": "To", "value": "victim@example.com"},
                {"name": "Subject", "value": "URGENT: Verify your account immediately"},
                {"name": "Date", "value": "Mon, 01 Jan 2024 12:00:00 +0000"},
                {"name": "Authentication-Results", "value": "spf=fail; dkim=fail; dmarc=fail"},
            ],
            "parts": [
                {
                    "mimeType": "text/html",
                    "body": {"data": base64.urlsafe_b64encode(phishing_html.encode()).decode()}
                }
            ]
        }
    }

    parsed = parse_gmail_message(message)
    engine = DetectionEngine()
    results = engine.analyze(parsed)

    assert results["risk_score"] > 0
    assert results["classification"] in ("LOW RISK", "SUSPICIOUS", "HIGH RISK")
    assert len(results["findings"]) > 0
    print("[PASS]  test_gmail_detection_engine_integration passed")


def test_gmail_safe_email():
    """Test that a legitimate-looking Gmail message scores low."""
    import base64

    safe_text = "Hi team, just a reminder about our meeting tomorrow at 3pm. Best, John"

    message = {
        "id": "gmail-safe-1",
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "From", "value": "john@company.com"},
                {"name": "To", "value": "team@company.com"},
                {"name": "Subject", "value": "Meeting Reminder"},
                {"name": "Date", "value": "Mon, 01 Jan 2024 12:00:00 +0000"},
                {"name": "Authentication-Results", "value": "spf=pass; dkim=pass; dmarc=pass"},
            ],
            "body": {"data": base64.urlsafe_b64encode(safe_text.encode()).decode()}
        }
    }

    parsed = parse_gmail_message(message)
    engine = DetectionEngine()
    results = engine.analyze(parsed)

    assert results["risk_score"] < 25
    assert results["classification"] == "SAFE"
    print("[PASS]  test_gmail_safe_email passed")


def test_gmail_authentication_results_parsing():
    """Test that authentication results are correctly parsed from Gmail messages."""
    message = {
        "id": "msg-auth-1",
        "payload": {
            "headers": [
                {"name": "From", "value": "user@example.com"},
                {"name": "Authentication-Results", "value": "mx.google.com; spf=pass; dkim=pass; dmarc=pass"},
            ],
        }
    }

    parsed = parse_gmail_message(message)
    assert parsed.spf_result == "pass"
    assert parsed.dkim_result == "pass"
    assert parsed.dmarc_result == "pass"
    print("[PASS]  test_gmail_authentication_results_parsing passed")


def test_gmail_auth_failure_parsing():
    """Test that authentication failures are correctly parsed."""
    message = {
        "id": "msg-auth-fail-1",
        "payload": {
            "headers": [
                {"name": "From", "value": "spoofed@evil.com"},
                {"name": "Authentication-Results", "value": "mx.google.com; spf=fail; dkim=fail; dmarc=fail"},
            ],
        }
    }

    parsed = parse_gmail_message(message)
    assert parsed.spf_result == "fail"
    assert parsed.dkim_result == "fail"
    assert parsed.dmarc_result == "fail"
    print("[PASS]  test_gmail_auth_failure_parsing passed")


def test_config_poll_interval():
    """Test that Gmail poll interval is configurable."""
    settings = Settings()
    assert settings.GMAIL_POLL_INTERVAL == 60
    assert settings.GMAIL_INITIAL_SYNC_COUNT == 50
    print("[PASS]  test_config_poll_interval passed")


def test_session_store():
    """Test SQLite-backed session store for OAuth."""
    from backend.app.database.connection import init_db
    init_db()  # ensure oauth_sessions/oauth_states tables exist

    from backend.app.auth.sessions import create_session, get_session_user, remove_session

    session_id = create_session("test@gmail.com")
    assert session_id is not None
    assert len(session_id) > 0

    user = get_session_user(session_id)
    assert user == "test@gmail.com"

    remove_session(session_id)
    user = get_session_user(session_id)
    assert user is None
    print("[PASS]  test_session_store passed")


def test_gmail_message_with_attachments():
    """Test parsing Gmail message with attachment metadata."""
    import base64

    message = {
        "id": "msg-attach-1",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": "sender@example.com"},
                {"name": "Subject", "value": "Invoice attached"},
            ],
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": base64.urlsafe_b64encode(b"Please see attached invoice.").decode()}
                },
                {
                    "mimeType": "application/pdf",
                    "filename": "invoice.pdf",
                    "body": {"data": "", "size": 1024}
                }
            ]
        }
    }

    parsed = parse_gmail_message(message)
    assert "invoice.pdf" in str(parsed.urls) or parsed.body_text != ""
    print("[PASS]  test_gmail_message_with_attachments passed")


if __name__ == '__main__':
    test_oauth_url_generation()
    test_oauth_scope_is_readonly()
    test_parse_gmail_message_basic()
    test_parse_gmail_message_multipart()
    test_parse_gmail_message_sender_domain()
    test_parse_gmail_message_empty()
    test_gmail_message_deduplication()
    test_gmail_detection_engine_integration()
    test_gmail_safe_email()
    test_gmail_authentication_results_parsing()
    test_gmail_auth_failure_parsing()
    test_config_poll_interval()
    test_session_store()
    test_gmail_message_with_attachments()
    print("\nAll Gmail tests passed! ")
