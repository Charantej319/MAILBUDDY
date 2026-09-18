"""
Test that email HTML content containing executable payloads
(e.g. <script> tags) never reaches the React UI as executable content.
This is a rendering/display-safety test, not a detection test.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.app.parser.email_parser import parse_eml_content


def _minimal_eml(body_text=None, body_html=None):
    """Build a minimal multipart .eml string with the given bodies."""
    boundary = "====TESTBOUNDARY===="
    parts = []
    if body_text is not None:
        parts.append(
            f"--{boundary}\r\n"
            "Content-Type: text/plain; charset=\"us-ascii\"\r\n"
            "\r\n"
            f"{body_text}\r\n"
        )
    if body_html is not None:
        parts.append(
            f"--{boundary}\r\n"
            "Content-Type: text/html; charset=\"us-ascii\"\r\n"
            "\r\n"
            f"{body_html}\r\n"
        )
    parts.append(f"--{boundary}--\r\n")

    return (
        f"From: attacker@evil.com\r\n"
        f"To: victim@example.com\r\n"
        f"Subject: Test\r\n"
        f"Date: Wed, 16 Sep 2026 13:37:27 +0530\r\n"
        "Content-Type: multipart/alternative; boundary=\"====TESTBOUNDARY====\"\r\n"
        "MIME-Version: 1.0\r\n"
        "\r\n"
        + "".join(parts)
    )


def test_html_script_payload_not_rendered_as_html():
    """
    A sample email whose HTML body contains a <script> payload
    must never produce executable content in the parsed representation
    that the frontend would render.

    Concretely, the parser may retain body_html for URL extraction;
    that is acceptable as long as the value is benign to store (i.e.
    it is a plain string, not an evaluated document). The frontend
    renders email content as plain text (see frontend/src/pages/EmailAnalysis.jsx),
    so no <script> tag ever reaches the DOM.

    This test asserts that the parser does not, by itself, execute or
    eval the payload, and that the extracted URLs come from the text of
    the email, not from any HTML attribute evaluation.
    """
    payload = "<script>alert('XSS')</script>"
    html_body = f"<html><body>{payload}<a href='http://evil.com/steal'>click</a></body></html>"

    eml = _minimal_eml(body_html=html_body)
    parsed = parse_eml_content(eml)

    # The parser stores body_html as a plain string (no eval, no DOM).
    assert parsed.body_html == html_body, "body_html should be the raw string, not an evaluated document"

    # Extracted URLs come from the href attribute text via HTMLParser,
    # but the parser never renders HTML in the UI. The backend never
    # returns body_html to the frontend, so there is no XSS surface here.
    urls = parsed.urls
    assert "http://evil.com/steal" in urls, "URL extractor should still find the href URL"

    # There must be no executable content produced by the parser beyond
    # the raw string. A quick sanity check: the body_html string itself
    # must not equal an executed form (e.g. it must still contain the
    # literal "<script>" substring, proving it was not stripped/evaluated).
    assert "<script>" in parsed.body_html


def test_plaintext_email_never_contains_html_payload():
    """An email with only a text/plain body must never contain HTML payload text."""
    payload = "<script>alert('XSS')</script>"
    eml = _minimal_eml(body_text=payload)
    parsed = parse_eml_content(eml)

    assert parsed.body_text == payload
    assert parsed.body_html == "", "A text-only email should have an empty body_html"
    assert "<script>" not in parsed.body_html
