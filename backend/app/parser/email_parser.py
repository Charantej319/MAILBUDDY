"""
Email parser that extracts structured data from email messages.
Handles both .eml files and Gmail API message format.
"""

import email
import email.policy
import re
import json
from email import policy
from email.parser import BytesParser
from typing import Optional
from dataclasses import dataclass, field, asdict
from html.parser import HTMLParser


@dataclass
class ParsedEmail:
    """Structured representation of a parsed email."""
    sender: str = ""
    sender_email: str = ""
    sender_name: str = ""
    sender_domain: str = ""
    recipient: str = ""
    subject: str = ""
    date: Optional[str] = None
    message_id: str = ""
    
    # Headers
    headers: dict = field(default_factory=dict)
    
    # Body
    body_text: str = ""
    body_html: str = ""
    
    # Extracted content
    urls: list = field(default_factory=list)
    anchors: list = field(default_factory=list)  # [(href, visible_text), ...]
    attachments: list = field(default_factory=list)
    
    # Authentication results
    spf_result: str = ""
    dkim_result: str = ""
    dmarc_result: str = ""
    
    # Raw headers for header analysis
    received_headers: list = field(default_factory=list)
    
    def to_dict(self):
        return asdict(self)


class URLExtractor(HTMLParser):
    """Extract URLs from HTML content."""
    
    def __init__(self):
        super().__init__()
        self.urls = []
    
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attr, value in attrs:
                if attr == 'href' and value and value.startswith(('http://', 'https://')):
                    self.urls.append(value)


class AnchorExtractor(HTMLParser):
    """Extract (href, visible_text) pairs from <a> elements.

    F-3: the visible anchor text is captured from the HTML source itself —
    it is NEVER inferred from the href. Nested formatting tags inside the
    anchor (<a><b>text</b></a>) are flattened into the visible text, HTML
    entities in both the href and the text are decoded (convert_charrefs=True
    plus html.parser's built-in attribute unescaping), and whitespace is
    collapsed.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self._href: str | None = None
        self._chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a' and self._href is None:  # ignore invalid nested <a>
            self._href = dict(attrs).get('href') or ''
            self._chunks = []

    def handle_endtag(self, tag):
        if tag == 'a' and self._href is not None:
            text = re.sub(r'\s+', ' ', ' '.join(self._chunks)).strip()
            self.anchors.append((self._href.strip(), text))
            self._href = None
            self._chunks = []

    def handle_data(self, data):
        if self._href is not None:
            self._chunks.append(data)


def extract_anchors_from_html(html: str) -> list[tuple[str, str]]:
    """Extract (href, visible_text) pairs from anchor tags in HTML content.

    Never raises: malformed HTML yields whatever anchors parsed cleanly.
    """
    if not html:
        return []
    extractor = AnchorExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass
    return extractor.anchors


# Valid RFC 5451 / RFC 7208 authentication verdicts (F-5).
AUTH_STATES = ("pass", "fail", "softfail", "neutral", "none",
               "temperror", "permerror")


def normalize_auth_result(header: str) -> dict:
    """Normalize an Authentication-Results header into distinct SPF/DKIM/DMARC
    verdicts.

    Each mechanism is extracted and normalized SEPARATELY so states are never
    collapsed into each other: spf=softfail stays 'softfail', dkim=none stays
    'none', dmarc=none stays 'none'. Malformed or vendor-extended tokens map
    to 'unknown' instead of being coerced into fail/pass.
    """
    result = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not header:
        return result
    auth_lower = str(header).lower()
    for mech in ("spf", "dkim", "dmarc"):
        match = re.search(rf'\b{mech}\s*=\s*([a-z]+)', auth_lower)
        if match:
            value = match.group(1)
            result[mech] = value if value in AUTH_STATES else "unknown"
    return result


def extract_urls_from_text(text: str) -> list[str]:
    """Extract URLs from plain text content."""
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    return list(set(url_pattern.findall(text)))


def extract_urls_from_html(html: str) -> list[str]:
    """Extract URLs from HTML content."""
    extractor = URLExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass
    
    # Also extract from text
    text_urls = extract_urls_from_text(html)
    
    all_urls = list(set(extractor.urls + text_urls))
    return all_urls


def parse_eml_content(eml_content: str | bytes) -> ParsedEmail:
    """
    Parse raw .eml content into structured ParsedEmail.
    Accepts both string and bytes input.
    """
    if isinstance(eml_content, str):
        eml_content = eml_content.encode('utf-8')
    
    msg = email.message_from_bytes(eml_content, policy=policy.default)
    parsed = ParsedEmail()
    
    # Extract basic headers
    parsed.sender = str(msg.get('From', ''))
    parsed.recipient = str(msg.get('To', ''))
    parsed.subject = str(msg.get('Subject', ''))
    parsed.date = str(msg.get('Date', ''))
    parsed.message_id = str(msg.get('Message-ID', ''))
    
    # Parse sender email and name
    from email.utils import parseaddr
    name, addr = parseaddr(parsed.sender)
    parsed.sender_name = name
    parsed.sender_email = addr
    if '@' in addr:
        parsed.sender_domain = addr.split('@')[-1].lower().strip()
    
    # Store all headers
    important_headers = [
        'From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 'Message-ID',
        'Reply-To', 'Return-Path', 'X-Mailer', 'User-Agent',
        'Received', 'Authentication-Results', 'ARC-Authentication-Results',
        'DKIM-Signature', 'SPF', 'X-Originating-IP', 'X-Spam-Status',
        'X-Spam-Score', 'List-Unsubscribe', 'Precedence',
    ]
    
    for header in important_headers:
        values = msg.get_all(header)
        if values:
            if len(values) == 1:
                parsed.headers[header] = str(values[0])
            else:
                parsed.headers[header] = [str(v) for v in values]
    
    # Parse authentication results (RFC 5451).
    #
    # F-5: SPF, DKIM and DMARC are normalized SEPARATELY via a shared
    # regex-based extractor; distinct verdicts (fail / softfail / neutral /
    # none / temperror / permerror / unknown) are preserved — never
    # collapsed into fail or none.
    auth_results = msg.get('Authentication-Results', '')
    normalized = normalize_auth_result(str(auth_results))
    parsed.spf_result = normalized["spf"]
    parsed.dkim_result = normalized["dkim"]
    parsed.dmarc_result = normalized["dmarc"]
    
    # Store Received headers
    received = msg.get_all('Received', [])
    parsed.received_headers = [str(r) for r in received] if received else []
    
    # Extract body and attachments
    body_text = ""
    body_html = ""
    attachments = []
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get('Content-Disposition', ''))
            if part.get_content_maintype() == 'multipart':
                continue  # container parts are not attachments

            if 'attachment' in disposition or part.get_filename():
                # This is an attachment — metadata only, never opened.
                filename = part.get_filename() or "unknown"
                payload = part.get_payload(decode=True)
                size = len(payload) if payload else 0
                if size == 0:
                    # Fall back to the declared size (e.g. Gmail API parts).
                    try:
                        size = int(part.get('Content-Length') or 0)
                    except (TypeError, ValueError):
                        size = 0

                attachments.append({
                    'filename': filename,
                    'content_type': content_type,
                    'size': size,
                    'disposition': disposition,
                })
            elif content_type == 'text/plain' and not body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        body_text = payload.decode(charset)
                    except (UnicodeDecodeError, LookupError):
                        body_text = payload.decode('utf-8', errors='replace')
            elif content_type == 'text/html' and not body_html:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    try:
                        body_html = payload.decode(charset)
                    except (UnicodeDecodeError, LookupError):
                        body_html = payload.decode('utf-8', errors='replace')
    else:
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or 'utf-8'
            try:
                content = payload.decode(charset)
            except (UnicodeDecodeError, LookupError):
                content = payload.decode('utf-8', errors='replace')
            
            if content_type == 'text/html':
                body_html = content
            else:
                body_text = content
    
    parsed.body_text = body_text
    parsed.body_html = body_html
    parsed.attachments = attachments
    
    # Extract URLs from both text and HTML
    urls_from_text = extract_urls_from_text(body_text)
    urls_from_html = extract_urls_from_html(body_html) if body_html else []
    parsed.urls = list(set(urls_from_text + urls_from_html))

    # F-3: extract (href, visible_text) anchor pairs straight from the HTML
    # so the URL analyzer can compare the DISPLAYED link against the real
    # destination. Visible text is taken from the source, never inferred.
    parsed.anchors = extract_anchors_from_html(body_html) if body_html else []

    # Preserve anchor text for the URL analyzer's visible-link check.
    # html.parser never renders clickable links, so this value is safe to
    # expose as the visible text of the email body.
    try:
        from ..utils.html_sanitizer import sanitize_email_html
        parsed.anchor_text = sanitize_email_html(body_html)
    except Exception:
        parsed.anchor_text = body_text or ""

    return parsed


def parse_eml_file(file_path: str) -> ParsedEmail:
    """Parse an .eml file from disk."""
    with open(file_path, 'rb') as f:
        content = f.read()
    return parse_eml_content(content)


def parse_gmail_message(message: dict) -> ParsedEmail:
    """
    Parse a Gmail API message resource into ParsedEmail.
    The message dict should have 'payload' from the Gmail API.
    """
    parsed = ParsedEmail()
    
    headers = {h['name']: h['value'] for h in message.get('payload', {}).get('headers', [])}
    
    parsed.sender = headers.get('From', '')
    parsed.recipient = headers.get('To', '')
    parsed.subject = headers.get('Subject', '')
    parsed.date = headers.get('Date', '')
    parsed.message_id = message.get('id', '')
    
    from email.utils import parseaddr
    name, addr = parseaddr(parsed.sender)
    parsed.sender_name = name
    parsed.sender_email = addr
    if '@' in addr:
        parsed.sender_domain = addr.split('@')[-1].lower().strip()
    
    # Store headers
    for key, value in headers.items():
        parsed.headers[key] = value
    
    # Parse authentication (RFC 5451) — shared normalizer, distinct states.
    normalized = normalize_auth_result(headers.get('Authentication-Results', ''))
    parsed.spf_result = normalized["spf"]
    parsed.dkim_result = normalized["dkim"]
    parsed.dmarc_result = normalized["dmarc"]
    
    # Extract body and attachment metadata from Gmail payload
    def extract_parts(payload):
        nonlocal body_text, body_html
        mime_type = payload.get('mimeType', '')
        filename = payload.get('filename') or ''
        body = payload.get('body', {}) or {}
        body_data = body.get('data', '')

        if filename and body_data == '':
            # Attachment part without inline data: record metadata only.
            attachments.append({
                'filename': filename,
                'content_type': mime_type or 'application/octet-stream',
                'size': int(body.get('size') or 0),
                'disposition': 'attachment',
            })
        elif body_data and filename:
            # F-30: attachment part WITH inline data. Gmail's body.size already
            # carries the decoded byte size, so the payload is NOT decoded here —
            # decoding a multi-MB base64 blob only to compute its length wasted
            # CPU and memory on every sync. Attachments are metadata-only by
            # design (SECURITY.md: never opened/executed); the detection
            # engine consumes only filename/type/size.
            attachments.append({
                'filename': filename,
                'content_type': mime_type or 'application/octet-stream',
                'size': int(body.get('size') or 0),
                'disposition': 'attachment',
            })
        elif body_data:
            import base64
            decoded = base64.urlsafe_b64decode(body_data + '==').decode('utf-8', errors='replace')
            if mime_type == 'text/plain' and not body_text:
                body_text = decoded
            elif mime_type == 'text/html' and not body_html:
                body_html = decoded

        for part in payload.get('parts', []):
            extract_parts(part)

    attachments = []
    
    body_text = ""
    body_html = ""
    
    payload = message.get('payload', {})
    extract_parts(payload)
    
    parsed.body_text = body_text
    parsed.body_html = body_html
    parsed.attachments = attachments
    
    # Extract URLs
    urls_from_text = extract_urls_from_text(body_text)
    urls_from_html = extract_urls_from_html(body_html) if body_html else []
    parsed.urls = list(set(urls_from_text + urls_from_html))

    # F-3: anchor pairs for the visible-link check (Gmail HTML bodies).
    parsed.anchors = extract_anchors_from_html(body_html) if body_html else []
    
    return parsed
