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
    
    # Parse authentication results
    auth_results = msg.get('Authentication-Results', '')
    if auth_results:
        auth_lower = auth_results.lower()
        if 'spf=fail' in auth_lower or 'spf=softfail' in auth_lower:
            parsed.spf_result = 'fail'
        elif 'spf=pass' in auth_lower:
            parsed.spf_result = 'pass'
        elif 'spf=none' in auth_lower:
            parsed.spf_result = 'none'
        
        if 'dkim=fail' in auth_lower or 'dkim=none' in auth_lower:
            parsed.dkim_result = 'fail' if 'dkim=fail' in auth_lower else 'none'
        elif 'dkim=pass' in auth_lower:
            parsed.dkim_result = 'pass'
        
        if 'dmarc=fail' in auth_lower or 'dmarc=none' in auth_lower:
            parsed.dmarc_result = 'fail' if 'dmarc=fail' in auth_lower else 'none'
        elif 'dmarc=pass' in auth_lower:
            parsed.dmarc_result = 'pass'
    
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
    
    # Parse authentication
    auth_results = headers.get('Authentication-Results', '')
    if auth_results:
        auth_lower = auth_results.lower()
        parsed.spf_result = 'fail' if 'spf=fail' in auth_lower or 'spf=softfail' in auth_lower else ('pass' if 'spf=pass' in auth_lower else 'none')
        parsed.dkim_result = 'fail' if 'dkim=fail' in auth_lower else ('none' if 'dkim=none' in auth_lower else ('pass' if 'dkim=pass' in auth_lower else ''))
        parsed.dmarc_result = 'fail' if 'dmarc=fail' in auth_lower else ('none' if 'dmarc=none' in auth_lower else ('pass' if 'dmarc=pass' in auth_lower else ''))
    
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
        elif body_data:
            import base64
            decoded = base64.urlsafe_b64decode(body_data + '==').decode('utf-8', errors='replace')
            if filename:
                attachments.append({
                    'filename': filename,
                    'content_type': mime_type or 'application/octet-stream',
                    'size': int(body.get('size') or len(decoded)),
                    'disposition': 'attachment',
                })
            elif mime_type == 'text/plain' and not body_text:
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
    
    return parsed
