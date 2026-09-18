"""
Database models for email analysis results.
Enhanced with confidence, intelligence, body content and AI verification fields.

All timestamps are stored in UTC. API responses serialize them as
timezone-aware ISO-8601 strings (see app.utils.timeutil) so the frontend
can render them correctly in the user's local timezone.
"""

from sqlalchemy import Column, String, Integer, DateTime, Text, Float
import uuid

from ..database.connection import Base
from ..utils.timeutil import iso_utc


class GmailToken(Base):
    """Stores server-side Gmail OAuth tokens. Never exposed to frontend."""
    __tablename__ = "gmail_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_email = Column(String, unique=True, nullable=False)
    access_token = Column(String, nullable=False)
    refresh_token = Column(String, nullable=True)
    token_expiry = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: __import__("datetime").datetime.utcnow())
    updated_at = Column(DateTime, default=lambda: __import__("datetime").datetime.utcnow(),
                        onupdate=lambda: __import__("datetime").datetime.utcnow())

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "created_at": iso_utc(self.created_at),
            "updated_at": iso_utc(self.updated_at),
        }


class EmailAnalysis(Base):
    """Stores the result of analyzing a single email."""
    __tablename__ = "email_analyses"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email_id = Column(String, unique=True, nullable=True)  # Gmail message ID or generated
    thread_id = Column(String, nullable=True)  # Gmail thread ID
    source = Column(String, nullable=False, default="eml")  # "gmail", "eml" or "raw"

    # Email metadata
    sender = Column(String, nullable=False)
    sender_email = Column(String, nullable=False)
    sender_domain = Column(String, nullable=False)
    recipient = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    date = Column(DateTime, nullable=True)  # email's Date header (UTC)

    # Analysis results
    risk_score = Column(Float, nullable=False, default=0.0)
    classification = Column(String, nullable=False, default="SAFE")
    confidence_level = Column(String, nullable=True, default="LOW")
    confidence_numeric = Column(Float, nullable=True, default=0.0)

    # Detailed findings stored as JSON strings
    detection_findings = Column(Text, nullable=True)  # JSON
    extracted_urls = Column(Text, nullable=True)  # JSON
    attachment_info = Column(Text, nullable=True)  # JSON
    header_findings = Column(Text, nullable=True)  # JSON
    recommended_actions = Column(Text, nullable=True)  # JSON list
    analysis_summary = Column(Text, nullable=True)  # engine summary text

    # Email body content (truncated, display-only; never executed)
    body_text = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)  # raw HTML — must be sanitized before display
    message_id_header = Column(String, nullable=True)  # RFC Message-ID header

    # AI second-opinion verification (optional layer)
    ai_status = Column(String, nullable=True, default="NOT_REQUESTED")  # NOT_REQUESTED/PENDING/VERIFIED/UNAVAILABLE/DISAGREEMENT
    ai_verdict = Column(String, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    ai_summary = Column(Text, nullable=True)
    ai_reasons = Column(Text, nullable=True)  # JSON list
    ai_recommended_action = Column(String, nullable=True)
    ai_model = Column(String, nullable=True)
    ai_analyzed_at = Column(DateTime, nullable=True)

    # Timestamps (UTC defaults; func.now() = SQLite CURRENT_TIMESTAMP = UTC)
    analyzed_at = Column(DateTime, server_default=__import__("sqlalchemy").text("CURRENT_TIMESTAMP"))
    created_at = Column(DateTime, server_default=__import__("sqlalchemy").text("CURRENT_TIMESTAMP"))

    def _json(self, raw, default):
        import json
        if not raw:
            return default
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return default

    def to_dict(self):
        """Convert to dictionary for JSON serialization (timezone-aware UTC)."""
        return {
            "id": self.id,
            "email_id": self.email_id,
            "thread_id": self.thread_id,
            "source": self.source,
            "sender": self.sender,
            "sender_email": self.sender_email,
            "sender_domain": self.sender_domain,
            "recipient": self.recipient,
            "subject": self.subject,
            "date": iso_utc(self.date),
            "risk_score": self.risk_score,
            "classification": self.classification,
            "confidence_level": self.confidence_level,
            "confidence_numeric": self.confidence_numeric,
            "detection_findings": self._json(self.detection_findings, []),
            "extracted_urls": self._json(self.extracted_urls, []),
            "attachment_info": self._json(self.attachment_info, []),
            "header_findings": self._json(self.header_findings, []),
            "recommended_actions": self._json(self.recommended_actions, []),
            "analysis_summary": self.analysis_summary,
            "body_text": self.body_text,
            "body_html": self.body_html,
            "message_id_header": self.message_id_header,
            "ai": self.ai_to_dict(),
            "analyzed_at": iso_utc(self.analyzed_at),
            "created_at": iso_utc(self.created_at),
        }

    def ai_to_dict(self):
        """AI verification block. Null fields mean 'not performed'."""
        return {
            "status": self.ai_status if self.ai_status else "NOT_REQUESTED",
            "verdict": self.ai_verdict,
            "confidence": self.ai_confidence,
            "summary": self.ai_summary,
            "reasons": self._json(self.ai_reasons, []),
            "recommended_action": self.ai_recommended_action,
            "model": self.ai_model,
            "analyzed_at": iso_utc(self.ai_analyzed_at),
        }
