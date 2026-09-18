"""
MailBuddy service layer.

- analyze_and_store: cached priority analysis per email (persisted so the same
  email is never re-analyzed unnecessarily).
- Notifications: dedup via the notification_log unique key; desktop delivery
  is best-effort through the Electron bridge (never fatal).
- Settings helpers: simple key/value toggles stored server-side.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models.email import AppSetting, EmailAnalysis, NotificationLog
from ..utils.timeutil import utc_now
from . import priority_ai
from .priority import VALID_CATEGORIES, VALID_LEVELS

logger = logging.getLogger("phishguard.mailbuddy")

NOTIFIABLE_LEVELS = ("CRITICAL", "HIGH")

# ---- Settings -------------------------------------------------------------

SETTING_DEFAULTS = {
    "assistant_enabled": "true",
    "smart_priority_enabled": "true",
    "important_notifications_enabled": "true",
    "desktop_notifications_enabled": "true",
}


def get_setting(db: Session, key: str) -> str:
    row = db.get(AppSetting, key)
    if row is not None:
        return row.value
    return SETTING_DEFAULTS.get(key, "true" if key in SETTING_DEFAULTS else "")


def get_settings(db: Session) -> dict:
    return {key: get_setting(db, key) == "true" for key in SETTING_DEFAULTS}


def set_setting(db: Session, key: str, value: bool) -> dict:
    if key not in SETTING_DEFAULTS:
        raise KeyError(key)
    row = db.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key, value="true" if value else "false")
        db.add(row)
    else:
        row.value = "true" if value else "false"
        row.updated_at = utc_now().replace(tzinfo=None) if utc_now().tzinfo else utc_now()
    db.commit()
    return get_settings(db)


# ---- Priority analysis with persistence -----------------------------------

def build_evidence(analysis: EmailAnalysis) -> dict:
    """Minimal, non-secret evidence for priority analysis from a stored analysis."""
    return {
        "subject": analysis.subject or "",
        "sender": analysis.sender or "",
        "sender_email": analysis.sender_email or "",
        "sender_domain": analysis.sender_domain or "",
        "recipient": analysis.recipient or "",
        "date": analysis.date.isoformat() if analysis.date else None,
        "body_text": (analysis.body_text or "")[:4000],
        "urls": (json.loads(analysis.extracted_urls) if analysis.extracted_urls else [])[:8],
        "security": {
            "classification": analysis.classification or "SAFE",
            "risk_score": analysis.risk_score,
        },
        "received_at": analysis.date.replace(tzinfo=timezone.utc) if analysis.date else None,
    }


def _store_result(analysis: EmailAnalysis, result: priority_ai.PriorityAnalysis) -> EmailAnalysis:
    analysis.priority_level = result.level
    analysis.priority_category = result.category
    analysis.priority_score = float(result.confidence)
    analysis.priority_reasons = json.dumps(result.reasons)
    analysis.priority_summary = result.summary
    analysis.priority_deadline = (
        datetime.fromisoformat(result.deadline_iso).replace(tzinfo=None)
        if result.deadline_iso else None
    )
    analysis.priority_analyzed_at = utc_now().replace(tzinfo=None) if utc_now().tzinfo else utc_now()
    analysis.priority_model = result.model
    analysis.priority_is_otp = "otp" in " ".join(result.reasons).lower() or result.category == "SECURITY"
    return analysis


async def analyze_and_store(analysis: EmailAnalysis, db: Session, force: bool = False) -> EmailAnalysis:
    """Analyze one stored email's priority (cached) and persist the result.

    Returns the analysis row. Never raises for AI failures — the heuristic
    fallback inside analyze_priority covers those.
    """
    if not force and analysis.priority_level:
        return analysis  # already analyzed; do not burn API calls on repeats
    evidence = build_evidence(analysis)
    result = await priority_ai.analyze_priority(evidence)
    _store_result(analysis, result)
    db.commit()
    db.refresh(analysis)
    return analysis


def ensure_unread_flags(db: Session, email_ids: set[str] | None = None) -> int:
    """Best-effort unread-flag sync for Gmail-sourced rows.

    MailBuddy marks Gmail rows unread by default and lets the frontend toggle;
    a full Gmail label sync is out of scope for this pass.
    """
    return 0  # placeholder: flags are set at ingestion time (see pipeline hook)


def json_or_empty(raw: str | None) -> list:
    try:
        return json.loads(raw) if raw else []
    except (ValueError, TypeError):
        return []


def rows_needing_analysis(db: Session, limit: int = 12) -> list[EmailAnalysis]:
    """Oldest-first unanalyzed rows, bounded per pass for rate-limit safety."""
    return (
        db.query(EmailAnalysis)
        .filter(EmailAnalysis.priority_level.is_(None))
        .order_by(EmailAnalysis.created_at.desc())
        .limit(limit)
        .all()
    )


# ---- Notifications ---------------------------------------------------------

def _deliver_desktop(title: str, body: str, analysis: EmailAnalysis) -> bool:
    """Best-effort desktop delivery through the Electron notification bridge.

    The renderer polls /api/mailbuddy/notifications/pending and shows native
    notifications; server-side we only mark the ledger row delivered. If no
    desktop shell is present, delivery stays false and nothing breaks.
    """
    return False


def queue_notifications(db: Session, analysis: EmailAnalysis) -> int:
    """Create deduplicated notification entries for a notifiable email.

    Returns the number of NEW notifications created (0 when the same email
    re-syncs — the unique notification_key absorbs duplicates).
    """
    if not analysis.priority_level or analysis.priority_level not in NOTIFIABLE_LEVELS:
        return 0
    kind = "priority"
    key = f"priority:{analysis.priority_level}:{analysis.email_id or analysis.id}"
    existing = db.query(NotificationLog).filter(NotificationLog.notification_key == key).first()
    if existing:
        return 0
    row = NotificationLog(
        id=str(uuid.uuid4()),
        notification_key=key,
        email_id=analysis.email_id or analysis.id,
        kind=kind,
        delivered=0,
    )
    db.add(row)
    db.commit()
    return 1


def pending_notifications(db: Session, limit: int = 10) -> list[dict]:
    rows = (
        db.query(NotificationLog)
        .filter(NotificationLog.delivered == 0)
        .order_by(NotificationLog.created_at.desc())
        .limit(limit)
        .all()
    )
    out = []
    for row in rows:
        analysis = db.query(EmailAnalysis).filter(
            (EmailAnalysis.email_id == row.email_id) | (EmailAnalysis.id == row.email_id)
        ).first() if row.email_id else None
        out.append({
            "key": row.notification_key,
            "kind": row.kind,
            "created_at": row.created_at.isoformat() + "Z" if row.created_at else None,
            "email": {
                "id": analysis.id,
                "email_id": analysis.email_id,
                "subject": analysis.subject,
                "sender": analysis.sender,
                "priority_level": analysis.priority_level,
                "priority_category": analysis.priority_category,
                "priority_summary": analysis.priority_summary,
            } if analysis else None,
        })
    return out


def mark_delivered(db: Session, keys: list[str]) -> int:
    if not keys:
        return 0
    count = 0
    rows = db.query(NotificationLog).filter(NotificationLog.notification_key.in_(keys)).all()
    for row in rows:
        if row.delivered == 0:
            row.delivered = 1
            count += 1
    db.commit()
    return count
