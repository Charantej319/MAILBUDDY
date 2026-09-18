"""
Ingestion-time MailBuddy priority hook.

Runs the deterministic heuristic synchronously when an email analysis row is
stored (Gmail sync, .eml upload, or raw paste). This guarantees every email
has a usable priority immediately — the inbox never blocks on AI.

AI refinement happens as a separate bounded pass (see
POST /api/mailbuddy/priority/analyze-batch), so Groq rate limits can never
freeze sync or the UI.
"""

import logging

from . import priority as heuristic
from .priority_ai import PriorityAnalysis
from .service import _store_result, queue_notifications

logger = logging.getLogger("phishguard.mailbuddy.ingest")


def apply_ingestion_priority(analysis, results: dict, db) -> None:
    """Heuristic priority at ingestion time + notification queueing.

    Called with a freshly committed EmailAnalysis row. Never raises upward:
    priority is additive and must never break email ingestion.
    """
    try:
        if analysis.priority_level:
            # Already classified (re-sync of the same message) — do not re-analyze.
            return
        evidence = {
            "subject": analysis.subject or "",
            "sender": analysis.sender or "",
            "sender_email": analysis.sender_email or "",
            "sender_domain": analysis.sender_domain or "",
            "body_text": (analysis.body_text or "")[:4000],
            "security": {
                "classification": analysis.classification or "SAFE",
                "risk_score": analysis.risk_score,
            },
            "received_at": analysis.date,
        }
        fallback = heuristic.heuristic_classify(
            subject=evidence["subject"], sender=evidence["sender"],
            sender_email=evidence["sender_email"], sender_domain=evidence["sender_domain"],
            body_text=evidence["body_text"],
            security_classification=evidence["security"]["classification"],
            received_at=evidence["received_at"],
        )
        result = PriorityAnalysis(
            level=fallback["priority"], category=fallback["category"],
            confidence=fallback["confidence"], reasons=fallback["reasons"],
            deadline_iso=fallback["deadline"], summary=fallback["summary"],
            model="heuristic",
        )
        _store_result(analysis, result)
        analysis.priority_is_unread = True  # new arrivals start unread
        db.commit()
        queue_notifications(db, analysis)
    except Exception as exc:  # noqa: BLE001 — priority must never break ingestion
        logger.warning("MailBuddy ingestion priority skipped: %s", exc)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
