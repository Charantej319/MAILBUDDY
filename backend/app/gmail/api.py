"""
Gmail API endpoints with server-side session management.
No tokens are exposed to the frontend.
"""

import json
import uuid
import asyncio
import logging
from datetime import timezone
from fastapi import APIRouter, HTTPException, Depends, Request, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel

from ..database.connection import get_db, SessionLocal
from ..models.email import EmailAnalysis, GmailToken
from ..auth.sessions import get_session_user
from ..utils.timeutil import utc_now
from .service import GmailService
from detection.engine import DetectionEngine

router = APIRouter(prefix="/api/gmail")
engine = DetectionEngine()
logger = logging.getLogger("phishguard.gmail")

# Background polling state
_polling_task = None
_polling_active = False


def _parse_date(date_str: str):
    """Parse an email Date header into an aware UTC datetime."""
    if not date_str:
        return utc_now()
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
    except Exception:
        from ..utils.timeutil import parse_iso
        dt = parse_iso(date_str)
        if dt is None:
            return utc_now()
    # NOTE: timezone must be a function-global import. A function-local import
    # here would make 'timezone' local to the entire function, so the final
    # astimezone(timezone.utc) would raise UnboundLocalError whenever the
    # parsed header was already timezone-aware (the common Gmail case).
    return dt.astimezone(timezone.utc)


def _store_gmail_analysis(parsed, results: dict, db: Session,
                          gmail_message_id: str, thread_id: str = None,
                          raw_message: dict = None) -> EmailAnalysis:
    """Store Gmail analysis with deduplication check."""
    # Check for existing analysis with this Gmail message ID
    existing = db.query(EmailAnalysis).filter(
        EmailAnalysis.email_id == gmail_message_id
    ).first()
    if existing:
        return existing

    # Prefer the RFC Message-ID header for display; fall back to the Gmail ID.
    message_id_header = ""
    if raw_message:
        for h in (raw_message.get("payload", {}) or {}).get("headers", []):
            if h.get("name", "").lower() == "message-id":
                message_id_header = h.get("value", "")
                break

    now = utc_now()
    analysis = EmailAnalysis(
        id=str(uuid.uuid4()),
        email_id=gmail_message_id,
        thread_id=thread_id,
        source="gmail",
        sender=parsed.sender,
        sender_email=parsed.sender_email,
        sender_domain=parsed.sender_domain,
        recipient=parsed.recipient,
        subject=parsed.subject,
        date=_parse_date(parsed.date),
        risk_score=results["risk_score"],
        classification=results["classification"],
        confidence_level=results.get("confidence_level", "LOW"),
        confidence_numeric=results.get("confidence_numeric", 0.0),
        detection_findings=json.dumps(results["findings"]),
        extracted_urls=json.dumps(parsed.urls),
        attachment_info=json.dumps(parsed.attachments),
        header_findings=json.dumps(results["categorized_findings"].get("HEADER", [])),
        recommended_actions=json.dumps(results.get("recommended_actions", [])),
        analysis_summary=results.get("summary", ""),
        body_text=(parsed.body_text or "")[:50000],
        body_html=(parsed.body_html or "")[:100000],
        message_id_header=message_id_header or gmail_message_id,
        analyzed_at=now,
        created_at=now,
    )

    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # MailBuddy: heuristic priority at ingestion time (never blocks or fails sync).
    try:
        from ..mailbuddy.ingest import apply_ingestion_priority
        apply_ingestion_priority(analysis, results, db)
    except Exception:  # noqa: BLE001
        pass

    return analysis


@router.get("/status")
async def gmail_status(request: Request, db: Session = Depends(get_db)):
    """Get Gmail connection status."""
    session_id = request.cookies.get("phishguard_session")
    if not session_id:
        return {"connected": False, "email": None, "last_sync": None}

    user_email = get_session_user(session_id)
    if not user_email:
        return {"connected": False, "email": None, "last_sync": None}

    token_record = db.query(GmailToken).filter(
        GmailToken.user_email == user_email
    ).first()

    if not token_record:
        return {"connected": False, "email": None, "last_sync": None}

    # Get last sync time from most recent Gmail email
    last_gmail = db.query(EmailAnalysis).filter(
        EmailAnalysis.source == "gmail"
    ).order_by(EmailAnalysis.analyzed_at.desc()).first()

    # Serialize as timezone-aware UTC ISO-8601 so browsers compute correct
    # relative times in the user's local timezone ("just now" after sync).
    from ..utils.timeutil import iso_utc
    last_sync = iso_utc(last_gmail.analyzed_at) if last_gmail else None

    # Count synced emails
    gmail_count = db.query(EmailAnalysis).filter(
        EmailAnalysis.source == "gmail"
    ).count()

    return {
        "connected": True,
        "email": user_email,
        "last_sync": last_sync,
        "synced_emails": gmail_count,
    }


@router.post("/sync")
async def sync_gmail(
    request: Request,
    max_results: int = 50,
    db: Session = Depends(get_db),
):
    """Sync latest inbox emails from Gmail. Deduplicates by message ID."""
    session_id = request.cookies.get("phishguard_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not connected to Gmail")

    user_email = get_session_user(session_id)
    if not user_email:
        raise HTTPException(status_code=401, detail="Invalid session")

    try:
        gmail_service = GmailService(user_email)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    try:
        # Get existing Gmail message IDs for dedup
        existing_ids = set(
            row[0] for row in db.query(EmailAnalysis.email_id)
            .filter(EmailAnalysis.source == "gmail")
            .filter(EmailAnalysis.email_id.isnot(None))
            .all()
        )

        # List messages in inbox
        messages = await gmail_service.list_messages(query="in:inbox", max_results=max_results)

        if not messages:
            return {"synced": 0, "skipped": 0, "total": 0, "message": "No emails in inbox"}

        synced = 0
        skipped = 0
        results = []

        for msg in messages:
            message_id = msg["id"]

            # Skip already analyzed
            if message_id in existing_ids:
                skipped += 1
                continue

            try:
                raw_message, parsed = await gmail_service.fetch_and_parse(message_id)
                analysis_results = engine.analyze(parsed)
                thread_id = raw_message.get("threadId")

                analysis = _store_gmail_analysis(
                    parsed, analysis_results, db, message_id, thread_id,
                    raw_message=raw_message,
                )

                synced += 1
                results.append({
                    "id": analysis.id,
                    "email_id": message_id,
                    "sender": parsed.sender,
                    "subject": parsed.subject,
                    "risk_score": analysis_results["risk_score"],
                    "classification": analysis_results["classification"],
                })

            except Exception as e:
                # Log the failure server-side but continue processing other emails.
                # Include str(e): for UnboundLocalError/KeyError the message names the
                # culprit symbol; email content/tokens never appear in these messages.
                logger.warning("Failed to process Gmail message %s: %s: %s", message_id[:12], type(e).__name__, e)
                skipped += 1
                continue

        return {
            "synced": synced,
            "skipped": skipped,
            "total": len(messages),
            "results": results,
        }

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.exception("Gmail sync failed")
        if "401" in error_msg or "unauthorized" in error_msg.lower() or "invalid_grant" in error_msg.lower():
            raise HTTPException(status_code=401, detail="Gmail session expired. Please reconnect your account in Settings.")
        raise HTTPException(status_code=500, detail="Gmail sync failed. Please try again, or reconnect your account if the problem persists.")


@router.post("/analyze-single")
async def analyze_single_gmail(
    request: Request,
    message_id: str,
    db: Session = Depends(get_db),
):
    """Analyze a single Gmail message by ID."""
    session_id = request.cookies.get("phishguard_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not connected to Gmail")

    user_email = get_session_user(session_id)
    if not user_email:
        raise HTTPException(status_code=401, detail="Invalid session")

    try:
        gmail_service = GmailService(user_email)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    try:
        raw_message, parsed = await gmail_service.fetch_and_parse(message_id)
        results = engine.analyze(parsed)
        thread_id = raw_message.get("threadId")

        analysis = _store_gmail_analysis(
            parsed, results, db, message_id, thread_id,
            raw_message=raw_message,
        )

        return {
            "id": analysis.id,
            "risk_score": results["risk_score"],
            "classification": results["classification"],
            "confidence_level": results.get("confidence_level", "LOW"),
            "confidence_numeric": results.get("confidence_numeric", 0.0),
            "findings": results["findings"],
            "top_findings": results.get("top_findings", []),
            "categorized_findings": results["categorized_findings"],
            "recommended_actions": results["recommended_actions"],
            "summary": results["summary"],
            "email_info": {
                "sender": parsed.sender,
                "sender_email": parsed.sender_email,
                "sender_domain": parsed.sender_domain,
                "subject": parsed.subject,
                "date": parsed.date,
                "urls": parsed.urls,
                "attachments": parsed.attachments,
                "headers": {k: v for k, v in parsed.headers.items()
                          if k in ['From', 'To', 'Subject', 'Date', 'Reply-To',
                                   'Return-Path', 'Message-ID', 'Authentication-Results']},
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.exception("Failed to analyze Gmail message %s", message_id[:12])
        if "401" in error_msg or "unauthorized" in error_msg.lower():
            raise HTTPException(status_code=401, detail="Gmail session expired. Please reconnect your account in Settings.")
        raise HTTPException(status_code=500, detail="Unable to analyze this Gmail message. Please try again.")


async def _poll_gmail_background():
    """Background task to poll Gmail for new emails."""
    global _polling_active
    from ..config import settings

    _polling_active = True
    interval = settings.GMAIL_POLL_INTERVAL

    while _polling_active:
        await asyncio.sleep(interval)

        if not _polling_active:
            break

        db = SessionLocal()
        try:
            # Get all connected Gmail users
            tokens = db.query(GmailToken).all()

            for token_record in tokens:
                try:
                    gmail_service = GmailService(token_record.user_email)

                    # Get existing message IDs
                    existing_ids = set(
                        row[0] for row in db.query(EmailAnalysis.email_id)
                        .filter(EmailAnalysis.source == "gmail")
                        .filter(EmailAnalysis.email_id.isnot(None))
                        .all()
                    )

                    # Check for new messages (last 10)
                    messages = await gmail_service.list_messages(query="in:inbox", max_results=10)

                    for msg in messages:
                        message_id = msg["id"]
                        if message_id in existing_ids:
                            continue

                        try:
                            raw_message, parsed = await gmail_service.fetch_and_parse(message_id)
                            results = engine.analyze(parsed)
                            thread_id = raw_message.get("threadId")

                            _store_gmail_analysis(
                                parsed, results, db, message_id, thread_id,
                                raw_message=raw_message,
                            )
                        except Exception as e:
                            logger.warning("Polling: failed to process %s: %s", message_id[:12], type(e).__name__)
                            continue

                except Exception as e:
                    logger.warning("Polling: failed for %s: %s", token_record.user_email, type(e).__name__)
                    continue

        finally:
            db.close()


@router.get("/message-content/{analysis_id}")
async def get_gmail_message_content(
    analysis_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Retrieve body content for an analyzed Gmail email whose body was not
    stored at sync time (older analyses).

    Guarantees:
    - Uses the existing server-side Gmail session/token (refresh if needed);
      tokens are never exposed to the frontend.
    - Only messages ALREADY analyzed by PhishGuard can be fetched (the Gmail
      message ID is resolved from the stored analysis row, never from user
      input), so this cannot be used to read arbitrary mailbox content.
    - Never creates duplicate analysis records — fills the body fields on the
      existing row only; risk score, classification and timestamps untouched.
    - Read-only: the Gmail message itself is never modified or deleted.
    - If Gmail is unavailable, returns {"available": false} and the UI keeps
      showing the stored security analysis.
    """
    session_id = request.cookies.get("phishguard_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not connected to Gmail")

    user_email = get_session_user(session_id)
    if not user_email:
        raise HTTPException(status_code=401, detail="Gmail session expired. Please reconnect your account in Settings.")

    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis or analysis.source != "gmail":
        raise HTTPException(status_code=404, detail="Email analysis not found")

    # Already have the body (e.g. newly synced email) — nothing to fetch.
    if analysis.body_text or analysis.body_html:
        return {
            "available": True,
            "cached": True,
            "body_text": analysis.body_text or "",
            "body_html": analysis.body_html or "",
        }

    gmail_message_id = analysis.email_id
    if not gmail_message_id:
        return {"available": False, "reason": "NOT_IN_GMAIL",
                "message": "Email content is currently unavailable. The stored security analysis is still available."}

    try:
        gmail_service = GmailService(user_email)
    except ValueError:
        raise HTTPException(status_code=401, detail="Gmail session expired. Please reconnect your account in Settings.")

    try:
        raw_message, parsed = await gmail_service.fetch_and_parse(gmail_message_id)
    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.warning("Content re-fetch failed for %s: %s", analysis_id[:12], type(e).__name__)
        if "404" in error_msg or "not found" in error_msg.lower():
            # Message no longer exists in Gmail (deleted/archived by user).
            return {"available": False, "reason": "NOT_IN_GMAIL",
                    "message": "Email content is currently unavailable. The stored security analysis is still available."}
        if "401" in error_msg or "unauthorized" in error_msg.lower() or "invalid_grant" in error_msg.lower():
            raise HTTPException(status_code=401, detail="Gmail session expired. Please reconnect your account in Settings.")
        return {"available": False, "reason": "GMAIL_UNAVAILABLE",
                "message": "Email content is currently unavailable. The stored security analysis is still available."}

    # Fill in the missing body on the EXISTING row — no new records, and the
    # deterministic analysis result is not recalculated or altered.
    analysis.body_text = (parsed.body_text or "")[:50000]
    analysis.body_html = (parsed.body_html or "")[:100000]
    # Backfill attachment metadata only when it was missing entirely.
    if not analysis.attachment_info or analysis.attachment_info == "[]":
        analysis.attachment_info = json.dumps(parsed.attachments)
    db.commit()

    return {
        "available": True,
        "cached": False,
        "body_text": analysis.body_text or "",
        "body_html": analysis.body_html or "",
    }


@router.post("/start-polling")
async def start_polling(request: Request):
    """Start background Gmail polling."""
    global _polling_task, _polling_active

    session_id = request.cookies.get("phishguard_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not connected to Gmail")

    user_email = get_session_user(session_id)
    if not user_email:
        raise HTTPException(status_code=401, detail="Invalid session")

    if _polling_task and not _polling_task.done():
        return {"status": "already_polling"}

    _polling_task = asyncio.create_task(_poll_gmail_background())
    return {"status": "started"}


@router.post("/stop-polling")
async def stop_polling():
    """Stop background Gmail polling."""
    global _polling_active
    _polling_active = False
    return {"status": "stopped"}
