"""
MailBuddy API routes.

All endpoints are read-only with respect to email. No endpoint here can
send, reply, forward, delete, move, archive, or label email. No endpoint
returns or accepts secrets; the Groq key never leaves the backend process.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database.connection import get_db
from ..models.email import EmailAnalysis
from . import assistant, priority_ai, service
from .priority import VALID_CATEGORIES, VALID_LEVELS

logger = logging.getLogger("phishguard.mailbuddy")

router = APIRouter(prefix="/api/mailbuddy")


# ---- Schemas ---------------------------------------------------------------

class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=500)
    # Optional id (analysis id or Gmail message id) of the email the user is
    # currently viewing. The backend loads the email itself — the client never
    # submits email content or mailbox data.
    email_id: str | None = Field(default=None, max_length=200)


class ChatMessage(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(min_length=1, max_length=2000)


class ChatContextRequest(BaseModel):
    messages: list[ChatMessage] = Field(default_factory=list, max_length=12)


class PriorityAnalyzeRequest(BaseModel):
    force: bool = False


class SettingsUpdate(BaseModel):
    assistant_enabled: bool | None = None
    smart_priority_enabled: bool | None = None
    important_notifications_enabled: bool | None = None
    desktop_notifications_enabled: bool | None = None


# ---- Priority ---------------------------------------------------------------

@router.get("/priority/summary")
def priority_summary(db: Session = Depends(get_db)):
    """Counts by priority level + attention list for the dashboard."""
    levels = {lvl: 0 for lvl in VALID_LEVELS}
    rows = db.query(EmailAnalysis.priority_level, EmailAnalysis.id).all()
    for (level, _id) in rows:
        if level in levels:
            levels[level] += 1
    attention = (
        db.query(EmailAnalysis)
        .filter(EmailAnalysis.priority_level.in_(("CRITICAL", "HIGH")))
        .order_by(
            EmailAnalysis.priority_level.asc(),  # CRITICAL < HIGH alphabetically
            EmailAnalysis.created_at.desc(),
        )
        .limit(12)
        .all()
    )
    return {
        "counts": levels,
        "attention": [
            {
                "id": a.id,
                "email_id": a.email_id,
                "sender": a.sender,
                "subject": a.subject,
                "priority": a.priority_level,
                "category": a.priority_category,
                "security": a.classification,
                "risk_score": a.risk_score,
                "deadline": a.priority_deadline.date().isoformat() if a.priority_deadline else None,
                "reasons": service.json_or_empty(a.priority_reasons),
                "summary": a.priority_summary,
                "date": a.created_at.isoformat() + "Z" if a.created_at else None,
            }
            for a in attention
        ],
        "pending": db.query(EmailAnalysis)
                      .filter(EmailAnalysis.priority_level.is_(None)).count(),
    }


@router.get("/priority/emails")
def priority_emails(level: str | None = None, category: str | None = None,
                    limit: int = 50, db: Session = Depends(get_db)):
    """Emails filtered by priority level and/or category (newest first)."""
    q = db.query(EmailAnalysis).order_by(EmailAnalysis.created_at.desc())
    if level:
        if level.upper() not in VALID_LEVELS:
            raise HTTPException(status_code=422, detail=f"invalid level: {level}")
        q = q.filter(EmailAnalysis.priority_level == level.upper())
    if category:
        if category.upper() not in VALID_CATEGORIES:
            raise HTTPException(status_code=422, detail=f"invalid category: {category}")
        q = q.filter(EmailAnalysis.priority_category == category.upper())
    rows = q.limit(min(limit, 100)).all()
    return {
        "emails": [
            {
                "id": r.id,
                "email_id": r.email_id,
                "sender": r.sender,
                "sender_email": r.sender_email,
                "subject": r.subject,
                "priority": r.priority_level,
                "category": r.priority_category,
                "security": r.classification,
                "risk_score": r.risk_score,
                "deadline": r.priority_deadline.date().isoformat() if r.priority_deadline else None,
                "summary": r.priority_summary,
                "date": r.created_at.isoformat() + "Z" if r.created_at else None,
            }
            for r in rows
        ]
    }


@router.post("/priority/analyze/{analysis_id}")
async def analyze_priority(analysis_id: str, body: PriorityAnalyzeRequest | None = None,
                           db: Session = Depends(get_db)):
    """Analyze (or re-analyze with force) one email's priority. Cached by default."""
    row = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="email analysis not found")
    force = bool(body.force) if body else False
    row = await service.analyze_and_store(row, db, force=force)
    service.queue_notifications(db, row)
    return {"id": row.id, "priority": row.priority_to_dict()}


@router.post("/priority/analyze-batch")
async def analyze_batch(body: dict | None = None, db: Session = Depends(get_db)):
    """Bounded batch analysis for unanalyzed emails (rate-limit safe)."""
    limit = min(int((body or {}).get("limit", 10)), 25)
    rows = service.rows_needing_analysis(db, limit=limit)
    done = 0
    for row in rows:
        await service.analyze_and_store(row, db)
        service.queue_notifications(db, row)
        done += 1
    remaining = db.query(EmailAnalysis).filter(EmailAnalysis.priority_level.is_(None)).count()
    return {"analyzed": done, "remaining": remaining}


# ---- Assistant ---------------------------------------------------------------

@router.post("/assistant/chat")
async def assistant_chat(body: ChatRequest, db: Session = Depends(get_db)):
    """Ask the read-only MailBuddy Assistant about your inbox.

    With email_id: grounded answer about THAT email (backend loads it).
    Without: intent-routed mailbox question over a bounded candidate set.
    """
    enabled = service.get_setting(db, "assistant_enabled")
    if enabled != "true":
        raise HTTPException(status_code=409, detail="MailBuddy Assistant is disabled in Settings")
    if body.email_id:
        return await assistant.answer_about_email(db, body.email_id, body.question)
    result = await assistant.answer_question(db, body.question)
    return result


@router.post("/assistant/chat/context")
async def assistant_chat_context(body: ChatContextRequest, db: Session = Depends(get_db)):
    """Chat with client-provided conversation context (stateless variant)."""
    enabled = service.get_setting(db, "assistant_enabled")
    if enabled != "true":
        raise HTTPException(status_code=409, detail="MailBuddy Assistant is disabled in Settings")
    history = [{"role": m.role, "content": m.content} for m in body.messages]
    question = history[-1]["content"] if history else ""
    if not question:
        raise HTTPException(status_code=422, detail="no user message provided")
    rows, intent = assistant.retrieve(db, question)
    deterministic = assistant._deterministic_answer(rows, intent, question)
    phrased = await assistant._phrase_with_ai(question, rows, history)
    answer = phrased["answer"] if phrased else deterministic
    refs = (phrased["refs"] if phrased else None) or list(range(1, len(rows) + 1))
    referenced = []
    for i in refs:
        if 1 <= i <= len(rows):
            row = rows[i - 1]
            referenced.append({
                "id": row.id,
                "email_id": row.email_id,
                "sender": row.sender,
                "subject": row.subject,
                "priority": row.priority_level,
                "category": row.priority_category,
                "security": row.classification,
                "deadline": row.priority_deadline.date().isoformat() if row.priority_deadline else None,
                "url": f"/emails/{row.id}",
            })
    return {"answer": answer, "intent": intent, "references": referenced,
            "grounded": bool(rows),
            "model": (f"groq:{assistant._groq_cfg()['model']}" if (phrased and assistant._groq_cfg()) else "deterministic")}


@router.get("/assistant/history")
def assistant_history():
    """Recent in-memory conversation (best-effort, per backend process)."""
    return {"messages": assistant.chat_history()}


@router.post("/assistant/clear")
def assistant_clear():
    """Clear the current in-memory chat (Settings: 'Clear current chat')."""
    assistant.clear_history()
    return {"cleared": True}


# ---- Notifications ------------------------------------------------------------

@router.get("/notifications/pending")
def notifications_pending(db: Session = Depends(get_db)):
    enabled = service.get_setting(db, "important_notifications_enabled") == "true" \
        and service.get_setting(db, "desktop_notifications_enabled") == "true"
    items = service.pending_notifications(db) if enabled else []
    return {"enabled": enabled, "notifications": items}


@router.post("/notifications/ack")
def notifications_ack(body: dict, db: Session = Depends(get_db)):
    keys = [k for k in (body or {}).get("keys", []) if isinstance(k, str)]
    return {"marked": service.mark_delivered(db, keys)}


# ---- Settings -------------------------------------------------------------------

@router.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    return {
        "settings": service.get_settings(db),
        "ai_priority_configured": priority_ai.is_configured(),
    }


@router.put("/settings")
def update_settings(body: SettingsUpdate, db: Session = Depends(get_db)):
    updates = body.model_dump(exclude_none=True)
    for key, value in updates.items():
        service.set_setting(db, key, value)
    return {"settings": service.get_settings(db)}
