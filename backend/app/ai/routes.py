"""
AI verification API endpoints.

POST /api/ai/verify/{analysis_id}
    Runs the optional AI second-opinion verifier against the stored
    deterministic analysis and persists the result on the record.
    The deterministic analysis is NEVER modified.

GET /api/ai/status
    Reports whether AI verification is configured (no secrets returned).
"""

import logging

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from ..database.connection import get_db
from ..models.email import EmailAnalysis
from . import verifier

logger = logging.getLogger("phishguard.ai")

router = APIRouter(prefix="/api/ai")


@router.get("/status")
async def ai_status():
    """Whether AI verification is configured. Exposes no secrets."""
    return {
        "configured": verifier.is_configured(),
        "model": verifier.get_model_name(),
    }


@router.post("/verify/{analysis_id}")
async def ai_verify(analysis_id: str, db: Session = Depends(get_db)):
    """Run AI verification for one stored analysis (second opinion only)."""
    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    if not verifier.is_configured():
        return {
            "ai": {
                "status": "UNAVAILABLE",
                "error": "AI verification is not configured. The deterministic analysis below is complete.",
                "verdict": None,
                "confidence": None,
                "summary": None,
                "reasons": [],
                "recommended_action": None,
                "model": None,
                "analyzed_at": None,
            }
        }

    payload = verifier.build_verifier_payload(
        sender=analysis.sender,
        sender_domain=analysis.sender_domain,
        recipient=analysis.recipient or "",
        subject=analysis.subject or "",
        urls=_safe_json(analysis.extracted_urls, []),
        auth=_auth_summary(analysis),
        attachments=_safe_json(analysis.attachment_info, []),
        indicators=_safe_json(analysis.detection_findings, []),
        body_text=analysis.body_text or "",
        rule_score=analysis.risk_score or 0.0,
        rule_classification=analysis.classification or "SAFE",
    )

    result = await verifier.verify_email(payload)
    status = verifier.correlate(analysis.classification or "SAFE", analysis.risk_score or 0.0, result)

    # Persist the AI block on the record (deterministic fields untouched).
    analysis.ai_status = status
    analysis.ai_verdict = result.verdict
    analysis.ai_confidence = result.confidence
    analysis.ai_summary = result.summary
    analysis.ai_reasons = __import__("json").dumps(result.reasons) if result.reasons else None
    analysis.ai_recommended_action = result.recommended_action
    analysis.ai_model = result.model
    if result.status == "VERIFIED":
        from ..utils.timeutil import utc_now
        analysis.ai_analyzed_at = utc_now()
    elif status == "UNAVAILABLE":
        analysis.ai_analyzed_at = None
    db.commit()

    return {"ai": {
        "status": status,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "summary": result.summary,
        "reasons": result.reasons,
        "recommended_action": result.recommended_action,
        "model": result.model,
        "error": result.error,
        "analyzed_at": analysis.ai_analyzed_at.isoformat() + "Z" if analysis.ai_analyzed_at else None,
        "disagreement": status == "DISAGREEMENT",
    }}


def _safe_json(raw, default):
    import json
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default


def _auth_summary(analysis: EmailAnalysis) -> dict:
    """Extract SPF/DKIM/DMARC summary from stored header findings."""
    auth = {}
    for f in _safe_json(analysis.header_findings, []):
        rule = f.get("rule_id", "")
        if rule == "HEADER_AUTH_ALL_PASS":
            auth = {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        elif rule.startswith("HEADER_SPF"):
            auth["spf"] = rule.replace("HEADER_SPF_", "").lower()
        elif rule.startswith("HEADER_DKIM"):
            auth["dkim"] = rule.replace("HEADER_DKIM_", "").lower()
        elif rule.startswith("HEADER_DMARC"):
            auth["dmarc"] = rule.replace("HEADER_DMARC_", "").lower()
    return auth
