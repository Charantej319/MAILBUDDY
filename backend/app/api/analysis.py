"""
API endpoints for email analysis.
Handles .eml upload, Gmail message analysis, and result retrieval.
Enhanced with confidence and intelligence data.
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger("phishguard.api")


def _parse_date(date_str: str):
    """Parse an email Date header into an aware UTC datetime."""
    from ..utils.timeutil import utc_now, parse_iso
    if not date_str:
        return utc_now()
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
    except Exception:
        dt = parse_iso(date_str)
        if dt is None:
            return utc_now()
    if dt.tzinfo is None:
        # Date headers without an explicit zone are ambiguous; assume UTC.
        from datetime import timezone
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _utcnow():
    from ..utils.timeutil import utc_now
    return utc_now()

from ..database.connection import get_db
from ..models.email import EmailAnalysis
from ..parser.email_parser import parse_eml_content
from detection.engine import DetectionEngine

router = APIRouter()
engine = DetectionEngine()


class AnalyzeURLRequest(BaseModel):
    """Request body for analyzing raw email content."""
    email_content: str


class AnalysisResponse(BaseModel):
    """Response from analysis."""
    id: str
    risk_score: float
    classification: str
    confidence_level: str
    confidence_numeric: float
    findings: list
    categorized_findings: dict
    recommended_actions: list
    summary: str
    email_info: dict


def _store_analysis(parsed_email, results: dict, db: Session,
                    source: str = "eml", email_id: str = None) -> EmailAnalysis:
    """Store analysis results in the database."""
    analysis = EmailAnalysis(
        id=str(uuid.uuid4()),
        email_id=email_id or str(uuid.uuid4()),
        source=source,
        sender=parsed_email.sender,
        sender_email=parsed_email.sender_email,
        sender_domain=parsed_email.sender_domain,
        recipient=parsed_email.recipient,
        subject=parsed_email.subject,
        date=_parse_date(parsed_email.date),
        risk_score=results["risk_score"],
        classification=results["classification"],
        confidence_level=results.get("confidence_level", "LOW"),
        confidence_numeric=results.get("confidence_numeric", 0.0),
        detection_findings=json.dumps(results["findings"]),
        extracted_urls=json.dumps(parsed_email.urls),
        attachment_info=json.dumps(parsed_email.attachments),
        header_findings=json.dumps(results["categorized_findings"].get("HEADER", [])),
        recommended_actions=json.dumps(results.get("recommended_actions", [])),
        analysis_summary=results.get("summary", ""),
        # Body content is stored for display only (truncated to bound size).
        body_text=(parsed_email.body_text or "")[:50000],
        body_html=(parsed_email.body_html or "")[:100000],
        message_id_header=parsed_email.message_id,
        analyzed_at=_utcnow(),
        created_at=_utcnow(),
    )

    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    return analysis


@router.post("/analyze/eml", response_model=None)
async def analyze_eml_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload and analyze an .eml file."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    if not file.filename.lower().endswith('.eml'):
        raise HTTPException(status_code=400, detail="File must be an .eml file")

    content = await file.read()

    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")

    try:
        parsed_email = parse_eml_content(content)
        results = engine.analyze(parsed_email)
        analysis = _store_analysis(parsed_email, results, db, source="eml")

        return {
            "id": analysis.id,
            "risk_score": results["risk_score"],
            "classification": results["classification"],
            "confidence_level": results["confidence_level"],
            "confidence_numeric": results["confidence_numeric"],
            "findings": results["findings"],
            "top_findings": results["top_findings"],
            "categorized_findings": results["categorized_findings"],
            "recommended_actions": results["recommended_actions"],
            "summary": results["summary"],
            "email_info": {
                "sender": parsed_email.sender,
                "sender_email": parsed_email.sender_email,
                "sender_domain": parsed_email.sender_domain,
                "subject": parsed_email.subject,
                "date": parsed_email.date,
                "urls": parsed_email.urls,
                "attachments": parsed_email.attachments,
                "headers": {k: v for k, v in parsed_email.headers.items()
                          if k in ['From', 'To', 'Subject', 'Date', 'Reply-To',
                                   'Return-Path', 'Message-ID', 'Authentication-Results',
                                   'Received']},
            },
        }

    except Exception as e:
        # Log full detail server-side; return a safe, generic message.
        logger.exception("Failed to analyze uploaded .eml file")
        raise HTTPException(status_code=500, detail="Unable to analyze email. Please check the file and try again.")


@router.post("/analyze/raw", response_model=None)
async def analyze_raw_email(
    request: AnalyzeURLRequest,
    db: Session = Depends(get_db),
):
    """Analyze raw email content (for testing)."""
    try:
        parsed_email = parse_eml_content(request.email_content)
        results = engine.analyze(parsed_email)
        analysis = _store_analysis(parsed_email, results, db, source="raw")

        return {
            "id": analysis.id,
            "risk_score": results["risk_score"],
            "classification": results["classification"],
            "confidence_level": results["confidence_level"],
            "confidence_numeric": results["confidence_numeric"],
            "findings": results["findings"],
            "top_findings": results["top_findings"],
            "categorized_findings": results["categorized_findings"],
            "recommended_actions": results["recommended_actions"],
            "summary": results["summary"],
            "email_info": {
                "sender": parsed_email.sender,
                "sender_email": parsed_email.sender_email,
                "sender_domain": parsed_email.sender_domain,
                "subject": parsed_email.subject,
                "date": parsed_email.date,
                "urls": parsed_email.urls,
                "attachments": parsed_email.attachments,
                "headers": {k: v for k, v in parsed_email.headers.items()
                          if k in ['From', 'To', 'Subject', 'Date', 'Reply-To',
                                   'Return-Path', 'Message-ID', 'Authentication-Results']},
            },
        }

    except Exception as e:
        logger.exception("Failed to analyze raw email content")
        raise HTTPException(status_code=500, detail="Unable to analyze email. Please check the content and try again.")


@router.get("/emails")
async def get_analyzed_emails(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Get all analyzed emails with summary info."""
    emails = db.query(EmailAnalysis).order_by(EmailAnalysis.analyzed_at.desc()).offset(skip).limit(limit).all()
    return {
        "emails": [email.to_dict() for email in emails],
        "total": db.query(EmailAnalysis).count(),
    }


@router.get("/emails/{analysis_id}")
async def get_email_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    """
    Get detailed analysis for a specific email by internal analysis ID.

    Includes stored body content, full headers, summary, recommended
    actions and any AI verification block. Returns a safe 404 for
    unknown IDs (internal IDs are UUIDs; malformed ones can't match).
    """
    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Email analysis not found. It may have been deleted.")

    data = analysis.to_dict()

    # Attach selected raw headers for the detail view (From/To/Subject/Date
    # etc. are already top-level; add auth + routing headers).
    header_findings = data.get("header_findings") or []
    data["auth_evidence"] = [
        f for f in header_findings
        if isinstance(f, dict) and str(f.get("rule_id", "")).startswith("HEADER_")
    ]
    return data


@router.delete("/emails/{analysis_id}")
async def delete_email_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    """Delete an email analysis."""
    analysis = db.query(EmailAnalysis).filter(EmailAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    db.delete(analysis)
    db.commit()

    return {"message": "Analysis deleted successfully"}


@router.get("/statistics")
async def get_statistics(db: Session = Depends(get_db)):
    """Get aggregate statistics about analyzed emails."""
    total = db.query(EmailAnalysis).count()

    if total == 0:
        return {
            "total_emails": 0,
            "safe_count": 0,
            "low_risk_count": 0,
            "suspicious_count": 0,
            "high_risk_count": 0,
            "risk_distribution": {},
            "top_sender_domains": [],
            "recent_analyses": [],
        }

    safe_count = db.query(EmailAnalysis).filter(EmailAnalysis.classification == "SAFE").count()
    low_risk_count = db.query(EmailAnalysis).filter(EmailAnalysis.classification == "LOW RISK").count()
    suspicious_count = db.query(EmailAnalysis).filter(EmailAnalysis.classification == "SUSPICIOUS").count()
    high_risk_count = db.query(EmailAnalysis).filter(EmailAnalysis.classification == "HIGH RISK").count()

    risk_distribution = {
        "SAFE": safe_count,
        "LOW RISK": low_risk_count,
        "SUSPICIOUS": suspicious_count,
        "HIGH RISK": high_risk_count,
    }

    # Get top sender domains
    from sqlalchemy import func
    top_domains = (
        db.query(EmailAnalysis.sender_domain, func.count(EmailAnalysis.sender_domain))
        .group_by(EmailAnalysis.sender_domain)
        .order_by(func.count(EmailAnalysis.sender_domain).desc())
        .limit(10)
        .all()
    )

    # Get recent analyses
    recent = db.query(EmailAnalysis).order_by(EmailAnalysis.analyzed_at.desc()).limit(10).all()

    # Get recent threats (HIGH RISK or SUSPICIOUS)
    recent_threats = (
        db.query(EmailAnalysis)
        .filter(EmailAnalysis.classification.in_(["HIGH RISK", "SUSPICIOUS"]))
        .order_by(EmailAnalysis.analyzed_at.desc())
        .limit(5)
        .all()
    )

    return {
        "total_emails": total,
        "safe_count": safe_count,
        "low_risk_count": low_risk_count,
        "suspicious_count": suspicious_count,
        "high_risk_count": high_risk_count,
        "risk_distribution": risk_distribution,
        "top_sender_domains": [{"domain": d[0], "count": d[1]} for d in top_domains],
        "recent_analyses": [e.to_dict() for e in recent],
        "recent_threats": [e.to_dict() for e in recent_threats],
    }


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "PhishGuard API", "version": "1.0.0"}
