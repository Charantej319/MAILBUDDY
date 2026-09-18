"""
Session and OAuth state stores backed by SQLite.

Sessions survive server restarts and `uvicorn --reload` (the previous
in-memory dict silently dropped every session on reload, which broke the
Gmail connection right after the Google callback).
"""

import uuid
import secrets
from datetime import datetime, timedelta

from sqlalchemy import Column, String, DateTime

from ..database.connection import Base, SessionLocal


class OAuthSession(Base):
    """Server-side session. The browser only ever sees a random session ID cookie."""

    __tablename__ = "oauth_sessions"

    session_id = Column(String, primary_key=True)
    user_email = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


class OAuthState(Base):
    """Single-use CSRF state parameter for the Google OAuth flow."""

    __tablename__ = "oauth_states"

    state = Column(String, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


def create_session(user_email: str) -> str:
    """Create a session ID for a user (valid for 7 days)."""
    session_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        db.add(OAuthSession(
            session_id=session_id,
            user_email=user_email,
            expires_at=datetime.utcnow() + timedelta(days=7),
        ))
        # Housekeeping: drop expired sessions.
        db.query(OAuthSession).filter(OAuthSession.expires_at < datetime.utcnow()).delete()
        db.commit()
    finally:
        db.close()
    return session_id


def get_session_user(session_id: str | None) -> str | None:
    """Get user email from session ID, or None if missing/expired."""
    if not session_id:
        return None
    db = SessionLocal()
    try:
        row = db.query(OAuthSession).filter(
            OAuthSession.session_id == session_id
        ).first()
        if not row or row.expires_at < datetime.utcnow():
            return None
        return row.user_email
    finally:
        db.close()


def remove_session(session_id: str | None):
    """Remove a session."""
    if not session_id:
        return
    db = SessionLocal()
    try:
        db.query(OAuthSession).filter(OAuthSession.session_id == session_id).delete()
        db.commit()
    finally:
        db.close()


def create_oauth_state() -> str:
    """Create a single-use CSRF state parameter (valid for 10 minutes)."""
    state = secrets.token_urlsafe(32)
    db = SessionLocal()
    try:
        db.add(OAuthState(
            state=state,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        ))
        # Housekeeping: drop expired states.
        db.query(OAuthState).filter(OAuthState.expires_at < datetime.utcnow()).delete()
        db.commit()
    finally:
        db.close()
    return state


def consume_oauth_state(state: str | None) -> bool:
    """
    Validate and consume a state parameter (single use).
    Returns True only if the state exists, is unexpired, and has not been used.
    """
    if not state:
        return False
    db = SessionLocal()
    try:
        row = db.query(OAuthState).filter(OAuthState.state == state).first()
        if not row or row.expires_at < datetime.utcnow():
            return False
        db.delete(row)
        db.commit()
        return True
    finally:
        db.close()
