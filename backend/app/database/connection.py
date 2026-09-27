"""
SQLite database connection and session management.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from ..config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},  # SQLite specific
    # SQL echo is disabled by default: DEBUG-level SQL logs render INSERT
    # parameters, including OAuth access/refresh tokens, into the console.
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency that provides a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all database tables."""
    # Import model modules first so every table is registered on
    # Base.metadata regardless of the caller's import order.
    from ..models.email import EmailAnalysis, GmailToken  # noqa: F401
    from ..models.email import ApiToken  # noqa: F401  (local API bearer token digests)
    from ..auth.sessions import OAuthSession, OAuthState  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _migrate_schema()


# Columns added to the models after the schema was first created.
# create_all() never alters existing tables, so older SQLite files need
# these added explicitly. Values are constant DEFAULT clauses for SQLite.
_MIGRATION_DEFAULTS = {
    "email_analyses": {
        "confidence_level": "VARCHAR DEFAULT 'LOW'",
        "confidence_numeric": "FLOAT DEFAULT 0",
        "recommended_actions": "TEXT",
        "analysis_summary": "TEXT",
        "body_text": "TEXT",
        "body_html": "TEXT",
        "message_id_header": "VARCHAR",
        "ai_status": "VARCHAR DEFAULT 'NOT_REQUESTED'",
        "ai_verdict": "VARCHAR",
        "ai_confidence": "FLOAT",
        "ai_summary": "TEXT",
        "ai_reasons": "TEXT",
        "ai_recommended_action": "VARCHAR",
        "ai_model": "VARCHAR",
        "ai_analyzed_at": "DATETIME",
        # F-16 account isolation: owner of the analyzed email (authenticated
        # account identity). NULL = pre-isolation legacy row.
        "owner_account": "VARCHAR",
    },
}


def _migrate_schema():
    """Add columns that exist on the models but are missing in older SQLite files."""
    from ..models.email import EmailAnalysis, GmailToken

    db = SessionLocal()
    try:
        for model in (EmailAnalysis, GmailToken):
            table = model.__tablename__
            existing = {row[1] for row in db.execute(text(f"PRAGMA table_info({table})"))}
            if not existing:
                continue  # table created fresh by create_all
            defaults = {}
            for column in model.__table__.columns:
                if column.name in existing:
                    continue
                col_type = _MIGRATION_DEFAULTS.get(table, {}).get(column.name)
                if col_type is None:
                    col_type = column.type.compile(engine.dialect)
                db.execute(text(f"ALTER TABLE {table} ADD COLUMN {column.name} {col_type}"))
        db.commit()
    finally:
        db.close()
