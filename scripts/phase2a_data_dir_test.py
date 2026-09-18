"""Phase 2a verification: PHISHGUARD_DATA_DIR override behavior.

Run from project root:
    python scripts/phase2a_data_dir_test.py            # override test (temp dir)
    python scripts/phase2a_data_dir_test.py --dev-mode # unset-mode assertions

Two separate processes are REQUIRED: settings/_DATA_DIR are resolved at import
time, so each mode must be validated with a fresh interpreter.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

results = []

def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))

data_dir = os.environ.get("PHISHGUARD_DATA_DIR", "")
dev_mode = "--dev-mode" in sys.argv

from sqlalchemy import text

from backend.app.config import settings, _DATA_DIR  # resolved at import time
from backend.app.database.connection import init_db, SessionLocal
from backend.app.models.email import EmailAnalysis
from backend.app.utils.timeutil import utc_now

if dev_mode:
    # ── Unset mode: development paths exactly as before Phase 2a ──────
    check("PHISHGUARD_DATA_DIR unset -> _DATA_DIR is None", _DATA_DIR is None)
    backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend")
    expected_db = os.path.abspath(os.path.join(backend_dir, "phishguard.db"))
    check("dev-mode: DATABASE_URL points at backend/phishguard.db",
          os.path.normcase(os.path.abspath(settings.DATABASE_URL.replace("sqlite:///", ""))) == os.path.normcase(expected_db),
          settings.DATABASE_URL[:60])
    check("dev-mode: UPLOAD_DIR unchanged", str(settings.UPLOAD_DIR) == "uploads", str(settings.UPLOAD_DIR))
    # Existing dev DB still readable, schema intact (ai_status column present).
    db = SessionLocal()
    cols = [c[1] for c in db.execute(text("PRAGMA table_info(email_analyses)")).fetchall()]
    check("dev-mode: existing dev DB opens and keeps ai_status column", "ai_status" in cols, f"{len(cols)} columns")
    n = db.query(EmailAnalysis).count()
    check("dev-mode: existing dev rows untouched", n > 0, f"{n} rows")
    db.close()
else:
    # ── Override mode: temp dir ────────────────────────────────────────
    check("PHISHGUARD_DATA_DIR set -> _DATA_DIR resolves to it",
          _DATA_DIR is not None and os.path.samefile(_DATA_DIR, data_dir), str(_DATA_DIR))
    check("override: DATABASE_URL points inside data dir",
          os.path.normcase(os.path.realpath(settings.DATABASE_URL.replace("sqlite:///", "")))
          == os.path.normcase(os.path.realpath(os.path.join(data_dir, "phishguard.db"))),
          settings.DATABASE_URL[:70])
    check("override: UPLOAD_DIR is <DATA_DIR>/uploads",
          os.path.normcase(os.path.realpath(settings.UPLOAD_DIR))
          == os.path.normcase(os.path.realpath(os.path.join(data_dir, "uploads"))), str(settings.UPLOAD_DIR))
    check("override: uploads dir auto-created", os.path.isdir(os.path.join(data_dir, "uploads")))

    # init_db must create the schema in the NEW location, schema identical.
    init_db()
    db_path = os.path.join(data_dir, "phishguard.db")
    check("override: phishguard.db created in data dir", os.path.isfile(db_path))
    db = SessionLocal()
    cols = [c[1] for c in db.execute(text("PRAGMA table_info(email_analyses)")).fetchall()]
    expected_cols = {"id", "email_id", "sender", "risk_score", "classification", "ai_status",
                     "ai_verdict", "ai_confidence", "ai_summary", "ai_analyzed_at", "analyzed_at"}
    check("override: schema identical (incl. AI columns)", expected_cols.issubset(set(cols)), f"{len(cols)} columns")
    # Round-trip one row to prove usability — then delete it (no residue).
    row = EmailAnalysis(
        id="phase2a-dd-test", email_id="phase2a-dd-msg", source="raw",
        sender="t", sender_email="t@t.com", sender_domain="t.com",
        risk_score=1, classification="SAFE", analyzed_at=utc_now(), created_at=utc_now(),
    )
    db.add(row); db.commit(); db.query(EmailAnalysis).filter(EmailAnalysis.id == "phase2a-dd-test").delete(); db.commit()
    check("override: insert/delete round-trip works in new DB", True)
    db.close()

    # Config loading from <DATA_DIR>/.env — write a harmless marker var.
    with open(os.path.join(data_dir, ".env"), "w", encoding="utf-8") as fh:
        fh.write("AI_ENABLED=true\n")
    check("override: .env written to data dir", os.path.isfile(os.path.join(data_dir, ".env")))

    # Dev database untouched by the override run.
    dev_db = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "phishguard.db"))
    check("override: dev backend/phishguard.db still exists", os.path.isfile(dev_db))

print(f"\n{'=' * 60}\nDATA-DIR TEST ({'dev-mode' if dev_mode else 'override'}): {sum(results and [1 for _, ok in results if ok] or [0])}/{len(results)} passed")
sys.exit(0 if all(ok for _, ok in results) else 1)
