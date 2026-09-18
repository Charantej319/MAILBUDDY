"""
One-off browser-verification orchestrator.

Boots the REAL PhishGuard FastAPI app (real detection engine, real Groq config,
real SQLite DB) with uvicorn in a background thread, plus:
  - a localhost-only control route to toggle AI_ENABLED at runtime
    (so the browser test can exercise the AI-unavailable scenario)
  - a pre-seeded DISAGREEMENT fixture row (classification HIGH RISK 85, AI
    LOW_RISK injected by monkeypatching verifier._call_groq ONLY for the
    fixture's marker subject, then removing the patch)

Then launches frontend/browser_groq_verify.mjs and cleans up the fixture.

Run from project root:  python scripts/browser_verify_orchestrator.py
"""
import json
import os
import subprocess
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import uvicorn

from backend.app.main import app
from backend.app.ai import verifier
from backend.app.database.connection import SessionLocal
from backend.app.models.email import EmailAnalysis
from backend.app.utils.timeutil import utc_now

# ── 1. Load the real Groq env from backend/.env (as production does) ──
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "backend", ".env"))
os.environ["AI_ENABLED"] = "true"
if (os.getenv("AI_PROVIDER") or "").lower() != "groq":
    os.environ["AI_PROVIDER"] = "groq"
if not os.getenv("GROQ_API_KEY"):
    print("FATAL: GROQ_API_KEY missing in backend/.env")
    sys.exit(2)
os.environ.setdefault("AI_MODEL", "openai/gpt-oss-120b")

# ── 2. Disagreement fixture: monkeypatch _call_groq for a marker payload ──
DISAGREE_SUBJECT = "PGX-DISAGREE-FIXTURE"
# The marker MUST appear inside the built payload: the subject is embedded in
# <email_subject>…</email_subject>, so use the subject itself as the marker.
MARKER = DISAGREE_SUBJECT
_orig_call_groq = verifier._call_groq

async def _patched_call_groq(payload, cfg):
    if MARKER in payload:
        return json.dumps({
            "verdict": "LOW_RISK", "confidence": 0.72,
            "reasons": ["No strong phishing indicators on AI review"],
            "recommended_action": "ALLOW",
            "summary": "AI second opinion differs from the rule engine (fixture).",
        })
    return await _orig_call_groq(payload, cfg)  # everything else -> real Groq

verifier._call_groq = _patched_call_groq

# ── 3. Control route (localhost-only dev app instance, not saved to disk) ──
from fastapi import APIRouter

ctrl = APIRouter()

@ctrl.post("/__browsertest__/ai")
async def _toggle_ai(payload: dict):
    os.environ["AI_ENABLED"] = "true" if payload.get("enabled") else "false"
    return {"ok": True, "AI_ENABLED": os.environ["AI_ENABLED"]}

app.include_router(ctrl)

# ── 4. Seed the disagreement fixture row ──────────────────────────────
def make_fixture():
    db = SessionLocal()
    row = EmailAnalysis(
        id="pgx-disagree-" + str(uuid.uuid4())[:8],
        email_id="pgx-disagree-msg-" + str(uuid.uuid4())[:8],
        source="raw",
        sender="no-reply@github.com", sender_email="no-reply@github.com",
        sender_domain="github.com",
        recipient="analyst@phishguard.local",
        subject=DISAGREE_SUBJECT,
        body_text="A third-party OAuth application (CI Tool) was authorized to access your account.",
        extracted_urls=json.dumps(["https://github.com/settings/security"]),
        risk_score=85.0, classification="HIGH RISK",
        analyzed_at=utc_now(), created_at=utc_now(),
    )
    db.add(row)
    db.commit()
    row_id = row.id
    db.close()
    return row_id

FIXTURE_ID = make_fixture()

# Run AI verify for the fixture so ai_status=DISAGREEMENT is persisted up-front
import asyncio
from fastapi.testclient import TestClient  # noqa: E402

with TestClient(app) as tc:  # context manager runs startup (init_db)
    resp = tc.post(f"/api/ai/verify/{FIXTURE_ID}")
    ai_status = resp.json().get("ai", {}).get("status")
    print("fixture verify:", resp.status_code, ai_status)
    if ai_status != "DISAGREEMENT":
        print("FATAL: fixture did not produce DISAGREEMENT — aborting")
        sys.exit(2)

# ── 5. Start the real server and launch the browser test ─────────────
config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="warning")
server = uvicorn.Server(config)
thread = threading.Thread(target=server.run, daemon=True)
thread.start()
for _ in range(50):
    try:
        import urllib.request
        urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=1)
        break
    except Exception:
        time.sleep(0.3)
else:
    print("FATAL: backend did not come up")
    sys.exit(2)

print("Backend up on :8000 — fixture:", FIXTURE_ID)

# ── 5b. Frontend: reuse an already-running vite dev server, else start one ──
import urllib.error

frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")


def _port_up(url):
    try:
        urllib.request.urlopen(url, timeout=1)
        return True
    except urllib.error.HTTPError:
        return True  # server responded (e.g. 404) — it's up
    except Exception:
        return False


vite = None
vite_log = None
exit_code = 1
try:
    # vite may bind IPv6-only (localhost), so probe with localhost, not 127.0.0.1
    if _port_up("http://localhost:5173/"):
        print("Frontend already running on :5173 — reusing it")
    else:
        vite_log_path = os.path.join(os.path.dirname(__file__), "..", ".vite_orchestrator.log")
        vite_log = open(vite_log_path, "w", encoding="utf-8")
        vite = subprocess.Popen(
            ["npm", "run", "dev", "--", "--port", "5173", "--strictPort"],
            cwd=frontend_dir,
            stdout=vite_log, stderr=subprocess.STDOUT,
            env={**os.environ, "BROWSER": "none"},
            shell=True,  # npm is a .cmd on Windows
        )
        came_up = False
        for _ in range(120):  # up to 60s
            if _port_up("http://localhost:5173/"):
                came_up = True
                break
            time.sleep(0.5)
        if not came_up:
            vite_log.flush()
            print("FATAL: vite dev server did not come up; log tail:")
            with open(vite_log_path, encoding="utf-8", errors="replace") as fh:
                print("".join(fh.readlines()[-25:]))
            sys.exit(2)
        print("Frontend started on :5173")

    env = {**os.environ, "DISAGREE_ID": FIXTURE_ID, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(["node", "frontend/browser_groq_verify.mjs"], env=env)
    exit_code = proc.returncode
finally:
    if vite is not None:
        vite.terminate()
        try:
            vite.wait(timeout=10)
        except Exception:
            vite.kill()
    if vite_log is not None:
        vite_log.close()

# ── 6. Cleanup: delete fixture row, stop server, unpatch ─────────────
db = SessionLocal()
row = db.query(EmailAnalysis).filter(EmailAnalysis.id == FIXTURE_ID).first()
if row:
    db.delete(row)
db.commit()
db.close()
verifier._call_groq = _orig_call_groq
server.should_exit = True
thread.join(timeout=5)
sys.exit(exit_code)
