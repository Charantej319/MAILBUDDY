"""Phase 2a browser test launcher: boots the REAL backend (uvicorn in a thread,
production mode serving frontend/dist), picks a real email row, runs the headless
Chrome test against http://localhost:8000, then cleans up.

Run from project root:  python scripts/phase2a_browser_launcher.py
"""
import os
import subprocess
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import uvicorn

from backend.app.main import app  # production mode: frontend/dist detected
from backend.app.database.connection import SessionLocal
from backend.app.models.email import EmailAnalysis

# Pick a real email row (prefer one with a stored body).
db = SessionLocal()
row = (
    db.query(EmailAnalysis)
    .filter(EmailAnalysis.body_text.isnot(None))
    .first()
) or db.query(EmailAnalysis).first()
EMAIL_ID = row.id if row else None
db.close()

if not EMAIL_ID:
    print("FATAL: no email rows in the dev database to test with")
    sys.exit(2)
print(f"Using email row: {EMAIL_ID}")

config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="warning")
server = uvicorn.Server(config)
thread = threading.Thread(target=server.run, daemon=True)
thread.start()
for _ in range(50):
    try:
        urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=1)
        break
    except Exception:
        time.sleep(0.3)
else:
    print("FATAL: backend did not come up")
    sys.exit(2)
print("Backend up on :8000 (production mode)")

env = {**os.environ, "EMAIL_ID": EMAIL_ID, "PYTHONIOENCODING": "utf-8"}
proc = subprocess.run(["node", "frontend/phase2a_browser_test.mjs"], env=env)
exit_code = proc.returncode

server.should_exit = True
thread.join(timeout=5)
sys.exit(exit_code)
