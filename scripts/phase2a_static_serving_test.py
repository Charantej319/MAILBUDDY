"""Phase 2a verification: FastAPI serves frontend/dist with SPA fallback.

Run from project root:  python scripts/phase2a_static_serving_test.py
Uses TestClient (in-process) against the real app. No secrets involved.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import re
import uuid

from fastapi.testclient import TestClient

from backend.app.main import app, _HAS_FRONTEND_BUILD, _FRONTEND_DIST
from backend.app.database.connection import SessionLocal
from backend.app.models.email import EmailAnalysis
from backend.app.utils.timeutil import utc_now

results = []

def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))

print(f"frontend/dist detected: {_HAS_FRONTEND_BUILD} ({_FRONTEND_DIST})")

client = TestClient(app)

# ── 1. Production shell served ───────────────────────────────────────
r = client.get("/")
body = r.text
check("GET / returns 200 HTML shell (not JSON metadata)",
      r.status_code == 200 and "text/html" in r.headers.get("content-type", "") and "<div id=\"root\">" in body,
      f"{r.status_code} {r.headers.get('content-type')}")

# ── 2. SPA fallback routes ───────────────────────────────────────────
for path in ("/dashboard", "/emails", "/settings", "/analytics"):
    r = client.get(path)
    check(f"GET {path} returns the React shell",
          r.status_code == 200 and "text/html" in r.headers.get("content-type", "") and "<div id=\"root\">" in r.text)

# Real email row -> /emails/<id> must serve the app, not 404.
db = SessionLocal()
existing = db.query(EmailAnalysis).first()
db.close()
if existing:
    r = client.get(f"/emails/{existing.id}")
    check("GET /emails/<existing-id> returns the React shell (not 404)",
          r.status_code == 200 and "text/html" in r.headers.get("content-type", "") and "<div" in r.text,
          f"{r.status_code}")

# Unknown deep route also falls back to the SPA.
r = client.get("/some/unknown/route")
check("GET /some/unknown/route falls back to the SPA",
      r.status_code == 200 and "text/html" in r.headers.get("content-type", ""))

# ── 3. API precedence over the fallback ──────────────────────────────
r = client.get("/api/health")
check("GET /api/health still reaches FastAPI", r.status_code == 200 and r.json().get("status") == "healthy")

r = client.get("/api/ai/status")
check("GET /api/ai/status still reaches FastAPI", r.status_code == 200 and "configured" in r.json())

r = client.get("/api/nonexistent")
check("GET /api/nonexistent -> JSON 404 (not HTML)", r.status_code == 404 and "text/html" not in r.headers.get("content-type", ""))

r = client.get("/api/nonexistent/")
check("GET /api/nonexistent/ -> JSON 404 (not HTML)", r.status_code == 404 and "text/html" not in r.headers.get("content-type", ""))

r = client.get("/auth/nonexistent")
check("GET /auth/nonexistent -> JSON 404 (not HTML)",
      r.status_code == 404 and "text/html" not in r.headers.get("content-type", ""))

# ── 4. OAuth route presence/behavior unchanged ───────────────────────
r = client.get("/auth/google", follow_redirects=False)
check("GET /auth/google handled by FastAPI (not SPA fallback)",
      r.status_code in (302, 307, 503) and "text/html" not in r.headers.get("content-type", "").lower() or r.status_code == 503,
      f"{r.status_code}")

r = client.get("/auth/google/callback?error=access_denied&state=x", follow_redirects=False)
check("GET /auth/google/callback handled by FastAPI (error redirect)",
      r.status_code in (302, 307),
      f"status={r.status_code}")

# ── 5. OpenAPI/docs unaffected ────────────────────────────────────────
r = client.get("/docs")
check("GET /docs still serves Swagger UI", r.status_code == 200 and "text/html" in r.headers.get("content-type", ""))

r = client.get("/openapi.json")
check("GET /openapi.json still serves the schema", r.status_code == 200 and r.json().get("info", {}).get("title") == "PhishGuard")

# ── 6. Security: assets only, no secrets in served files ─────────────
# Note: HTTP clients normalize "/assets/../.env" to "/.env" before it reaches
# the server, so the real assertion is on CONTENT: no traversal variant may
# return anything but the SPA shell or a JSON 404 — never file contents.
for probe in ("/assets/../.env", "/assets/%2e%2e/%2e%2e/backend/.env", "/../backend/.env", "/.env"):
    r = client.get(probe)
    body = r.text
    safe = ("GROQ_API_KEY" not in body and "GOOGLE_CLIENT_SECRET" not in body
            and not body.lstrip().startswith("["))
    check(f"Traversal probe {probe!r} leaks nothing",
          safe and (r.status_code == 404 or "<div id=\"root\">" in body),
          f"{r.status_code}")

leak = re.search(r"gsk_[A-Za-z0-9]{10,}|GOOGLE_CLIENT_SECRET=|refresh_token=", body)
check("No secret material in served index.html", leak is None)

print(f"\n{'=' * 60}\nPHASE 2a STATIC SERVING: {sum(1 for _, ok, _ in results if ok)}/{len(results)} checks passed")
sys.exit(0 if all(ok for _, ok, _ in results) else 1)
