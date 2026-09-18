"""
PyInstaller entry point for the PhishGuard backend.

Launches the existing FastAPI app (backend/app/main.py) exactly as the dev
uvicorn command does. No application behavior is modified here; the only
frozen-environment concern handled is sys.path: the project-local ``detection``
package must be importable inside the bundle. The frontend/dist location is
resolved inside backend/app/main.py (Phase 2a), which also handles the frozen
_MEIPASS location.
"""
import os
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    # Inside the one-dir bundle the app modules live under _MEIPASS/backend.
    _meipass = Path(getattr(sys, "_MEIPASS", ""))
    for _p in (_meipass, _meipass / "backend"):
        if _p.is_dir() and str(_p) not in sys.path:
            sys.path.insert(0, str(_p))

# Imported after frozen path setup. This is the same app object uvicorn serves.
from backend.app.main import app  # noqa: E402

# Serve with uvicorn's programmatic interface — identical to the dev command
# `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`.
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.environ.get("PHISHGUARD_BACKEND_PORT", "8000")),
        log_level=os.environ.get("PHISHGUARD_BACKEND_LOG_LEVEL", "warning"),
    )
