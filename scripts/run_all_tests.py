# F-29: one-command developer verification for the whole project.
#
# Usage (from the repository root):
#   python scripts/run_all_tests.py            # all steps
#   python scripts/run_all_tests.py --quick    # skip frontend build + Electron tests
#
# Steps (any failure stops the run with a non-zero exit code):
#   1. Backend pytest suite            (python -m pytest tests/ -q)
#   2. Frontend production build       (npm run build in frontend/)
#   3. Frontend auth-status unit tests (node --test, no npm deps needed)
#   4. Electron/Node shell tests       (node --test in desktop/)
#
# No new test frameworks or dependencies are introduced.

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NPM = "npm.cmd" if sys.platform == "win32" else "npm"

STEPS = [
    (
        "Backend pytest",
        [sys.executable, "-m", "pytest", "tests/", "-q"],
        ROOT,
    ),
    (
        "Frontend build",
        [NPM, "run", "build"],
        ROOT / "frontend",
    ),
    (
        "Frontend auth-status unit tests (node --test)",
        ["node", "--test", "src/utils/authStatus.test.js"],
        ROOT / "frontend",
    ),
    (
        "Electron/Node tests",
        ["node", "--test"],
        ROOT / "desktop",
    ),
]


def main() -> int:
    quick = "--quick" in sys.argv
    failures = []
    for name, cmd, cwd in STEPS:
        if quick and name in ("Frontend build", "Electron/Node tests"):
            print(f"--- SKIP (quick mode): {name}")
            continue
        print(f"--- {name}")
        proc = subprocess.run(cmd, cwd=str(cwd))
        if proc.returncode != 0:
            failures.append(name)
            print(f"=== FAILED: {name}")
            break
        print(f"=== OK: {name}")

    if failures:
        print(f"\nRESULT: FAILED ({', '.join(failures)})")
        return 1
    print("\nRESULT: ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
