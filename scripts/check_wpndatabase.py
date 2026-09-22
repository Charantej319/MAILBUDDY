"""Read-only inspection of the Windows notification platform database.

Copies %LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\wpndatabase (plus
-wal/-shm) to a temp dir and searches stored toasts for MailBuddy payloads.
The original database is never opened in write mode.
"""
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime

SRC_DIR = os.path.join(os.environ["LOCALAPPDATA"], "Microsoft", "Windows", "Notifications")
TMP = tempfile.mkdtemp(prefix="wpn_")

for name in ("wpndatabase.db", "wpndatabase.db-wal", "wpndatabase.db-shm"):
    src = os.path.join(SRC_DIR, name)
    if os.path.exists(src):
        shutil.copy2(src, os.path.join(TMP, name))
        print(f"copied {name}")

db = sqlite3.connect(os.path.join(TMP, "wpndatabase.db"))
db.row_factory = sqlite3.Row

tables = [r[0] for r in db.execute("select name from sqlite_master where type='table'")]
print("tables:", tables)

def filetime_to_iso(ft):
    try:
        return (datetime(1601, 1, 1) + __import__("datetime").timedelta(microseconds=ft // 10)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ft)

# Map handler ids to AUMIDs if the Handler table exists
handlers = {}
if "Handler" in tables:
    for r in db.execute("select * from Handler"):
        d = dict(r)
        handlers[d.get("Id", d.get("id"))] = str(list(d.values())[1:3])

hits = 0
if "Notification" in tables:
    cols = [c[1] for c in db.execute("PRAGMA table_info(Notification)")]
    print("notification columns:", cols)
    rows = db.execute("select * from Notification order by rowid desc limit 60").fetchall()
    for r in rows:
        d = dict(r)
        blob = d.get("Payload") or b""
        if isinstance(blob, str):
            blob = blob.encode("utf-8", "ignore")
        text = blob.decode("utf-8", "ignore")
        if ("VALIDATION-TEST" in text or "MailBuddy" in text or "phishguard" in text.lower()
                or "mailbuddy" in text.lower()):
            hits += 1
            arrival = d.get("ArrivalTime") or d.get("arrivaltime")
            print("-" * 70)
            print("arrival:", filetime_to_iso(arrival) if arrival else "?", f"(raw {arrival})")
            for k, v in d.items():
                if k in ("Payload",):
                    continue
                if v not in (None, ""):
                    print(f"  {k}: {v}")
            snippet = text.replace("\n", " ")[:400]
            print("  payload:", snippet)

print("-" * 70)
print(f"MailBuddy-related toast rows found in the last 60 notifications: {hits}")
db.close()
shutil.rmtree(TMP, ignore_errors=True)
