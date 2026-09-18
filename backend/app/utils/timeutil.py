"""
Timezone-aware UTC timestamp helpers.

PhishGuard stores every timestamp in the database as UTC (SQLite has no
real timezone type, so we always persist naive-UTC values) and every API
response as timezone-aware ISO-8601 with an explicit "Z" suffix (or +00:00)
so browsers parse it correctly regardless of the user's local timezone.

Root cause of the historical "Last sync: 5 hours ago" bug:
- SQLite's CURRENT_TIMESTAMP (server_default=func.now()) is UTC, but when
  SQLAlchemy read the value back it attached *no* timezone info, so
  `.isoformat()` produced a bare string like "2026-09-17T07:35:05".
- JavaScript `new Date("2026-09-17T07:35:05")` treats ISO strings without
  an offset as LOCAL time (ES2015+ behaviour for date-time forms), so a
  UTC wall-clock time rendered in IST appeared to be 5.5 hours old.
"""


def utc_now() -> "datetime.datetime":
    """Current time as an aware UTC datetime."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def as_utc(dt) -> "datetime.datetime | None":
    """
    Normalize a datetime read from the database to aware UTC.

    SQLite + SQLAlchemy returns naive datetimes. We assume any naive value
    was persisted as UTC (which is true for CURRENT_TIMESTAMP defaults and
    for every write path in this application) and attach UTC explicitly.
    Aware values are converted to UTC.
    """
    from datetime import datetime, timezone
    if dt is None:
        return None
    if isinstance(dt, str):
        dt = parse_iso(dt)
        if dt is None:
            return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_iso(value: str) -> "datetime.datetime | None":
    """Parse an ISO-8601 string, tolerating the trailing 'Z' suffix."""
    from datetime import datetime, timezone
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Legacy rows stored bare UTC wall-clock strings.
        return dt.replace(tzinfo=timezone.utc)
    return dt


def iso_utc(dt) -> "str | None":
    """
    Serialize a datetime as timezone-aware ISO-8601 in UTC.

    Uses the "...Z" suffix (ES5/ES2015+ Date.parse treats Z as UTC) so the
    frontend always computes correct relative times in the user's timezone.
    Legacy naive values are treated as UTC (matching how they were written).
    """
    dt = as_utc(dt)
    if dt is None:
        return None
    return dt.isoformat().replace("+00:00", "Z")
