"""F-16 account isolation: identity resolution and query scoping.

ARCHITECTURE DECISION (user-approved): this application supports MULTIPLE
Gmail accounts per desktop profile.

    - Every stored email analysis is stamped with the authenticated account
      that produced it (``EmailAnalysis.owner_account``).
    - Every read path resolves the caller's identity from the SERVER-SIDE
      authenticated context — the OAuth session cookie (a specific Gmail
      account) — never from a client-supplied field.
    - Queries are scoped with :func:`scope_owner` so callers only ever see
      their own rows plus (deliberately) legacy NULL-owner rows from before
      isolation existed in this single-user desktop data dir.

Identity rules
--------------
* OAuth session cookie present  -> that Gmail address.
* No session cookie             -> legacy/public analysis surface. Rows are
  visible only when ``owner_account`` is NULL; any owned row is invisible.
* A row's owner is NEVER accepted from the client.

The scope filter is the ONE place that defines account visibility so every
endpoint (list, detail, statistics, priority, notifications, assistant)
cannot drift apart.
"""

from __future__ import annotations

from sqlalchemy.orm import Query

from .sessions import get_session_user

SESSION_COOKIE = "phishguard_session"


def resolve_account(request) -> str | None:
    """Resolve the caller's account identity from the OAuth session cookie.

    Returns the Gmail address for a valid session, else None. The value is
    always derived server-side; client input is never trusted for identity.
    """
    if request is None:
        return None
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None
    return get_session_user(session_id)


def scope_owner(query: Query, account: str | None) -> Query:
    """Restrict *query* to rows owned by *account* (plus legacy NULL rows).

    - account set : own rows OR legacy NULL-owner rows (desktop upgrade path).
    - account None: only legacy NULL-owner rows — an unauthenticated caller
      must never see an owned row.
    """
    if account:
        from ..models.email import EmailAnalysis

        return query.filter(
            (EmailAnalysis.owner_account == account)
            | (EmailAnalysis.owner_account.is_(None))
        )
    from ..models.email import EmailAnalysis

    return query.filter(EmailAnalysis.owner_account.is_(None))


def owns_row(row, account: str | None) -> bool:
    """True when *account* may access *row* (mirrors scope_owner's rule)."""
    owner = getattr(row, "owner_account", None)
    if owner is None:
        return True  # legacy row
    return bool(account) and owner == account
