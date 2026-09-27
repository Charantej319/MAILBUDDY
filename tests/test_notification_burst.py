"""F-28 — bounded notification policy (anti-flood) regression tests.

An attacker-controlled sender can burst SECURITY/OTP-class emails; the
per-account burst guard in mailbuddy.service.queue_notifications bounds how
many notifications one account can create per rolling window, while keeping:

* exact-duplicate suppression (Gmail re-syncs) — test B,
* other accounts unaffected (quota is per-owner, owner from the
  server-stamped row, never client input) — test D,
* deferred (not dropped) notifications after the window drains — test E,
* acknowledgement (mark_delivered) still functional — test F.

All tests run against the real service layer + real database session
(ephemeral per-test data dir via conftest); no live Gmail, no Groq, no
network. Notification/analysis rows use the 'mb-' id convention that
conftest cleans up.
"""

import uuid
from datetime import datetime, timedelta

import pytest

from backend.app.mailbuddy import service
from backend.app.models.email import EmailAnalysis, NotificationLog
from backend.app.utils.timeutil import utc_now


def _make_analysis(owner: str | None = None, level: str = "CRITICAL",
                   category: str = "SECURITY") -> EmailAnalysis:
    now = utc_now()
    if now.tzinfo:
        now = now.replace(tzinfo=None)
    row = EmailAnalysis(
        id=f"mb-{uuid.uuid4().hex[:12]}",
        email_id=f"mb-{uuid.uuid4().hex[:12]}",
        source="gmail",
        owner_account=owner,
        sender="Evil Attacker",
        sender_email="attacker@example.com",
        sender_domain="example.com",
        subject="URGENT: verify your account",
        date=now,
        risk_score=80.0,
        classification="HIGH_RISK",
        priority_level=level,
        priority_category=category,
        priority_is_otp=True,
        created_at=now,
        analyzed_at=now,
    )
    return row


@pytest.fixture
def seeded(db_session):
    """Hermetic slate for notification assertions.

    The pytest data dir is a persistent, test-only database, so rows from
    earlier sessions (including legacy NULL-owner rows that F-16 makes
    visible to any authenticated account) would otherwise leak into
    pending_notifications(). This suite owns the whole notification surface
    being asserted, so the test-only tables are emptied first. Rows created
    here use the 'mb-' convention that conftest cleans up afterwards.
    """
    db_session.query(NotificationLog).delete(synchronize_session=False)
    db_session.query(EmailAnalysis).delete(synchronize_session=False)
    db_session.commit()

    def _commit(row):
        db_session.add(row)
        db_session.commit()
        db_session.refresh(row)
        return row
    return _commit


# ── A. a normal SECURITY notification is still created ────────────────

def test_a_normal_security_notification_created(db_session, seeded):
    row = seeded(_make_analysis(owner="a@gmail.com"))
    created = service.queue_notifications(db_session, row)
    assert created == 1
    pending = service.pending_notifications(db_session, account="a@gmail.com")
    assert len(pending) == 1
    assert pending[0]["email"]["id"] == row.id
    assert pending[0]["email"]["priority_level"] == "CRITICAL"


# ── B. repeated identical notification stays suppressed ───────────────

def test_b_duplicate_suppressed(db_session, seeded):
    row = seeded(_make_analysis(owner="a@gmail.com"))
    assert service.queue_notifications(db_session, row) == 1
    # Gmail re-sync calls queue_notifications again for the same email.
    assert service.queue_notifications(db_session, row) == 0
    assert service.queue_notifications(db_session, row) == 0
    assert db_session.query(NotificationLog).count() == 1


# ── C. burst of many security emails is bounded per account ───────────

def test_c_burst_bounded_per_account(db_session, seeded, monkeypatch):
    # Tighten the window for a deterministic assertion.
    monkeypatch.setattr(service, "NOTIFICATION_BURST_LIMIT", 3)
    owner = "burst-victim@gmail.com"
    rows = [seeded(_make_analysis(owner=owner)) for _ in range(10)]

    created = sum(service.queue_notifications(db_session, row) for row in rows)
    assert created == 3, "burst must be capped at NOTIFICATION_BURST_LIMIT"

    pending = service.pending_notifications(db_session, account=owner)
    assert len(pending) == 3

    # Non-notifiable levels are unaffected by (and irrelevant to) the guard.
    low = seeded(_make_analysis(owner=owner, level="NORMAL"))
    assert service.queue_notifications(db_session, low) == 0


# ── D. Account A's burst cannot consume Account B's quota ─────────────

def test_d_quota_is_account_specific(db_session, seeded, monkeypatch):
    monkeypatch.setattr(service, "NOTIFICATION_BURST_LIMIT", 3)
    a_rows = [seeded(_make_analysis(owner="a@gmail.com")) for _ in range(6)]
    created_a = sum(service.queue_notifications(db_session, row) for row in a_rows)
    assert created_a == 3, "Account A hits its own cap"

    # Account B's very first notification must still go through.
    b_row = seeded(_make_analysis(owner="b@gmail.com"))
    assert service.queue_notifications(db_session, b_row) == 1
    b_pending = service.pending_notifications(db_session, account="b@gmail.com")
    assert len(b_pending) == 1

    # And B can still use its full quota afterwards.
    b_rows = [seeded(_make_analysis(owner="b@gmail.com")) for _ in range(4)]
    created_b = sum(service.queue_notifications(db_session, row) for row in b_rows)
    assert created_b == 2, "B had 1 + gets 2 more = 3 total (its own cap)"

    # A's pending notifications are exactly A's — never B's rows.
    a_pending = service.pending_notifications(db_session, account="a@gmail.com")
    assert all(p["email"]["id"].startswith("mb-") for p in a_pending)
    a_ids = {p["email"]["id"] for p in a_pending}
    b_ids = {b_row.id} | {r.id for r in b_rows}
    assert not (a_ids & b_ids)


# ── E. after the window drains, deferred notifications flow again ─────

def test_e_window_recovery_deferred_not_dropped(db_session, seeded, monkeypatch):
    monkeypatch.setattr(service, "NOTIFICATION_BURST_LIMIT", 2)
    monkeypatch.setattr(service, "NOTIFICATION_BURST_WINDOW_SECONDS", 3600)
    owner = "recovery@gmail.com"
    rows = [seeded(_make_analysis(owner=owner)) for _ in range(4)]

    first = sum(service.queue_notifications(db_session, row) for row in rows[:2])
    assert first == 2

    # Window exhausted: later emails are deferred (not created, not recorded).
    deferred = service.queue_notifications(db_session, rows[2])
    assert deferred == 0
    assert db_session.query(NotificationLog).filter(
        NotificationLog.email_id == rows[2].email_id).count() == 0

    # Age the window out: backdate the existing notifications' created_at so
    # the rolling window is empty again.
    old = utc_now().replace(tzinfo=None) - timedelta(hours=2)
    for row in db_session.query(NotificationLog).all():
        row.created_at = old
    db_session.commit()

    assert service.queue_notifications(db_session, rows[2]) == 1, \
        "legitimate notification after the rate window must be created"
    assert service.queue_notifications(db_session, rows[3]) == 1


# ── F. acknowledgement still works under the guard ────────────────────

def test_f_ack_still_works(db_session, seeded):
    owner = "ack@gmail.com"
    row = seeded(_make_analysis(owner=owner))
    assert service.queue_notifications(db_session, row) == 1

    pending = service.pending_notifications(db_session, account=owner)
    assert len(pending) == 1
    key = pending[0]["key"]

    marked = service.mark_delivered(db_session, [key], account=owner)
    assert marked == 1
    assert service.pending_notifications(db_session, account=owner) == []

    # Cross-account ack remains forbidden (F-16 contract unchanged).
    row2 = seeded(_make_analysis(owner="other@gmail.com"))
    service.queue_notifications(db_session, row2)
    key2 = service.pending_notifications(db_session, account="other@gmail.com")[0]["key"]
    assert service.mark_delivered(db_session, [key2], account="ack@gmail.com") == 0


# ── G. quota counting cannot be steered by client-visible fields ──────

def test_g_owner_from_server_stamped_row_only(db_session, seeded, monkeypatch):
    """The guard counts against owner_account on the stored row — a value the
    API never accepts from the client — so spoofed identities cannot reset or
    shift another account's quota."""
    monkeypatch.setattr(service, "NOTIFICATION_BURST_LIMIT", 1)
    row = seeded(_make_analysis(owner="real@gmail.com"))

    # Even if a caller mutates non-owner fields, quota follows owner_account.
    assert service.queue_notifications(db_session, row) == 1

    row2 = seeded(_make_analysis(owner="real@gmail.com"))
    assert service.queue_notifications(db_session, row2) == 0  # real owner capped

    # A different owner still has quota.
    row3 = seeded(_make_analysis(owner="someone-else@gmail.com"))
    assert service.queue_notifications(db_session, row3) == 1
