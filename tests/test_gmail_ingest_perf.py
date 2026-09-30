"""
F-30 — Gmail ingestion performance regression tests.

Proves, against mocked Gmail API calls (no network):

1. Message fetches are no longer serialized: sync overlaps per-message
   fetches with bounded concurrency (bounded, never unbounded).
2. Attachment metadata comes from Gmail's body.size WITHOUT decoding the
   attachment payload (the old code base64-decoded the whole blob only to
   measure its length).
3. One failed message does not abort the sync — the others still land.
4. Duplicate messages (already-analyzed IDs) are not re-fetched or
   reprocessed.
"""

import asyncio
import base64
import uuid
from unittest.mock import patch

import pytest

from backend.app.database.connection import SessionLocal
from backend.app.models.email import EmailAnalysis
from backend.app.utils.timeutil import utc_now
from backend.app.parser.email_parser import ParsedEmail, parse_gmail_message
from backend.app.gmail import api as gmail_api


# ── helpers ──────────────────────────────────────────────────────────────


def _gmail_full_message(message_id: str, subject: str = "Hello") -> dict:
    """Minimal Gmail API `format=full` message."""
    return {
        "id": message_id,
        "threadId": f"thread-{message_id}",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": "Alice <alice@example.com>"},
                {"name": "Subject", "value": subject},
                {"name": "Date", "value": "Mon, 21 Sep 2026 10:00:00 +0000"},
            ],
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {
                        "data": base64.urlsafe_b64encode(b"Hi, just checking in.").decode(),
                        "size": 18,
                    },
                },
            ],
        },
    }


class FakeGmailService:
    """Stands in for GmailService with a controllable fetch delay."""

    instances: list = []

    # F-30 deterministic concurrency instrumentation (no wall-clock timing):
    # fetch_and_parse records how many fetches are in flight at any moment.
    # The increment/peek/decrement around the await is fully synchronous, so
    # on asyncio's single-threaded loop the counter is exact — no locks and
    # no dependence on machine speed or elapsed time.
    _in_flight = 0
    max_in_flight = 0

    @classmethod
    def reset_concurrency_counters(cls) -> None:
        cls._in_flight = 0
        cls.max_in_flight = 0

    def __init__(self, user_email: str, fetch_delay: float = 0.0):
        self.user_email = user_email
        self.fetch_delay = fetch_delay
        self.fetched: list[str] = []
        self.shared_client_used = False
        self.closed = False
        FakeGmailService.instances.append(self)

    def use_shared_client(self):
        self.shared_client_used = True

    async def aclose(self):
        self.closed = True

    async def list_messages(self, query: str = "", max_results: int = 50) -> list[dict]:
        self.list_call = {"query": query, "max_results": max_results}
        return [{"id": mid} for mid in self.message_ids]

    async def fetch_and_parse(self, message_id: str):
        self.fetched.append(message_id)
        cls = FakeGmailService
        cls._in_flight += 1
        if cls._in_flight > cls.max_in_flight:
            cls.max_in_flight = cls._in_flight
        try:
            if self.fetch_delay:
                await asyncio.sleep(self.fetch_delay)
            return _gmail_full_message(message_id), ParsedEmail(
                sender="Alice", sender_email="alice@example.com",
                sender_domain="example.com", subject="Hello",
            )
        finally:
            cls._in_flight -= 1


@pytest.fixture(autouse=True)
def _clean_db():
    """Test-only slate for gmail-source rows (id convention: perf-)."""
    db = SessionLocal()
    db.query(EmailAnalysis).filter(EmailAnalysis.email_id.like("perf-%")).delete(synchronize_session=False)
    db.commit()
    yield
    db.query(EmailAnalysis).filter(EmailAnalysis.email_id.like("perf-%")).delete(synchronize_session=False)
    db.commit()
    db.close()


def _make_request(account: str):
    class _Req:
        cookies = {"phishguard_session": "unused-session"}

    from unittest.mock import patch as _p
    with _p("backend.app.gmail.api.get_session_user", return_value=account):
        # GmailService is constructed inside sync_gmail; FakeGmailService
        # replaces it via patch in the tests.
        pass
    return _Req()


@pytest.fixture
def request_ctx():
    """Patch session resolution + GmailService for the sync endpoint."""
    from contextlib import contextmanager

    @contextmanager
    def _ctx(account: str = "perf-account@example.com", fetch_delay: float = 0.0):
        FakeGmailService.instances = []
        with patch("backend.app.gmail.api.get_session_user", return_value=account), \
             patch("backend.app.gmail.api.GmailService",
                   lambda user: FakeGmailService(user, fetch_delay=fetch_delay)):
            yield None

    return _ctx


class _DBCtx:
    """Satisfies `db: Session = Depends(get_db)` in direct endpoint calls."""

    def __init__(self, db):
        self._db = db

    def __getattr__(self, item):
        return getattr(self._db, item)


# ── 1. bounded concurrency (not serialized) ─────────────────────────────


@pytest.mark.asyncio
async def test_sync_fetches_concurrently_bounded(request_ctx):
    """F-30, deterministically: sync overlaps per-message fetches but never
    exceeds GMAIL_FETCH_CONCURRENCY.

    The old version asserted a wall-clock deadline (elapsed < 80% of the
    sequential floor), which is machine-speed dependent and failed on slower
    hosts even with correct bounded concurrency. Instead, the fake Gmail
    service counts in-flight fetch_and_parse calls:

      - max_in_flight >= 2 proves fetches actually overlap (a serialized
        implementation can never exceed 1, regardless of timing);
      - max_in_flight <= GMAIL_FETCH_CONCURRENCY proves the semaphore caps
        parallelism.

    No elapsed-time measurement, no CPU-speed dependence, no thresholds.
    """
    n = 12
    delay = 0.05
    FakeGmailService.reset_concurrency_counters()
    with request_ctx(fetch_delay=delay) as _:
        ids = [f"perf-{uuid.uuid4().hex[:10]}" for _ in range(n)]

        class _ListShim(FakeGmailService):
            message_ids = ids

        with patch("backend.app.gmail.api.GmailService",
                   lambda user: _ListShim(user, fetch_delay=delay)):
            resp = await gmail_api.sync_gmail(
                request=_make_request("perf-account@example.com"),
                max_results=n, db=SessionLocal(),
            )

    assert resp["synced"] == n
    assert resp["skipped"] == 0

    svc = FakeGmailService.instances[-1]
    # Every message was fetched exactly once through the instrumented path.
    assert sorted(svc.fetched) == sorted(ids)

    # 1) Concurrency actually occurs: at least two fetches were in flight
    #    simultaneously. Deterministic for n > 1: the gather starts n tasks
    #    and the semaphore admits GMAIL_FETCH_CONCURRENCY of them before any
    #    await completes, so a serialized implementation can never reach 2.
    max_observed = FakeGmailService.max_in_flight
    assert max_observed >= 2, (
        f"fetches appear serialized: max in-flight fetches = {max_observed}"
    )

    # 2) Concurrency is bounded: the semaphore never admitted more than
    #    GMAIL_FETCH_CONCURRENCY simultaneous fetches.
    assert max_observed <= gmail_api.GMAIL_FETCH_CONCURRENCY, (
        f"unbounded concurrency: max in-flight fetches = {max_observed} "
        f"> GMAIL_FETCH_CONCURRENCY = {gmail_api.GMAIL_FETCH_CONCURRENCY}"
    )

    # Bounded: the concurrency constant stays conservative for Gmail limits.
    assert gmail_api.GMAIL_FETCH_CONCURRENCY == 4
    # Shared connection pool was used for the loop and closed afterwards.
    assert svc.shared_client_used is True
    assert svc.closed is True


@pytest.mark.asyncio
async def test_sync_never_unbounded(request_ctx):
    """Concurrency is bounded by the module constant (semaphore-based)."""
    assert gmail_api.GMAIL_FETCH_CONCURRENCY >= 1
    assert gmail_api.GMAIL_FETCH_CONCURRENCY <= 8  # conservative Gmail limits


@pytest.mark.asyncio
async def test_shared_connection_pool_reused(request_ctx):
    """One shared AsyncClient for the whole sync loop, closed afterwards."""
    ids = [f"perf-{uuid.uuid4().hex[:10]}" for _ in range(3)]

    class _ListShim(FakeGmailService):
        message_ids = ids

    with request_ctx() as _:
        with patch("backend.app.gmail.api.GmailService",
                   lambda user: _ListShim(user)):
            await gmail_api.sync_gmail(
                request=_make_request("perf-account@example.com"),
                max_results=3, db=SessionLocal(),
            )
        svc = _ListShim.instances[-1]
        assert svc.shared_client_used is True
        assert svc.closed is True


# ── 2. attachment metadata without payload decoding ─────────────────────


def test_attachment_size_from_metadata_no_decode():
    """Gmail attachment part with inline base64 data: size must come from
    body.size and the payload must NOT be decoded."""
    payload_bytes = b"A" * 5000
    encoded = base64.urlsafe_b64encode(payload_bytes).decode()
    message = {
        "id": "m1",
        "threadId": "t1",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": "Bob <bob@example.com>"},
                {"name": "Subject", "value": "Invoice"},
            ],
            "parts": [
                {
                    "mimeType": "application/pdf",
                    "filename": "invoice.pdf",
                    "body": {"attachmentId": "att1", "size": len(payload_bytes), "data": encoded},
                },
            ],
        },
    }

    calls = {"n": 0}
    real_decode = base64.urlsafe_b64decode

    def _spy_decode(s, *a, **kw):
        if isinstance(s, str) and len(s) > 1000:
            calls["n"] += 1
        return real_decode(s, *a, **kw)

    with patch("base64.urlsafe_b64decode", side_effect=_spy_decode):
        parsed = parse_gmail_message(message)

    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att["filename"] == "invoice.pdf"
    assert att["size"] == len(payload_bytes)
    # The multi-KB attachment blob was never decoded.
    assert calls["n"] == 0, "attachment payload must not be decoded for metadata"
    # Body parts are still decoded normally.
    assert parsed.body_text == ""  # no text/plain part in this message


def test_attachment_metadata_only_part_still_works():
    """Attachment part without inline data (attachmentId style) — unchanged."""
    message = {
        "id": "m2",
        "threadId": "t2",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": "Bob <bob@example.com>"},
            ],
            "parts": [
                {
                    "mimeType": "application/zip",
                    "filename": "archive.zip",
                    "body": {"attachmentId": "att2", "size": 123456},
                },
            ],
        },
    }
    parsed = parse_gmail_message(message)
    assert parsed.attachments == [{
        "filename": "archive.zip",
        "content_type": "application/zip",
        "size": 123456,
        "disposition": "attachment",
    }]


def test_attachment_size_fallback_when_size_missing():
    """Gmail always provides body.size for attachment parts; when absent the
    parser records 0 rather than decoding the payload (metadata-only design)."""
    encoded = base64.urlsafe_b64encode(b"x" * 100).decode()
    message = {
        "id": "m3",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [{"name": "From", "value": "B <b@e.com>"}],
            "parts": [
                {
                    "mimeType": "application/octet-stream",
                    "filename": "blob.bin",
                    "body": {"data": encoded},  # no size key
                },
            ],
        },
    }
    parsed = parse_gmail_message(message)
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0]["size"] == 0


def test_body_parts_still_decoded():
    """text/plain and text/html bodies are still decoded (behavior unchanged)."""
    message = _gmail_full_message("m4")
    parsed = parse_gmail_message(message)
    assert parsed.body_text == "Hi, just checking in."
    assert parsed.urls == [] or isinstance(parsed.urls, list)


# ── 3. one failed message does not abort the sync ────────────────────────


@pytest.mark.asyncio
async def test_failed_message_does_not_abort_sync(request_ctx):
    ids = [f"perf-{uuid.uuid4().hex[:10]}" for _ in range(4)]
    fail_id = ids[1]

    class _ListShim(FakeGmailService):
        message_ids = ids

        async def fetch_and_parse(self, message_id: str):
            if message_id == fail_id:
                raise RuntimeError("simulated Gmail 500")
            return await super().fetch_and_parse(message_id)

    with request_ctx() as _:
        with patch("backend.app.gmail.api.GmailService",
                   lambda user: _ListShim(user)):
            resp = await gmail_api.sync_gmail(
                request=_make_request("perf-account@example.com"),
                max_results=4, db=SessionLocal(),
            )

    assert resp["synced"] == 3, "other messages must still be stored"
    assert resp["skipped"] == 1
    assert resp["total"] == 4
    db = SessionLocal()
    stored = db.query(EmailAnalysis).filter(EmailAnalysis.email_id.in_(ids)).count()
    db.close()
    assert stored == 3


# ── 4. duplicates are not reprocessed ────────────────────────────────────


@pytest.mark.asyncio
async def test_duplicates_not_refetched(request_ctx):
    ids = [f"perf-{uuid.uuid4().hex[:10]}" for _ in range(2)]
    db = SessionLocal()
    now = utc_now()
    if now.tzinfo:
        now = now.replace(tzinfo=None)
    for mid in ids:
        db.add(EmailAnalysis(
            id=str(uuid.uuid4()), email_id=mid, source="gmail",
            owner_account="perf-account@example.com",
            sender="Alice", sender_email="alice@example.com",
            sender_domain="example.com", subject="Hello",
            risk_score=0.0, classification="SAFE",
            analyzed_at=now, created_at=now,
        ))
    db.commit()
    db.close()

    class _ListShim(FakeGmailService):
        message_ids = list(ids) + [f"perf-{uuid.uuid4().hex[:10]}"]  # 2 old + 1 new

    with request_ctx() as _:
        with patch("backend.app.gmail.api.GmailService",
                   lambda user: _ListShim(user)):
            resp = await gmail_api.sync_gmail(
                request=_make_request("perf-account@example.com"),
                max_results=3, db=SessionLocal(),
            )

    assert resp["synced"] == 1
    assert resp["skipped"] == 2
    # Only the NEW message was fetched; duplicates never hit the API again.
    assert len(_ListShim.instances[-1].fetched) == 1
