"""
Regression tests for email Date-header parsing (_parse_date).

Root cause these tests pin: a function-local `from datetime import timezone`
made `timezone` local to the whole function, so `dt.astimezone(timezone.utc)`
raised UnboundLocalError for every REAL Gmail header (which parses to an
already timezone-aware datetime). Sync then stored zero emails while OAuth
itself succeeded — the post-approval "failure" users saw.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from datetime import datetime, timezone as dt_timezone


def _gmail_parse_date(date_str):
    from backend.app.gmail.api import _parse_date
    return _parse_date(date_str)


def _analysis_parse_date(date_str):
    from backend.app.api.analysis import _parse_date
    return _parse_date(date_str)


def test_parse_date_aware_utc_header():
    """The standard Gmail case: explicit +0000 zone (parses aware). Must not raise."""
    for fn in (_gmail_parse_date, _analysis_parse_date):
        dt = fn("Thu, 18 Sep 2026 12:00:00 +0000")
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0


def test_parse_date_aware_offset_header():
    """Non-UTC offsets (e.g. +0530) must convert to UTC, not raise."""
    for fn in (_gmail_parse_date, _analysis_parse_date):
        dt = fn("Fri, 18 Sep 2026 17:30:00 +0530")
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0
        assert (dt.hour, dt.minute) == (12, 0)  # 17:30+05:30 == 12:00 UTC


def test_parse_date_naive_header_assumed_utc():
    """Header without a zone: ambiguous, must be assumed UTC — not raise."""
    for fn in (_gmail_parse_date, _analysis_parse_date):
        dt = fn("Thu, 18 Sep 2026 12:00:00")
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0


def test_parse_date_empty_falls_back_to_now():
    for fn in (_gmail_parse_date, _analysis_parse_date):
        dt = fn("")
        assert dt.tzinfo is not None
        assert isinstance(dt, datetime)


def test_parse_date_garbage_falls_back_to_now():
    for fn in (_gmail_parse_date, _analysis_parse_date):
        dt = fn("not a date at all")
        assert dt.tzinfo is not None
        assert isinstance(dt, datetime)


def test_parse_date_result_is_utc():
    """Output must always be normalized to UTC regardless of input zone."""
    dt = _gmail_parse_date("Thu, 18 Sep 2026 09:00:00 -0300")  # 12:00 UTC
    assert dt.utcoffset().total_seconds() == 0
    assert (dt.hour, dt.minute) == (12, 0)
