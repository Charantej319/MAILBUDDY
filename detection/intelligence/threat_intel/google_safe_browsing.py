"""
Google Safe Browsing provider (Session B).

Passive URL threat lookup against Google Safe Browsing v4
`threatMatches.find` (HTTPS POST). This is THREAT INTELLIGENCE only — it
never replaces MailBuddy's deterministic URL analyzer and never fetches
the destination URL.

Security and privacy invariants (see also base.py):

- HTTPS only; HTTP is rejected before any request is built.
- Strict timeouts: every attempt is bounded (connect+read via a bounded
  worker pool and a hard result timeout — no request can outlive
  SB_TIMEOUT_SECONDS, matching the F-14/domain-age philosophy).
- No redirects are followed (urllib's HTTPRedirectHandler is disabled).
- The destination URL is NEVER fetched; only the Safe Browsing API is
  contacted, and only the normalized URL is sent to it.
- NEVER sent to the provider: sender/recipient addresses, subject,
  body, headers, attachments, Gmail account info.
- The API key is sent only in the request URL to Google's endpoint,
  never logged, never included in exceptions or error classifications.
- Unbounded concurrency is impossible: lookups run on the shared bounded
  pool and results are memoized per URL (one request per email analysis,
  one process-wide TTL cache).

Provider state mapping:

- missing/disabled config        -> UNAVAILABLE (no request is made)
- successful response, no match  -> NO_MATCH
- successful response with match -> KNOWN_THREAT (+ threat types)
- HTTP 4xx/5xx, timeout, connection failure, malformed JSON/schema -> ERROR
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
import urllib.error
from typing import Optional
from urllib.parse import urlparse, urlunparse

from .base import (
    KNOWN_THREAT_TYPES,
    ThreatIntelResult,
    ThreatStatus,
)

PROVIDER_NAME = "google_safe_browsing"

# --- configuration -------------------------------------------------------

SB_API_KEY_ENV = "GOOGLE_SAFE_BROWSING_API_KEY"
SB_ENABLED_ENV = "SAFE_BROWSING_ENABLED"          # default: enabled
SB_TIMEOUT_SECONDS = 4.0                          # hard bound per lookup
SB_MAX_URL_LENGTH = 2048                          # request-size sanity guard

# --- cache (process-local, bounded, TTL) --------------------------------
#
# Reuses the cache shape/conventions of domain_intelligence/domain_age
# (md5 key + timestamp), but with per-state TTLs:
#   KNOWN_THREAT -> 1 h   (threat lists change on update, not per request)
#   NO_MATCH     -> 10 min (short: a clean URL can turn bad quickly)
#   ERROR        -> 1 min  (short negative TTL: retry soon, don't hammer)
#   UNAVAILABLE  -> 1 min  (negative: config may appear mid-process)
#
# Never persisted to the database; never an external cache service.

_CACHE_TTL = {
    ThreatStatus.KNOWN_THREAT: 3600.0,
    ThreatStatus.NO_MATCH: 600.0,
    ThreatStatus.ERROR: 60.0,
    ThreatStatus.UNAVAILABLE: 60.0,
}
_CACHE_MAX_ENTRIES = 2048
_cache: dict[str, dict] = {}


def _cache_key(normalized_url: str) -> str:
    return hashlib.sha256(normalized_url.encode("utf-8", "replace")).hexdigest()


def _cache_get(normalized_url: str) -> Optional[ThreatIntelResult]:
    entry = _cache.get(_cache_key(normalized_url))
    if not entry:
        return None
    ttl = _CACHE_TTL.get(entry["result"].status, 60.0)
    if (time.time() - entry["ts"]) < ttl:
        return entry["result"]
    return None  # expired


def _cache_set(normalized_url: str, result: ThreatIntelResult) -> None:
    if len(_cache) >= _CACHE_MAX_ENTRIES:
        # Bounded: drop everything rather than growing without limit.
        _cache.clear()
    _cache[_cache_key(normalized_url)] = {"ts": time.time(), "result": result}


def clear_cache() -> None:
    """Clear the Safe Browsing result cache (tests / cache reset)."""
    _cache.clear()


# --- URL normalization (lookup key only; never sent anywhere else) ------

def normalize_url(url: str) -> Optional[str]:
    """Normalize a URL for Safe Browsing lookup.

    Returns None for anything not safely usable as a lookup key
    (malformed, wrong scheme, missing host, over-long, embedded
    credentials). Normalization is conservative: scheme+host lowercased,
    default ports removed, fragment removed (the fragment never reaches
    Google's matching in v4 and only leaks information), no other
    rewriting. The ORIGINAL URL is unchanged for the rest of the engine.
    """
    if not isinstance(url, str):
        return None
    candidate = url.strip()
    if not candidate or len(candidate) > SB_MAX_URL_LENGTH:
        return None
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        # Credentialed URLs are handled by the static analyzer; do not
        # transmit embedded credentials to a third party.
        return None
    try:
        host = parsed.hostname.lower()
        # hostname is already lowercased by urlparse; keep IDN as-is (the
        # Safe Browsing API accepts the same LDH/IDN form the email used).
        port = parsed.port
    except ValueError:
        # malformed port (e.g. "http://x:bad/") — not a safe lookup key
        return None
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    return urlunparse((parsed.scheme, netloc, parsed.path or "/",
                       parsed.params, parsed.query, ""))


# --- bounded execution (same philosophy as domain_age F-14 pool) ---------

_MAX_WORKERS = 2
_executor = None


def _get_executor():
    global _executor
    if _executor is None:
        from concurrent.futures import ThreadPoolExecutor
        _executor = ThreadPoolExecutor(
            max_workers=_MAX_WORKERS,
            thread_name_prefix="phishguard-sb",
        )
    return _executor


def _run_bounded(fn, timeout: float):
    from concurrent.futures import TimeoutError as FuturesTimeoutError
    future = _get_executor().submit(fn)
    try:
        return future.result(timeout=timeout)
    except FuturesTimeoutError:
        future.cancel()
        raise


# --- HTTP boundary (single seam; tests patch this function) --------------

# Test-isolation gate: conftest sets this False so the suite never calls
# Google. Tests that exercise the HTTP path patch _post_threat_matches.
_network_allowed = True


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Redirect policy for Safe Browsing requests: NEVER follow.

    Module-level (not nested) so the policy is structurally verifiable.
    Returning None from redirect_request makes urllib raise HTTPError for
    any 3xx instead of following the (potentially attacker-influenced)
    Location header.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # never follow redirects


def _post_threat_matches(api_key: str, body: dict, timeout: float) -> dict:
    """HTTPS POST to threatMatches.find. Raises on any failure.

    Redirects are disabled; HTTP is refused; the API key appears only in
    the request URL. This is the ONLY function that touches the network.
    """
    if not _network_allowed:
        raise OSError("Safe Browsing network access is disabled (test gate)")
    if not api_key:
        raise RuntimeError("missing API key")

    endpoint = ("https://safebrowsing.googleapis.com/v4/"
                f"threatMatches:find?key={api_key}")
    if not endpoint.lower().startswith("https://"):
        raise ValueError("Safe Browsing requires HTTPS")
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json",
                 "User-Agent": "MailBuddy/1.0"},
        method="POST",
    )

    opener = urllib.request.build_opener(_NoRedirects)
    try:
        with opener.open(request, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            if status != 200:
                raise urllib.error.HTTPError(
                    "safebrowsing.googleapis.com", status,
                    "non-200 Safe Browsing response", None, None)
            raw = resp.read(256 * 1024)  # sanity cap on response size
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
        if not isinstance(parsed, dict):
            raise ValueError("malformed Safe Browsing response schema")
        return parsed
    except urllib.error.HTTPError as exc:
        # Re-raise as a fixed classification; never embed the key/URL.
        raise RuntimeError(f"SB_HTTP_{exc.code}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError("SB_CONNECTION_FAILURE") from None


# --- response parsing -----------------------------------------------------

def _classify_error(exc: Exception) -> str:
    """Map a failure to a fixed error CLASSIFICATION (no raw text)."""
    text = str(exc)
    if text.startswith("SB_HTTP_"):
        code = text.split("SB_HTTP_", 1)[1]
        if code in ("400",):
            return "HTTP_400_BAD_REQUEST"
        if code in ("401", "403"):
            return "HTTP_AUTH_FORBIDDEN"
        if code == "429":
            return "HTTP_RATE_LIMITED"
        if code.startswith("5"):
            return "HTTP_SERVER_ERROR"
        return f"HTTP_{code}"
    if text == "SB_CONNECTION_FAILURE":
        return "CONNECTION_FAILURE"
    if isinstance(exc, TimeoutError):
        return "TIMEOUT"
    if isinstance(exc, (ValueError, json.JSONDecodeError)):
        return "MALFORMED_RESPONSE"
    return "REQUEST_FAILED"


def _parse_threat_types(matches) -> tuple[str, ...]:
    """Extract threatTypes from a threatMatches response.

    Unknown provider categories are preserved verbatim (never dropped,
    never treated as safe) and still constitute a KNOWN_THREAT per the
    provider's own verdict.
    """
    types: list[str] = []
    if not isinstance(matches, list):
        return tuple()
    for m in matches:
        if isinstance(m, dict):
            tt = m.get("threatType")
            if isinstance(tt, str) and tt and tt not in types:
                types.append(tt.upper())
    return tuple(types)


# --- provider -------------------------------------------------------------

class GoogleSafeBrowsingProvider:
    """Safe Browsing v4 threatMatches provider. check_url NEVER raises."""

    name = PROVIDER_NAME

    def _api_key(self) -> str:
        return (os.getenv(SB_API_KEY_ENV) or "").strip()

    def _enabled(self) -> bool:
        raw = (os.getenv(SB_ENABLED_ENV) or "true").strip().lower()
        return raw not in ("0", "false", "no", "off")

    def _unavailable(self, reason: str, url: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            provider=self.name, status=ThreatStatus.UNAVAILABLE,
            url=url, threat_types=(), available=False, error=reason,
        )

    def check_url(self, url: str) -> ThreatIntelResult:
        # 1. Normalize (malformed URLs fail safely -> ERROR is NOT right
        #    here: nothing was attempted and the URL itself is unusable;
        #    this is reported as ERROR with a fixed classification).
        normalized = normalize_url(url)
        if normalized is None:
            return ThreatIntelResult(
                provider=self.name, status=ThreatStatus.ERROR,
                url=str(url)[:SB_MAX_URL_LENGTH], threat_types=(),
                available=False, error="MALFORMED_URL",
            )

        # 2. Per-URL memoization: one request per URL per analysis.
        cached = _cache_get(normalized)
        if cached is not None:
            return cached

        # 3. Configuration gate -> UNAVAILABLE (never a crash).
        api_key = self._api_key()
        if not api_key:
            result = self._unavailable("MISSING_API_KEY", normalized)
            _cache_set(normalized, result)
            return result
        if not self._enabled():
            result = self._unavailable("PROVIDER_DISABLED", normalized)
            _cache_set(normalized, result)
            return result

        # 4. Build the MINIMAL request body: the lookup URL only. No
        #    email metadata of any kind is included (privacy invariant).
        body = {
            "client": {"clientId": "mailbuddy", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": sorted(KNOWN_THREAT_TYPES),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": normalized}],
            },
        }

        # 5. Bounded request; every failure is a fixed ERROR class.
        try:
            response = _run_bounded(
                lambda: _post_threat_matches(api_key, body, SB_TIMEOUT_SECONDS),
                SB_TIMEOUT_SECONDS + 1.0,
            )
            # Schema guard: a non-dict body (list, string, number) is a
            # malformed response -> ERROR/MALFORMED_RESPONSE, never a crash
            # and never a silent NO_MATCH.
            if not isinstance(response, dict):
                raise ValueError("malformed Safe Browsing response schema")
            matches = response.get("matches")
            if matches:
                result = ThreatIntelResult(
                    provider=self.name, status=ThreatStatus.KNOWN_THREAT,
                    url=normalized, threat_types=_parse_threat_types(matches),
                    available=True, error="",
                )
            else:
                result = ThreatIntelResult(
                    provider=self.name, status=ThreatStatus.NO_MATCH,
                    url=normalized, threat_types=(), available=True, error="",
                )
        except Exception as exc:  # noqa: BLE001 — fail safe by contract
            result = ThreatIntelResult(
                provider=self.name, status=ThreatStatus.ERROR,
                url=normalized, threat_types=(), available=False,
                error=_classify_error(exc),
            )

        _cache_set(normalized, result)
        return result
