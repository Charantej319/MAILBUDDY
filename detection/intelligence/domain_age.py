"""
Domain Age Intelligence (Session A, MailBuddy).

Passive, privacy-respecting estimation of sender-domain age via public
Registration Data Access Protocol (RDAP) endpoints (RFC 7480-7484), with
 graceful degradation and NO hard dependency on any new library.

Design invariants
-----------------
- Passive only: RDAP is a plain HTTPS GET on a public registry record.
  No port scanning, no mailbox verification, no intrusive probing.
- Fail SAFE: any error (no network, malformed response, unsupported TLD,
  timeout) yields "no evidence" — never an exception and never a
  fabricated legitimacy claim. `_EMPTY_AGE` is the universal "unknown".
- Bounded time: a hard timeout (`_RDAP_TIMEOUT_SECONDS`) on a shared
  bounded worker pool, mirroring F-14, so a slow resolver can never
  stall the FastAPI event loop or the sync path.
- No new dependencies: uses urllib (stdlib) inside the bounded pool. The
  optional `requests` library is used only when already installed.
- Zero false positives from age alone: domain age modulates severity of
  OTHER findings (e.g. brand impersonation); it never convicts a domain
  by itself. Age is one signal, not a verdict.
- Cache-first: module-level TTL cache identical in shape to
  `_intel_cache` in domain_intelligence.py; the guardrails in
  `_cache_key` / `_get_cached` / `_set_cached` (md5 key, TTL, shared
  cache for per-run correctness) come from that module so behavior is
  consistent across the intelligence package.

Public surface
--------------
- get_domain_age(domain) -> dict        (main entry point)
- clear_age_cache() -> None
- AGE_RULE_ID / AGE_FINDINGS builder, used by domain_intelligence.py
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.request
import urllib.error
from typing import Optional

from ..rules import Finding, Severity, Category

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Hard wall-clock budget for one RDAP request. Same philosophy as F-14's
# _DNS_TIMEOUT_SECONDS: slow endpoints must never stall analysis.
RDAP_TIMEOUT_SECONDS = 4.0

# Bound on the worker pool serving blocking RDAP calls. Small by design:
# lookups are cache-absorbed and rare relative to email volume.
RDAP_MAX_WORKERS = 2

# Cache TTL for age results. Domain age changes ~never; a long TTL is safe.
AGE_CACHE_TTL = 24 * 3600  # seconds

# Threshold (days) distinguishing "young" from "established".
# Consistent with industry heuristics (e.g. PhishLabs/Alias reports):
# the overwhelming majority of phishing domains are under ~30 days old.
YOUNG_DOMAIN_DAYS = 30

# Threshold beyond which a domain is considered clearly established.
ESTABLISHED_DOMAIN_DAYS = 365

# Cap on findings-eligible range: domains older than this are simply
# "established" and get NO finding at all (never a positive signal).
_OLD_DOMAIN_DAYS = 3650  # ~10 years

# Bounded module-level worker pool, created lazily, shared with the
# intelligence package's DNS pool philosophy (bounded, never unbounded).
_EXECUTOR = None

# RDAP base endpoints. IANA's bootstrap service redirects per-TLD; a
# direct two-tier fallback avoids needing the full bootstrap dataset.
_RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"

# TLDs known to publish RDAP directly (fallback if bootstrap unreachable).
_RDAP_DIRECT_SUFFIXES = {
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
}


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------

# Universal "unknown / no evidence" result.
_EMPTY_AGE: dict = {
    "age_known": False,
    "age_days": None,
    "creation_date": None,
    "registrar": None,
    "registrar_url": None,
    "age_category": "unknown",   # unknown | young | recent | established
    "source": None,
}


def _empty_age() -> dict:
    """Fresh copy of the universal 'no evidence' result."""
    return dict(_EMPTY_AGE)


# ---------------------------------------------------------------------------
# Bounded execution
# ---------------------------------------------------------------------------

def _get_executor():
    """Lazily created shared bounded pool for blocking RDAP work (F-14 style)."""
    global _EXECUTOR
    if _EXECUTOR is None:
        from concurrent.futures import ThreadPoolExecutor
        _EXECUTOR = ThreadPoolExecutor(
            max_workers=RDAP_MAX_WORKERS,
            thread_name_prefix="phishguard-rdap",
        )
    return _EXECUTOR


def _run_bounded(fn, timeout: float):
    """Run blocking fn() with a hard timeout on the shared bounded pool.

    Raises the underlying exception on timeout (after abandoning the
    worker — the pool keeps it bounded so repeated timeouts cannot leak
    threads). The caller is expected to treat every failure as 'no
    evidence'.
    """
    from concurrent.futures import TimeoutError as FuturesTimeoutError
    executor = _get_executor()
    future = executor.submit(fn)
    try:
        return future.result(timeout=timeout)
    except FuturesTimeoutError:
        future.cancel()
        raise


# ---------------------------------------------------------------------------
# Domain plausibility guard (same contract as domain_intelligence.py)
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def _is_plausible_domain(domain: str) -> bool:
    """Cheap structural check; garbage never reaches the network."""
    return bool(_DOMAIN_RE.match((domain or "").strip()))


def _registrable(domain: str) -> str:
    """Registrable domain (last two labels, common two-level suffix aware).

    Kept dependency-free and consistent with detection.sender._split_domain
    and domain_intelligence._registrable (same two-level suffix set).
    """
    domain = (domain or "").lower().strip().rstrip(".")
    if not domain:
        return ""
    labels = domain.split(".")
    if len(labels) < 2:
        return domain
    two_level_suffixes = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in",
        "com.br", "co.jp", "co.za", "com.mx", "co.nz", "co.kr",
    }
    if len(labels) >= 3 and ".".join(labels[-2:]) in two_level_suffixes:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# ---------------------------------------------------------------------------
# Cache (mirrors domain_intelligence cache shape)
# ---------------------------------------------------------------------------

_age_cache: dict[str, dict] = {}


def _cache_key(domain: str) -> str:
    return hashlib.md5(domain.lower().strip().encode()).hexdigest()


def _get_cached_age(domain: str) -> Optional[dict]:
    entry = _age_cache.get(_cache_key(domain))
    if entry and (time.time() - entry["timestamp"]) < AGE_CACHE_TTL:
        return entry["result"]
    return None


def _set_cached_age(domain: str, result: dict) -> None:
    # Size guard: bounded by distinct domains seen; entries expire with
    # clear_age_cache() or process end.
    if len(_age_cache) > 2048:
        _age_cache.clear()
    _age_cache[_cache_key(domain)] = {
        "timestamp": time.time(),
        "result": result,
    }


def clear_age_cache() -> None:
    """Clear the domain-age cache (public helper for tests and cache reset)."""
    _age_cache.clear()


# ---------------------------------------------------------------------------
# RDAP response parsing
# ---------------------------------------------------------------------------

# RFC 3339-ish timestamp; RDAP also emits some with trailing 'Z' and some
# fractional seconds, so accept both.
_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?$"
)


def _parse_iso8601(value: str):
    """Parse an RDAP event timestamp into a timezone-naive UTC datetime.

    Returns None for anything unparseable. Timezone-aware inputs are
    normalized to UTC then made naive so date arithmetic is consistent.
    """
    from datetime import datetime, timezone

    if not isinstance(value, str):
        return None
    s = value.strip()
    m = _ISO_RE.match(s)
    if not m:
        # Last resort: let datetime.fromisoformat try (Py 3.11+ handles 'Z').
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    year, month, day, hh, mm, ss = (int(g) for g in m.groups())
    try:
        # Trailing offset already validated by the regex; 'Z' handled below.
        if s.endswith(("Z", "z")):
            return datetime(year, month, day, hh, mm, ss, tzinfo=timezone.utc) \
                .replace(tzinfo=None)
        # Numeric offsets: parse via fromisoformat to honor the offset.
        return datetime.fromisoformat(s.replace(" ", "T")).astimezone(
            timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


def _extract_creation_event(rdap_json: dict):
    """Extract the domain creation (registration) event per RFC 7483 §5.1.

    Prefers eventAction == "registration"; falls back to the first
    parseable date in the (deprecated but still common) top-level
    "events" list or legacy non-standard fields.
    """
    if not isinstance(rdap_json, dict):
        return None

    events = rdap_json.get("events") or []
    if isinstance(events, list):
        for ev in events:
            if not isinstance(ev, dict):
                continue
            action = str(ev.get("eventAction", "")).lower()
            if action in ("registration", "created", "created date"):
                dt = _parse_iso8601(ev.get("eventDate"))
                if dt:
                    return dt

    # Legacy / non-standard fallbacks seen in some registry responses.
    for key in ("creationDate", "created", "registrationDate"):
        dt = _parse_iso8601(rdap_json.get(key))
        if dt:
            return dt
    return None


def _extract_registrar(rdap_json: dict):
    """Best-effort registrar name/URL from RDAP entities (RFC 7483 §5.1)."""
    if not isinstance(rdap_json, dict):
        return None, None
    entities = rdap_json.get("entities") or []
    if not isinstance(entities, list):
        return None, None
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = ent.get("roles") or []
        if "registrar" not in roles:
            continue
        vcard = ent.get("vcardArray")
        name = None
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and item and item[0] == "fn":
                    name = item[3] if len(item) > 3 else None
                    break
        if not name:
            name = ent.get("handle")
        links = ent.get("links") or []
        url = None
        for link in links:
            if isinstance(link, dict) and link.get("href"):
                url = link.get("href")
                break
        return name, url
    return None, None


def _classify_age(age_days: int) -> str:
    """Bucket an age in days into young | recent | established."""
    if age_days < YOUNG_DOMAIN_DAYS:
        return "young"
    if age_days < ESTABLISHED_DOMAIN_DAYS:
        return "recent"
    return "established"


# ---------------------------------------------------------------------------
# RDAP network access
# ---------------------------------------------------------------------------

def _http_get_json(url: str, timeout: float):
    """Fetch JSON over HTTPS using stdlib urllib, bounded in time.

    Raises on any network/HTTP/parse failure — the caller fail-safes.
    Only https:// URLs are allowed (never redirects to other schemes).

    Test hermeticity: when _RDAP_NETWORK_ALLOWED is False (set by the
    suite-wide conftest fixture) this raises before touching the network.
    Tests that exercise the RDAP path replace _http_get_json itself via
    monkeypatch, so they bypass the gate entirely.
    """
    if not url.lower().startswith("https://"):
        raise ValueError("RDAP requires HTTPS")
    if not _RDAP_NETWORK_ALLOWED:
        raise OSError("RDAP network access is disabled (test isolation gate)")
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/rdap+json, application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = getattr(resp, "status", None) or resp.getcode()
        if status != 200:
            raise urllib.error.HTTPError(url, status, "non-200 RDAP response",
                                         None, None)
        charset = resp.headers.get_content_charset() or "utf-8"
        raw = resp.read(max(1, 256 * 1024))  # sanity cap on response size
        return json.loads(raw.decode(charset, errors="replace"))


def _fetch_rdap(domain: str) -> dict:
    """Fetch and parse the RDAP record for a registrable domain.

    Tries the IANA bootstrap redirector first (rdap.org), then a small
    direct-endpoint fallback. Raises on total failure; caller fail-safes.
    """
    registrable = _registrable(domain)
    if not registrable or not _is_plausible_domain(registrable):
        raise ValueError(f"implausible domain: {domain!r}")

    urls = [_RDAP_BOOTSTRAP_URL.format(domain=registrable)]
    tld = registrable.rsplit(".", 1)[-1]
    direct = _RDAP_DIRECT_SUFFIXES.get(tld)
    if direct:
        urls.append(direct + registrable)

    last_exc: Optional[Exception] = None
    for url in urls:
        try:
            data = _run_bounded(
                lambda u=url: _http_get_json(u, RDAP_TIMEOUT_SECONDS),
                RDAP_TIMEOUT_SECONDS + 1.0,
            )
            if isinstance(data, dict):
                global _last_success_host
                try:
                    from urllib.parse import urlparse
                    _last_success_host = urlparse(url).netloc or None
                except Exception:
                    _last_success_host = None
                return data
        except Exception as exc:  # noqa: BLE001 — deliberate broad catch
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"no RDAP data for {registrable!r}")


# ---------------------------------------------------------------------------
# Findings builder
# ---------------------------------------------------------------------------

# The rule_id used by the age-derived findings.
AGE_RULE_ID_YOUNG = "INTEL_YOUNG_DOMAIN"

# Severity modulation applied by OTHER analyzers is out of scope here; this
# module only emits its own self-contained findings.


def _age_findings(age_result: dict) -> list:
    """Build Finding objects from an age result.

    Two self-contained findings:
      - INTEL_YOUNG_DOMAIN:      MEDIUM, +8   (age < 30 days)
      - INTEL_DOMAIN_RECENT:     LOW,    +3   (age < 365 days)
    Established domains (>= 365 days) get NO finding — age alone never
    proves legitimacy and age alone never proves guilt.
    """
    findings: list = []
    if not age_result.get("age_known"):
        return findings

    age_days = age_result.get("age_days")
    if age_days is None:
        return findings
    age_days = int(age_days)

    created = age_result.get("creation_date") or "unknown date"
    src = "RDAP (passive)"

    if age_days < YOUNG_DOMAIN_DAYS:
        findings.append(Finding(
            rule_id=AGE_RULE_ID_YOUNG,
            category=Category.INTEL,
            severity=Severity.MEDIUM.value,
            points=8,
            message=(
                f"Domain is very young ({age_days} day(s) old, registered "
                f"{created})."
            ),
            evidence=f"age_days={age_days}; creation={created}; "
                     f"source={age_result.get('source')}",
            explanation=(
                "The sender domain was registered within the last 30 days. "
                "Most phishing domains are brand new; a young domain is a "
                "meaningful risk signal, though not proof of malicious intent "
                "(legitimate businesses do launch new domains)."
            ),
            source=src,
        ))
    elif age_days < ESTABLISHED_DOMAIN_DAYS:
        findings.append(Finding(
            rule_id="INTEL_DOMAIN_RECENT",
            category=Category.INTEL,
            severity=Severity.LOW.value,
            points=3,
            message=f"Domain is relatively new ({age_days} days old).",
            evidence=f"age_days={age_days}; creation={created}; "
                     f"source={age_result.get('source')}",
            explanation=(
                "The sender domain is less than a year old. This is a weak "
                "signal on its own but adds context when combined with other "
                "indicators."
            ),
            source=src,
        ))
    # Established: no finding — absence of a finding is the correct
    # 'no evidence' representation (age never confers trust).

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def get_domain_age(domain: str) -> dict:
    """Estimate sender-domain age passively via public RDAP records.

    Returns a dict (never raises):
        age_known      bool           False = 'no evidence'
        age_days       int | None
        creation_date  str | None     ISO date of registration event
        registrar      str | None
        registrar_url  str | None
        age_category   str            unknown | young | recent | established
        source         str | None     e.g. 'rdap.verisign.com'

    Failure semantics (all yield `_empty_age()`, never raise):
        - empty / implausible / non-registrable domain
        - no network, DNS failure, TLS failure, timeout
        - HTTP non-200 (including 404 = no RDAP record)
        - malformed JSON or missing creation event
        - any unexpected internal error
    """
    result = _empty_age()
    if not domain or not isinstance(domain, str):
        return result

    domain = domain.strip()
    if not _is_plausible_domain(domain):
        return result

    cached = _get_cached_age(domain)
    if cached is not None:
        return dict(cached)

    try:
        rdap = _fetch_rdap(domain)
    except Exception:
        # Fail SAFE: network problems, 404s, timeouts, garbage — 'no evidence'.
        # The negative result is cached briefly to avoid hammering a broken
        # resolver on every email from the same domain.
        result = _empty_age()
        _set_cached_age(domain, result)
        return result

    created = _extract_creation_event(rdap)
    if created is None:
        # Record exists but no usable creation date — still 'no evidence'.
        result = _empty_age()
        _set_cached_age(domain, result)
        return result

    registrar_name, registrar_url = _extract_registrar(rdap)
    # created is a naive UTC datetime (normalized in _parse_iso8601); use
    # calendar.timegm so the epoch conversion never re-interprets it as
    # LOCAL time (naive .timestamp() would, skewing age_days by the machine's
    # UTC offset).
    import calendar
    now = time.time()
    age_days = max(0, int((now - calendar.timegm(created.utctimetuple())) // 86400))

    source = None
    try:
        links = rdap.get("links") or []
        if links and isinstance(links[0], dict):
            from urllib.parse import urlparse
            source = urlparse(links[0].get("href", "")).netloc or None
    except Exception:
        source = None
    if not source:
        # Fall back to the request host that actually succeeded.
        source = _last_success_host or None

    result = {
        "age_known": True,
        "age_days": age_days,
        "creation_date": created.date().isoformat(),
        "registrar": registrar_name,
        "registrar_url": registrar_url,
        "age_category": _classify_age(age_days),
        "source": source,
    }
    _set_cached_age(domain, result)
    return result


# Host of the last successful RDAP fetch (used only as a metadata fallback;
# not security-relevant). Set inside _fetch_rdap on success.
_last_success_host: Optional[str] = None

# Test-isolation gate: when False, _http_get_json refuses to open network
# connections. Defaults to True (production behavior); conftest.py flips it
# off suite-wide so existing tests never make real RDAP requests.
_RDAP_NETWORK_ALLOWED = True


# ---------------------------------------------------------------------------
# Integration: findings hook used by domain_intelligence.py
# ---------------------------------------------------------------------------

def get_domain_age_with_findings(domain: str) -> tuple[dict, list]:
    """Convenience wrapper returning (age_result, findings).

    The findings list is empty when age is unknown or established.
    """
    age = get_domain_age(domain)
    return age, _age_findings(age)


# ---------------------------------------------------------------------------
# Self-test / smoke check
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    demo = get_domain_age("google.com")
    print(json.dumps(demo, indent=2, default=str))
