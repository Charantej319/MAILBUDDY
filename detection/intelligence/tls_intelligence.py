"""
TLS / certificate intelligence (Session C).

Passive, minimal TLS evidence for HTTPS URLs found in emails. This module
answers exactly one question per HTTPS URL: what is the observable state
of the certificate served for its hostname?

This is EVIDENCE, not a verdict:
- TLS_VALID does NOT prove a site is legitimate (most phishing sites have
  valid certificates — Let's Encrypt is free and automated).
- An invalid/expired/mismatched certificate is suspicious evidence but
  must never, by itself, make an email HIGH_RISK.

Strict security boundary (enforced below):

- NO webpage fetching, NO HTTP GET, NO redirects, NO HTML, NO JS, NO
  content inspection, NO link crawling.
- The ONLY network operation is a TLS ClientHello + handshake (no HTTP
  request is ever sent — the socket is closed before any application
  data would flow) to port 443 of the URL's own hostname, solely to
  observe the certificate.
- Bounded: hard connect + total timeout on the shared bounded-worker
  pattern (F-14 / domain_age / Safe Browsing); no unbounded threads.
- Private/local target protection BEFORE any connection: localhost,
  loopback, link-local, RFC1918, ULA, unspecified, and obviously
  internal hostnames are rejected without connecting. Because the
  hostname is resolved locally first and the connection uses the
  verified IP, DNS rebinding cannot redirect the probe into a private
  network.
- Only port 443 is ever contacted; no port scanning of any kind.
- Privacy: nothing about the email (sender, subject, body, headers,
  attachments) is transmitted — only a TLS handshake with the hostname
  taken from the URL itself. No webpage content is ever received.

States (never collapsed):

    TLS_VALID              certificate validates for the hostname
    TLS_EXPIRED            certificate validity period has ended
    TLS_HOSTNAME_MISMATCH  certificate is not valid for this hostname
    TLS_INVALID            other certificate validation failure
    TLS_UNAVAILABLE        host/port unreachable (no TLS observed)
    HTTP                   plain-HTTP URL — no TLS to inspect
    TLS_ERROR              timeout or TLS-level failure (no verdict)

Failure is never evidence of safety: TLS_UNAVAILABLE/TLS_ERROR are
recorded as structured intelligence and never raise risk by themselves.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TLS_CONNECT_TIMEOUT = 3.0   # bound on TCP connect
TLS_TOTAL_TIMEOUT = 6.0     # hard bound on the whole probe (connect+TLS)

# Single port. No port scanning, ever.
_TLS_PORT = 443

# --- cache (process-local, bounded, TTL; same shape as the other intel) ---
#
#   valid / expired / mismatch / invalid : 10 min (cert rotation is slow)
#   HTTP (plain URL)                     : 1 h  (URL property, never changes)
#   TLS_UNAVAILABLE                      : 60 s (negative — host may return)
#   TLS_ERROR                            : 60 s (negative — retry soon)

_CACHE_TTL = {
    "TLS_VALID": 600.0,
    "TLS_EXPIRED": 600.0,
    "TLS_HOSTNAME_MISMATCH": 600.0,
    "TLS_INVALID": 600.0,
    "HTTP": 3600.0,
    "TLS_UNAVAILABLE": 60.0,
    "TLS_ERROR": 60.0,
}
_CACHE_MAX_ENTRIES = 2048
_cache: dict[str, dict] = {}


def _cache_key(normalized_url: str) -> str:
    return normalized_url


def _cache_get(normalized_url: str):
    entry = _cache.get(_cache_key(normalized_url))
    if not entry:
        return None
    ttl = _CACHE_TTL.get(entry["result"]["state"], 60.0)
    if (time.time() - entry["ts"]) < ttl:
        return entry["result"]
    return None  # expired


def _cache_set(normalized_url: str, result: dict) -> None:
    if len(_cache) >= _CACHE_MAX_ENTRIES:
        _cache.clear()  # bounded, like the other intel caches
    _cache[_cache_key(normalized_url)] = {"ts": time.time(), "result": result}


def clear_cache() -> None:
    """Clear the TLS result cache (tests / cache reset)."""
    _cache.clear()


# ---------------------------------------------------------------------------
# URL normalization — REUSES the Safe Browsing normalizer (Session B) so the
# repository has exactly ONE URL normalization implementation.
# ---------------------------------------------------------------------------

from .threat_intel.google_safe_browsing import normalize_url  # noqa: E402


# ---------------------------------------------------------------------------
# Private / local target protection (checked BEFORE any connection)
# ---------------------------------------------------------------------------

# Hostnames that must never be probed regardless of what they resolve to.
_INTERNAL_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "local", "internal", "intranet", "corp", "corp.local", "lan",
    "host.docker.internal", "gateway.docker.internal",
    "metadata.google.internal",  # cloud metadata endpoints
}


def is_safe_public_hostname(hostname: str) -> bool:
    """True when hostname is structurally safe to contact for TLS evidence.

    Rejects obvious internal names; numerical hosts are judged by their
    address (private/loopback/link-local/unspecified are unsafe). A name
    that is neither internal nor numerical still passes here — the
    resolved IP is checked separately at probe time (rebinding-safe).
    """
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return False
    if host in _INTERNAL_HOSTNAMES:
        return False
    if host.endswith((".local", ".internal", ".lan", ".home", ".corp")):
        return False
    # Bare / bracketed IP literals.
    bare = host
    if bare.startswith("[") and bare.endswith("]"):
        bare = bare[1:-1]
    if bare.startswith(("v1.", "v2.")):  # IPvFuture forms per RFC 3986
        return False
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        return True  # a regular name; IP safety checked after resolution
    return _is_public_addr(addr)


def _is_public_addr(addr: "ipaddress._BaseAddress") -> bool:
    """True only for globally routable, non-special addresses."""
    return not (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
        or getattr(addr, "is_global", False) is False
    )


def _rebound_to_private_ip(resolved_ip: str) -> bool:
    """True when the RESOLVED address is not a safe public address.

    Called at probe time on the actual address a name resolved to, so a
    DNS rebinding attack cannot redirect the TLS probe into a private
    network: we connect to the vetted IP, never re-resolve.
    """
    try:
        addr = ipaddress.ip_address(resolved_ip)
    except ValueError:
        return True  # unparseable address — treat as unsafe
    return not _is_public_addr(addr)


# ---------------------------------------------------------------------------
# Result type (repository dataclass conventions)
# ---------------------------------------------------------------------------

@dataclass
class TLSResult:
    """TLS evidence for one URL. Small, structured, UI-safe."""

    url: str                  # the normalized URL that was inspected
    state: str                # one of the TLS_* / HTTP states above
    hostname: str = ""
    issuer: str = ""          # certificate issuer (organization), if available
    subject_cn: str = ""      # certificate commonName, if available
    not_before: str = ""      # ISO string, if available
    not_after: str = ""       # ISO string, if available
    error: str = ""           # fixed classification, never raw exception text

    @property
    def has_tls(self) -> bool:
        return self.state not in ("HTTP", "TLS_UNAVAILABLE", "TLS_ERROR")

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "state": self.state,
            "hostname": self.hostname,
            "issuer": self.issuer,
            "subject_cn": self.subject_cn,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "error": self.error,
        }


# Test-isolation gate: conftest sets False so the suite never opens sockets.
_network_allowed = True


# ---------------------------------------------------------------------------
# The TLS probe — the ONLY place a network operation happens
# ---------------------------------------------------------------------------

def _getaddrinfo(host: str, port: int):
    return socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)


def _socket_connect(family, socktype, proto, address: tuple, timeout: float):
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout)
    sock.connect(address)  # raises OSError on refusal/unreachable/timeout
    return sock


def _tls_wrap(sock: socket.socket, hostname: str, timeout: float):
    ctx = ssl.create_default_context()
    ctx.check_hostname = True    # hostname verification ON (secure default)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx.wrap_socket(sock, server_hostname=hostname)


def _classify_failure(exc: Exception) -> str:
    """Map a verification failure to the precise TLS_* state.

    The first handshake already ran with CERT_REQUIRED + check_hostname,
    so any SSLCertVerificationError means the certificate is NOT fully
    valid for this hostname. Which way it failed is taken from the
    exception's SSL reason string — a stable stdlib classification, not
    attacker-controlled content (the server can only fail the handshake,
    not choose our wording).
    """
    text = str(exc).lower()
    if ("hostname mismatch" in text or "doesn't match" in text
            or "does not match" in text or "is not valid for" in text):
        return "TLS_HOSTNAME_MISMATCH"
    if "expired" in text:
        return "TLS_EXPIRED"
    return "TLS_INVALID"


def _hostname_of(url: str) -> str:
    """Hostname of the ORIGINAL URL (bracketed IPv6 handled correctly).

    Deliberately NOT the normalized URL: the Safe Browsing normalizer
    rebuilds the netloc without brackets, which re-parses as a mangled
    name. urlparse on the original string strips brackets itself.
    """
    try:
        return (urlparse(url).hostname or "").strip().lower().rstrip(".")
    except ValueError:
        return ""


def probe_tls(url: str) -> dict:
    """Probe TLS state for one URL. Returns a TLSResult.to_dict().

    Fail-safe: never raises. Called only on public HTTPS hostnames.
    """
    result = TLSResult(url=url, state="TLS_ERROR")

    # Hostname comes from the ORIGINAL URL (bracketed IPv6-safe).
    hostname = _hostname_of(url)

    normalized = normalize_url(url)
    if normalized is None or not hostname:
        result.error = "MALFORMED_URL"
        return result.to_dict()
    result.url = normalized

    parsed = urlparse(url)
    if parsed.scheme == "http":
        result.state = "HTTP"
        result.hostname = hostname
        return result.to_dict()
    if parsed.scheme != "https":
        result.error = "UNSUPPORTED_SCHEME"
        return result.to_dict()

    result.hostname = hostname
    if not hostname or not is_safe_public_hostname(hostname):
        result.state = "TLS_ERROR"
        result.error = "UNSAFE_TARGET"
        return result.to_dict()

    # Cache (after cheap local checks, before any network work).
    cached = _cache_get(normalized)
    if cached is not None:
        return cached

    if not _network_allowed:
        result.state = "TLS_ERROR"
        result.error = "NETWORK_DISABLED"
        return result.to_dict()

    try:
        result_dict = _probe_with_socket(hostname, result)
    except _TLSUnavailable:
        result.state = "TLS_UNAVAILABLE"
        result.error = "CONNECT_FAILED"
        result_dict = result.to_dict()
    except _TLSTimeout:
        result.state = "TLS_ERROR"
        result.error = "TIMEOUT"
        result_dict = result.to_dict()
    except _TLSError as exc:
        result.state = "TLS_ERROR"
        result.error = exc.reason
        result_dict = result.to_dict()
    except _TLSVerdict as exc:
        # Certificate verdict (valid/expired/mismatch/invalid) with metadata.
        result_dict = exc.payload

    _cache_set(normalized, result_dict)
    return result_dict


class _TLSUnavailable(Exception):
    pass


class _TLSTimeout(Exception):
    pass


class _TLSError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _TLSVerdict(Exception):
    """Carrier for a definitive certificate verdict + metadata."""

    def __init__(self, payload: dict):
        super().__init__(payload.get("state", "TLS_ERROR"))
        self.payload = payload


def _probe_with_socket(hostname: str, base: TLSResult) -> dict:
    """Bounded TLS handshake producing a verdict dict. Raises carriers."""
    from concurrent.futures import TimeoutError as FuturesTimeoutError
    from .threat_intel.google_safe_browsing import _run_bounded

    def _do_probe() -> dict:
        # 1. Resolve ONCE and vet the address (rebinding-safe: we connect
        #    to exactly this vetted IP, never re-resolve).
        try:
            infos = _getaddrinfo(hostname, _TLS_PORT)
        except socket.gaierror:
            raise _TLSUnavailable()
        if not infos:
            raise _TLSUnavailable()
        family, socktype, proto, _canon, address = infos[0]
        ip = address[0]
        if _rebound_to_private_ip(ip):
            # Private/loopback/link-local/unspecified: never connect.
            raise _TLSError("UNSAFE_TARGET")

        # 2. Bounded TCP connect (port 443 only).
        try:
            raw_sock = _socket_connect(family, socktype, proto, address,
                                       TLS_CONNECT_TIMEOUT)
        except (socket.timeout, TimeoutError):
            raise _TLSTimeout()
        except OSError:
            raise _TLSUnavailable()

        # 3. TLS handshake with full verification. No HTTP request is
        #    ever sent; the socket is closed before application data.
        sock = None
        try:
            try:
                sock = _tls_wrap(raw_sock, hostname, TLS_TOTAL_TIMEOUT)
                sock.settimeout(TLS_TOTAL_TIMEOUT)
            except ssl.SSLCertVerificationError as exc:
                state = _classify_failure(exc)
                raise _TLSVerdict(_verdict_payload(base, state))
            except ssl.SSLError as exc:
                raise _TLSError("TLS_HANDSHAKE_FAILURE")

            # 4. Definitive verdict: chain AND hostname verified.
            #    Expiry check: the verified cert's dates; if parsing fails
            #    the handshake verdict (valid) stands.
            cert = sock.getpeercert() or {}
            payload = _verdict_payload(base, "TLS_VALID", cert)
            try:
                import ssl as _ssl
                import time as _time
                if cert and _ssl.cert_time_to_seconds(cert["notAfter"]) < _time.time():
                    payload = _verdict_payload(base, "TLS_EXPIRED", cert)
            except (KeyError, ValueError):
                pass
            return payload
        finally:
            try:
                if sock is not None:
                    sock.close()
                else:
                    raw_sock.close()
            except OSError:
                pass

    try:
        return _run_bounded(_do_probe, TLS_TOTAL_TIMEOUT + 1.0)
    except FuturesTimeoutError:
        raise _TLSTimeout()


def _verdict_payload(base: TLSResult, state: str, cert: dict | None = None) -> dict:
    """Build the result payload for a certificate verdict."""
    payload = TLSResult(
        url=base.url, state=state, hostname=base.hostname,
    ).to_dict()
    if cert:
        # Only minimal, useful metadata — never the raw certificate.
        issuer = cert.get("issuer") or ()
        for rdn in issuer:
            for key, value in rdn:
                if key == "organizationName" and value:
                    payload["issuer"] = value
        subject = cert.get("subject") or ()
        for rdn in subject:
            for key, value in rdn:
                if key == "commonName" and value:
                    payload["subject_cn"] = value
        payload["not_before"] = cert.get("notBefore", "") or ""
        payload["not_after"] = cert.get("notAfter", "") or ""
    return payload


# ---------------------------------------------------------------------------
# Findings data (Session C follows the Session B pattern: the module
# provides structured evidence; DomainIntelligence builds Finding objects
# from it, keeping all rule construction in one place).
# ---------------------------------------------------------------------------

# rule_id -> (severity, points) for certificate-failure findings.
# Points are minimal on purpose: TLS evidence must not inflate scores, and
# TLS_VALID produces NO finding at all (never a "safe" bonus either).
TLS_FINDING_RULES: dict[str, tuple[str, float]] = {
    "TLS_EXPIRED": ("LOW", 2),
    "TLS_HOSTNAME_MISMATCH": ("MEDIUM", 4),
    "TLS_INVALID": ("LOW", 2),
}
