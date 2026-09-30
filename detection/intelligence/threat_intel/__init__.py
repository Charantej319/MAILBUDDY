"""Threat intelligence providers (Session B).

Optional external lookups — currently Google Safe Browsing — that answer
one question per URL: is it a KNOWN_THREAT, NO_MATCH, UNAVAILABLE, or
ERROR? Only KNOWN_THREAT may produce a risk finding; every other state is
"no evidence" and must never raise phishing risk by itself.
"""

from .base import (
    KNOWN_THREAT_TYPES,
    ThreatIntelProvider,
    ThreatIntelResult,
    ThreatStatus,
)
from .google_safe_browsing import (
    GoogleSafeBrowsingProvider,
    PROVIDER_NAME,
    SB_API_KEY_ENV,
    SB_ENABLED_ENV,
    SB_MAX_URL_LENGTH,
    SB_TIMEOUT_SECONDS,
    clear_cache,
    normalize_url,
)


def get_provider() -> ThreatIntelProvider:
    """Return the configured provider (Google Safe Browsing)."""
    return GoogleSafeBrowsingProvider()


def check_url(url: str) -> ThreatIntelResult:
    """Convenience single-URL lookup via the default provider."""
    return get_provider().check_url(url)
