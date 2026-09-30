"""
Threat intelligence provider abstraction (Session B).

A provider answers ONE question about ONE URL:
    "Is this URL currently known to this provider as a threat?"

The four states below are deliberately distinct and MUST NOT be collapsed:

    KNOWN_THREAT  — the provider explicitly reports a supported threat.
    NO_MATCH      — the provider answered successfully: no threat reported.
                    NOTE: NO_MATCH is NOT a guarantee of safety.
    UNAVAILABLE   — the provider is not configured / intentionally disabled.
                    NOTE: UNAVAILABLE is NOT safe — it means "no evidence".
    ERROR         — the provider was attempted but failed (network, timeout,
                    malformed response, HTTP error).
                    NOTE: ERROR is NOT safe and must never raise risk by itself.

Provider failure must never INCREASE phishing risk by itself: only
KNOWN_THREAT results may produce risk findings. NO_MATCH / UNAVAILABLE /
ERROR are represented in structured intelligence results only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class ThreatStatus:
    """The four distinct provider states (never collapsed)."""

    KNOWN_THREAT = "KNOWN_THREAT"
    NO_MATCH = "NO_MATCH"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"

    ALL = (KNOWN_THREAT, NO_MATCH, UNAVAILABLE, ERROR)


# Threat types this integration explicitly recognizes. Google may return
# other types — unknown types are preserved verbatim in the result (never
# crashed on, never silently treated as safe).
KNOWN_THREAT_TYPES = frozenset({
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
})


@dataclass(frozen=True)
class ThreatIntelResult:
    """Structured outcome of one provider lookup for one URL.

    Keep this small: it maps directly onto the existing Finding system
    (only KNOWN_THREAT becomes a Finding) and onto structured intelligence
    summaries for the UI/explainability layer.
    """

    provider: str
    status: str                 # one of ThreatStatus
    url: str                    # the normalized URL that was looked up
    threat_types: tuple[str, ...] = ()   # provider-reported types (any set)
    available: bool = False     # True only when the provider answered
    error: str = ""             # fixed error CLASSIFICATION (never raw text,
                                # never exception strings, never the API key)

    @property
    def is_known_threat(self) -> bool:
        return self.status == ThreatStatus.KNOWN_THREAT

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "status": self.status,
            "url": self.url,
            "threat_types": list(self.threat_types),
            "available": self.available,
            "error": self.error,
        }


class ThreatIntelProvider(ABC):
    """Minimal provider interface: one method, one result, never raises."""

    name: str = "abstract"

    @abstractmethod
    def check_url(self, url: str) -> ThreatIntelResult:
        """Look up one URL. MUST NOT raise: failures are ERROR/UNAVAILABLE."""
        raise NotImplementedError
