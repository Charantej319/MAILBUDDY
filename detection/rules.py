"""
Detection rules metadata and constants.
Defines rule IDs, categories, severity levels, weight configurations,
and the enhanced Finding dataclass with full explainability.
"""

from enum import Enum
from dataclasses import dataclass, asdict, field
from typing import Optional


@dataclass
class Finding:
    """A single detection finding with full explainability."""
    rule_id: str
    category: 'Category'
    severity: str
    points: float
    message: str
    evidence: str = ""
    explanation: str = ""
    source: str = "Local analysis"
    # Canonical identity for deduplication of correlated events. Two findings
    # with the same (rule_id, dedup_key) describe the same underlying mismatch
    # (e.g. From/Reply-To and From/Return-Path disagreeing with the sender
    # domain) and contribute ONE scoring entry — the highest-severity copy at
    # full points — while keeping understandable evidence from the original
    # finding that it overlaps with the winner.
    dedup_key: str = ""

    def to_dict(self):
        d = asdict(self)
        d['category'] = self.category.value
        return d


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# F-9: THE canonical severity ranking. Severity strings must never be
# compared alphabetically ("HIGH" >= "CRITICAL" is True as a string compare,
# which lets a HIGH finding replace a CRITICAL one in winner selection).
# Every severity comparison in scoring/correlation code goes through
# severity_rank(); values are the project's actual Severity enum values.
_SEVERITY_RANK = {
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


def severity_rank(severity: str) -> int:
    """Numeric rank for a severity value (LOW=1 < MEDIUM=2 < HIGH=3 < CRITICAL=4).

    Unknown severity strings rank 0 so malformed data never outranks real
    findings.
    """
    return _SEVERITY_RANK.get((severity or "").upper(), 0)


class Category(str, Enum):
    SENDER = "SENDER"
    URL = "URL"
    CONTENT = "CONTENT"
    HEADER = "HEADER"
    ATTACHMENT = "ATTACHMENT"
    INTEL = "INTEL"
    CORRELATION = "CORRELATION"
    OTHER = "OTHER"


# Maximum score contribution per category (evidence-weighted)
CATEGORY_WEIGHTS = {
    Category.SENDER: 20,
    Category.URL: 25,
    Category.CONTENT: 20,
    Category.HEADER: 20,
    Category.ATTACHMENT: 10,
    Category.INTEL: 5,
    Category.CORRELATION: 10,
    Category.OTHER: 5,
}


def classify_risk(score: float) -> str:
    """Classify risk level based on score.

    Returns the CANONICAL internal representation (F-21):
    SAFE | LOW_RISK | SUSPICIOUS | HIGH_RISK — machine-form, used by the
    detection engine, the DB, and all backend filters. Human-readable
    display labels ("HIGH RISK") are derived via risk_display_label().
    """
    score = max(0.0, min(score, 100.0))
    if score < 25:
        return RiskLevel.SAFE
    elif score < 50:
        return RiskLevel.LOW_RISK
    elif score < 75:
        return RiskLevel.SUSPICIOUS
    else:
        return RiskLevel.HIGH_RISK


# F-21: THE single source of truth for risk-level representation.
# Internal canonical values use the machine form (HIGH_RISK); the historical
# engine output used the display form ("HIGH RISK"). Both are accepted by
# normalize_risk_level() so persisted legacy rows never disappear from
# filters, and display labels come ONLY from risk_display_label().
class RiskLevel:
    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"


_RISK_LEVEL_ALIASES = {
    "SAFE": RiskLevel.SAFE,
    "LOW_RISK": RiskLevel.LOW_RISK,
    "LOW RISK": RiskLevel.LOW_RISK,
    "LOWRISK": RiskLevel.LOW_RISK,
    "SUSPICIOUS": RiskLevel.SUSPICIOUS,
    "HIGH_RISK": RiskLevel.HIGH_RISK,
    "HIGH RISK": RiskLevel.HIGH_RISK,
    "HIGHRISK": RiskLevel.HIGH_RISK,
    "MEDIUM": RiskLevel.SUSPICIOUS,  # legacy variant seen in exports
    "THREAT": RiskLevel.HIGH_RISK,   # frontend display label
    "REVIEW": RiskLevel.SUSPICIOUS,
}


def normalize_risk_level(value: str) -> str:
    """Normalize any stored/legacy risk representation to the canonical form.

    Accepts machine form ("HIGH_RISK"), display form ("HIGH RISK"), and
    known legacy variants; unknown values map to SAFE (fail-safe: an
    unparseable level never inflates risk).
    """
    if not value:
        return RiskLevel.SAFE
    return _RISK_LEVEL_ALIASES.get(str(value).strip().upper(), RiskLevel.SAFE)


def risk_display_label(value: str) -> str:
    """Human-readable display label for a canonical (or legacy) risk value.

    The frontend's displayed text keeps the traditional spaced form —
    normalize first so both stored forms render identically.
    """
    canonical = normalize_risk_level(value)
    return {
        RiskLevel.SAFE: "SAFE",
        RiskLevel.LOW_RISK: "LOW RISK",
        RiskLevel.SUSPICIOUS: "SUSPICIOUS",
        RiskLevel.HIGH_RISK: "HIGH RISK",
    }[canonical]


def is_risky_level(value: str) -> bool:
    """True for any risk representation that means SUSPICIOUS or worse.

    The one place filters (MailBuddy priority/assistant, statistics, threat
    lists) should test flagged-ness — accepts both stored forms.
    """
    return normalize_risk_level(value) in (RiskLevel.SUSPICIOUS, RiskLevel.HIGH_RISK)


def calculate_confidence(findings: list, has_intel: bool = False) -> tuple[str, float]:
    """
    Calculate analysis confidence based on available evidence.
    
    Returns (level, numeric) where level is LOW/MEDIUM/HIGH/VERY HIGH.
    
    Confidence reflects how much supporting evidence was available,
    NOT how certain we are about the classification.
    """
    if not findings:
        return ("LOW", 0.25)

    # Evidence richness signals
    has_auth_data = any(f.rule_id.startswith("HEADER_SPF") or 
                        f.rule_id.startswith("HEADER_DKIM") or 
                        f.rule_id.startswith("HEADER_DMARC") for f in findings)
    has_sender_intel = any(f.category.value == "SENDER" for f in findings)
    has_url_data = any(f.category.value == "URL" for f in findings)
    has_content = any(f.category.value == "CONTENT" for f in findings)
    has_attachments = any(f.category.value == "ATTACHMENT" for f in findings)
    has_correlation = any(f.category.value == "CORRELATION" for f in findings)
    
    # Count distinct evidence sources
    evidence_sources = sum([
        has_auth_data,
        has_sender_intel,
        has_url_data,
        has_content,
        has_attachments,
        has_intel,
        has_correlation,
    ])

    # Count total findings as proxy for evidence volume
    finding_count = len(findings)
    high_findings = sum(1 for f in findings if f.severity in ("HIGH", "CRITICAL"))

    # Calculate confidence
    confidence = 0.0

    # Base: evidence source diversity (max 0.45)
    confidence += evidence_sources * 0.065

    # Finding volume bonus (max 0.25)
    if finding_count >= 10:
        confidence += 0.25
    elif finding_count >= 6:
        confidence += 0.20
    elif finding_count >= 3:
        confidence += 0.15
    elif finding_count >= 1:
        confidence += 0.10

    # High-severity findings add confidence (max 0.15)
    if high_findings >= 3:
        confidence += 0.15
    elif high_findings >= 1:
        confidence += 0.10

    # Correlation findings significantly boost confidence (max 0.15)
    if has_correlation:
        confidence += 0.15

    # Cap at 1.0
    confidence = min(confidence, 1.0)

    # Map to levels
    if confidence >= 0.75:
        level = "VERY HIGH"
    elif confidence >= 0.55:
        level = "HIGH"
    elif confidence >= 0.35:
        level = "MEDIUM"
    else:
        level = "LOW"

    return (level, round(confidence, 2))
