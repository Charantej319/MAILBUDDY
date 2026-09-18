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

    def to_dict(self):
        d = asdict(self)
        d['category'] = self.category.value
        return d


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


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
    """Classify risk level based on score."""
    if score < 25:
        return "SAFE"
    elif score < 50:
        return "LOW RISK"
    elif score < 75:
        return "SUSPICIOUS"
    else:
        return "HIGH RISK"


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
