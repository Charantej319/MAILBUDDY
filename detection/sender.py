"""
Sender and domain analysis module.
Detects lookalike domains, display name mismatches, brand impersonation, etc.
Enhanced with full explainability.
"""

import re
from difflib import SequenceMatcher
from .rules import Finding, Severity, Category


# Known brand domains for impersonation detection
KNOWN_BRANDS = {
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "live.com",
    "apple.com", "icloud.com", "amazon.com", "amazon.co.uk",
    "facebook.com", "fb.com", "instagram.com",
    "paypal.com", "ebay.com", "netflix.com", "spotify.com",
    "twitter.com", "x.com", "linkedin.com",
    "dropbox.com", "github.com", "microsoft365.com",
    "office.com", "office365.com", "live.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com",
    "zoom.us", "slack.com", "teams.microsoft.com",
}

# Brand names to check for in domains
BRAND_NAMES = [
    "google", "microsoft", "apple", "amazon", "paypal", "facebook",
    "netflix", "bank", "secure", "verify", "account", "login", "auth",
    "outlook", "office", "dropbox", "linkedin", "twitter", "instagram",
    "dhl", "fedex", "ups", "usps", "ebay", "walmart", "target",
    "visa", "mastercard", "amex", "chase", "wellsfargo", "citibank",
    "uber", "airbnb", "spotify", "zoom", "slack", "github",
]

# Free/personal mailbox providers used by the sender analysis below.
FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "protonmail.com", "proton.me", "icloud.com",
    "mail.com", "gmx.com", "yandex.com", "zoho.com",
}

# Display-name / content terms that indicate claimed organisational authority.
_AUTHORITY_TERMS = (
    "ceo", "cfo", "cto", "coo", "chief", "president", "director",
    "vp "
    "manager", "head of", "founder", "owner", "principal",
    "hr department", "human resources", "it department", "it support",
    "admin", "administrator", "system administrator",
)

# Phishing-relevant actions that make claimed authority dangerous when the
# address is a freemail account (classic BEC pattern).
_BEC_ACTION_TERMS = (
    "wire transfer", "wire", "transfer", "payment", "invoice", "bank",
    "gift card", "credentials", "password", "payroll", "tax",
    "urgent", "confidential", "verify", "confirm", "account number",
    "routing", "iban", "swift",
)

# Character substitution mappings (homoglyphs)
HOMOGLYPH_MAP = {
    '0': 'o', 'o': '0',
    '1': 'l', 'l': '1', '1': 'i', 'i': '1',
    '3': 'e', 'e': '3',
    '5': 's', 's': '5',
    '8': 'b', 'b': '8',
    '@': 'a',
    'rn': 'm', 'm': 'rn',
    'cl': 'd', 'd': 'cl',
    'vv': 'w', 'w': 'vv',
}


def normalize_domain(domain: str) -> str:
    """Normalize a domain by applying common homoglyph substitutions."""
    normalized = domain.lower().strip()
    for chars, replacement in HOMOGLYPH_MAP.items():
        if len(chars) > 1:
            normalized = normalized.replace(chars, replacement)
    return normalized


def similarity_ratio(s1: str, s2: str) -> float:
    """Calculate string similarity ratio."""
    return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()


def detect_character_substitutions(domain: str) -> list[str]:
    """Detect suspicious character substitutions in a domain."""
    substitutions = []
    digit_to_letter = {'0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b'}
    for digit, letter in digit_to_letter.items():
        if digit in domain:
            substitutions.append(f"'{digit}' may be used as '{letter}'")
    return substitutions


def check_brand_impersonation(domain: str) -> list[Finding]:
    """Check if a domain impersonates a known brand."""
    findings = []

    if domain in KNOWN_BRANDS:
        return findings

    domain_base = domain.lower().split('.')[0] if '.' in domain else domain.lower()

    for brand in BRAND_NAMES:
        if len(brand) < 4:
            continue
        if brand in domain_base and domain not in KNOWN_BRANDS:
            findings.append(Finding(
                rule_id="SENDER_BRAND_IMPERSONATION",
                category=Category.SENDER,
                severity=Severity.HIGH.value,
                points=15,
                message=f"Domain '{domain}' contains brand name '{brand}' but is not an official domain.",
                evidence=domain,
                explanation=(
                    f"The sender domain '{domain}' contains the brand name '{brand}' "
                    f"but is not an official {brand} domain. This is a strong indicator "
                    f"of brand impersonation."
                ),
                source="Local domain analysis",
            ))
            break

    return findings


class SenderAnalyzer:
    """Analyzes sender information for phishing indicators."""

    def analyze(self, sender_email: str, sender_name: str,
                sender_domain: str, reply_to: str = "",
                return_path: str = "") -> list[Finding]:
        """
        Perform sender analysis and return list of findings.
        """
        findings = []

        if not sender_email or not sender_domain:
            findings.append(Finding(
                rule_id="SENDER_MISSING",
                category=Category.SENDER,
                severity=Severity.MEDIUM.value,
                points=5,
                message="Sender email address is missing or could not be parsed.",
                evidence=f"Name: {sender_name}, Email: {sender_email}",
                explanation=(
                    "The email could not be properly parsed to extract a sender address. "
                    "This may indicate a malformed or intentionally obfuscated email."
                ),
                source="Local analysis",
            ))
            return findings

        domain = sender_domain.lower().strip()

        # 1. Check for display name vs sender mismatch
        if sender_name and sender_email:
            name_lower = sender_name.lower()
            for brand in BRAND_NAMES:
                if brand in name_lower and brand not in domain:
                    findings.append(Finding(
                        rule_id="SENDER_NAME_DOMAIN_MISMATCH",
                        category=Category.SENDER,
                        severity=Severity.HIGH.value,
                        points=15,
                        message=f"Display name references '{brand}' but sender domain is '{domain}'.",
                        evidence=f"Name: {sender_name}, Domain: {domain}",
                        explanation=(
                            f"The display name '{sender_name}' references '{brand}', "
                            f"but the sender domain '{domain}' is not associated with {brand}. "
                            f"This is a common impersonation technique."
                        ),
                        source="Local analysis",
                    ))
                    break

        # 2. Check for character substitutions in domain
        substitutions = detect_character_substitutions(domain)
        if substitutions:
            findings.append(Finding(
                rule_id="SENDER_HOMOGLYPH",
                category=Category.SENDER,
                severity=Severity.HIGH.value,
                points=12,
                message="Domain contains potentially substituted characters (homoglyphs).",
                evidence=f"Domain: {domain}. {'; '.join(substitutions)}",
                explanation=(
                    "The domain uses character substitution (homoglyphs) where digits "
                    "resemble letters. This technique is used to create domains that "
                    "appear visually similar to legitimate brands."
                ),
                source="Local domain analysis",
            ))

        # 3. Check for lookalike domains using similarity
        for known_domain in KNOWN_BRANDS:
            known_name = known_domain.split('.')[0]
            if known_name in domain and domain != known_domain:
                ratio = similarity_ratio(domain, known_domain)
                if 0.5 < ratio < 1.0:
                    findings.append(Finding(
                        rule_id="SENDER_LOOKALIKE_DOMAIN",
                        category=Category.SENDER,
                        severity=Severity.HIGH.value,
                        points=15,
                        message=f"Domain '{domain}' closely resembles known brand '{known_domain}' (similarity: {ratio:.0%}).",
                        evidence=f"Domain: {domain}, Target: {known_domain}",
                        explanation=(
                            f"The sender domain '{domain}' closely resembles the legitimate "
                            f"domain '{known_domain}'. This could be a typosquatting attack "
                            f"designed to trick recipients."
                        ),
                        source="Local domain analysis",
                    ))
                    break

        # 4. Brand impersonation check
        findings.extend(check_brand_impersonation(domain))

        # 5. Suspicious domain patterns
        suspicious_patterns = [
            (r'\d{4,}', "Domain contains many consecutive digits"),
            (r'-{2,}', "Domain contains consecutive hyphens"),
            (r'^[\d-]+', "Domain starts with digits or hyphens"),
            (r'\.(xyz|top|club|buzz|tk|ml|ga|cf|gq|pw|click|link)$', "Domain uses suspicious TLD"),
        ]

        for pattern, message in suspicious_patterns:
            if re.search(pattern, domain):
                findings.append(Finding(
                    rule_id="SENDER_SUSPICIOUS_DOMAIN",
                    category=Category.SENDER,
                    severity=Severity.MEDIUM.value,
                    points=8,
                    message=message,
                    evidence=f"Domain: {domain}",
                    explanation=f"Domain pattern analysis: {message}.",
                    source="Local domain analysis",
                ))

        # 6. Free email provider check (informational)
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com"]
        if domain in free_providers:
            # Informational — not necessarily suspicious
            pass

        # 7. From/Reply-To mismatch (strip angle brackets before comparing)
        if reply_to:
            reply_domain = reply_to.split('@')[-1].lower().strip() if '@' in reply_to else ""
            reply_domain = reply_domain.strip().strip('<>').strip().rstrip('.')
            if reply_domain and reply_domain != domain:
                findings.append(Finding(
                    rule_id="SENDER_REPLY_TO_MISMATCH",
                    category=Category.SENDER,
                    severity=Severity.MEDIUM.value,
                    points=8,
                    message=f"Reply-To domain '{reply_domain}' differs from sender domain '{domain}'.",
                    evidence=f"From: {sender_email}, Reply-To: {reply_to}",
                    explanation=(
                        f"The Reply-To address uses a different domain ('{reply_domain}') "
                        f"than the From address ('{domain}'). Replies would go to the "
                        f"Reply-To address, potentially diverting them to an attacker."
                    ),
                    source="Local analysis",
                ))

        # 8. Return-Path mismatch (strip angle brackets and trailing punctuation
        #    before comparing — '<user@domain.com>' must equal 'domain.com')
        if return_path:
            return_domain = return_path.split('@')[-1].lower().strip() if '@' in return_path else ""
            return_domain = return_domain.strip().strip('<>').strip().rstrip('.')
            if return_domain and return_domain != domain:
                findings.append(Finding(
                    rule_id="SENDER_RETURN_PATH_MISMATCH",
                    category=Category.SENDER,
                    severity=Severity.LOW.value,
                    points=4,
                    message=f"Return-Path domain '{return_domain}' differs from sender domain '{domain}'.",
                    evidence=f"From: {sender_email}, Return-Path: {return_path}",
                    explanation=(
                        f"The Return-Path envelope sender uses a different domain than "
                        f"the From address. This may indicate email forwarding or "
                        f"SPF manipulation."
                    ),
                    source="Local analysis",
                ))

        # 9. Business Email Compromise (BEC) signals.
        #     A free mailbox address that claims organisational authority is a
        #     classic BEC pattern — executives' mail domains rarely match
        #     gmail.com/outlook.com, and attackers know display names are
        #     unverified. Body context is checked by the engine (see
        #     engine.analyze → BEC pass) before this finding is kept.
        if domain in FREE_MAIL_PROVIDERS and sender_name:
            name_lower = sender_name.lower()
            if any(term in name_lower for term in _AUTHORITY_TERMS):
                findings.append(Finding(
                    rule_id="SENDER_FREEMAIL_AUTHORITY",
                    category=Category.SENDER,
                    severity=Severity.HIGH.value,
                    points=12,
                    message=(
                        f"Sender claims organisational authority ('{sender_name}') "
                        f"but uses a free mailbox domain '{domain}'."
                    ),
                    evidence=f"Display name: {sender_name}, Address: {sender_email}",
                    explanation=(
                        "The display name claims an authoritative role inside an "
                        "organisation, but the address is a free personal mailbox. "
                        "Legitimate executives and IT/HR departments send from "
                        "company-controlled domains. This mismatch is a hallmark of "
                        "Business Email Compromise (BEC) and CEO-fraud attacks."
                    ),
                    source="Local analysis",
                ))

        return findings
