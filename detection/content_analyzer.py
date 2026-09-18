"""
Email content analysis module.
Detects urgency language, credential requests, social engineering patterns.
Enhanced with full explainability.
"""

import re
from .rules import Finding, Severity, Category


# Pattern groups with weights
URGENCY_PATTERNS = [
    (r'\b(?:act now|act immediately)\b', 4),
    (r'\b(?:immediate(?:ly)?|urgent|urgently)\b', 3),
    (r'\b(?:within 24 hours|within 48 hours|within \d+ hours)\b', 3),
    (r'\b(?:final warning|last chance|last notice)\b', 4),
    (r'\b(?:expires? today|expir(?:es?|ing) (?:soon|today|tonight))\b', 3),
    (r'\b(?:time.?sensitive|time.?critical)\b', 2),
    (r'\b(?:right away|asap|at once)\b', 2),
    (r'\b(?:don\'?t delay|do not delay)\b', 3),
]

CREDENTIAL_PATTERNS = [
    (r'\b(?:password|passwd|pwd)\b', 5),
    (r'\b(?:one.?time.?password|otp)\b', 6),
    (r'\b(?:verification code|verify(?:ing)? code)\b', 5),
    (r'\b(?:pin(?:\s*code)?)\b', 5),
    (r'\b(?:banking details|bank details|account number)\b', 6),
    (r'\b(?:social security|ssn|aadhaar)\b', 7),
    (r'\b(?:credit card|debit card|card number)\b', 6),
    (r'\b(?:cvv|cvc|security code)\b', 6),
    (r'\b(?:login credentials|login details)\b', 5),
    (r'\b(?:enter your (?:password|credentials|login))\b', 6),
    (r'\b(?:provide your (?:password|credentials))\b', 6),
]

THREAT_PATTERNS = [
    (r'\b(?:account (?:has been |was )?suspend(?:ed)?)\b', 7),
    (r'\b(?:account (?:has been |was )?lock(?:ed)?)\b', 7),
    (r'\b(?:unusual (?:activity|sign.?in|login))\b', 6),
    (r'\b(?:security alert|security warning|security notice)\b', 5),
    (r'\b(?:suspicious (?:activity|sign.?in|login|access))\b', 5),
    (r'\b(?:payment (?:has )?fail(?:ed)?)\b', 6),
    (r'\b(?:legal action|lawsuit|court order)\b', 7),
    (r'\b(?:unauthorized (?:access|transaction|activity))\b', 6),
    (r'\b(?:your account will be (?:closed|terminated|deactivated))\b', 7),
    (r'\b(?:immediate(?:ly)? (?:verify|confirm|update) your)\b', 5),
]

SOCIAL_ENGINEERING_PATTERNS = [
    (r'\b(?:dear (?:customer|user|member|client|sir|madam))\b', 2),
    (r'\b(?:valued customer|loyal customer|preferred member)\b', 3),
    (r'\b(?:click (?:here|below|the link|this link))\b', 3),
    (r'\b(?:tap (?:here|below|the link|this link))\b', 3),
    (r'\b(?:update your (?:account|information|details|payment))\b', 5),
    (r'\b(?:verify your (?:account|identity|email|information))\b', 5),
    (r'\b(?:confirm your (?:account|identity|email|information))\b', 5),
    (r'\b(?:reactivate your (?:account|service))\b', 5),
    (r'\b(?:claim your (?:prize|reward|refund|bonus))\b', 6),
    (r'\b(?:you (?:have )?(?:won|been selected|been chosen))\b', 5),
    (r'\b(?:congratulations? you (?:have )?(?:won|been selected))\b', 6),
]

FINANCIAL_PATTERNS = [
    (r'\b(?:wire transfer|bank transfer)\b', 7),
    (r'\b(?:western union|moneygram)\b', 7),
    (r'\b(?:bitcoin|crypto(?:currency)?)\b', 5),
    (r'\b(?:gift card|itunes card|google play card)\b', 6),
    (r'\b(?:send money|transfer funds)\b', 7),
    (r'\b(?:inheritance|beneficiary|next of kin)\b', 8),
    (r'\b(?:lottery|lotto|prize winner)\b', 8),
]


class ContentAnalyzer:
    """Analyzes email content for phishing and social engineering indicators."""

    def analyze(self, body_text: str, body_html: str = "") -> list[Finding]:
        """
        Analyze email content and return findings.
        """
        findings = []

        # Combine text and stripped HTML for analysis
        combined_text = body_text.lower()
        if body_html:
            clean_html = re.sub(r'<[^>]+>', ' ', body_html).lower()
            combined_text = combined_text + " " + clean_html

        if not combined_text.strip():
            return findings

        # Track which pattern groups matched for combination bonuses
        matched_groups = set()

        # 1. Urgency patterns
        urgency_score = 0
        urgency_evidence = []
        for pattern, weight in URGENCY_PATTERNS:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                urgency_score += weight
                urgency_evidence.extend(matches[:2])
                matched_groups.add("URGENCY")

        if urgency_score > 0:
            urgency_score = min(urgency_score, 8)
            findings.append(Finding(
                rule_id="CONTENT_URGENCY",
                category=Category.CONTENT,
                severity=Severity.MEDIUM.value if urgency_score <= 5 else Severity.HIGH.value,
                points=urgency_score,
                message="Email uses urgency language to pressure immediate action.",
                evidence=f"Detected: {', '.join(set(urgency_evidence))}",
                explanation=(
                    "The email contains language designed to create a sense of urgency, "
                    "pressuring the recipient to act quickly without careful consideration. "
                    "This is a hallmark social engineering technique."
                ),
                source="Content analysis",
            ))

        # 2. Credential request patterns
        credential_score = 0
        credential_evidence = []
        for pattern, weight in CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                credential_score += weight
                credential_evidence.extend(matches[:2])
                matched_groups.add("CREDENTIALS")

        if credential_score > 0:
            credential_score = min(credential_score, 10)
            findings.append(Finding(
                rule_id="CONTENT_CREDENTIAL_REQUEST",
                category=Category.CONTENT,
                severity=Severity.HIGH.value if credential_score >= 5 else Severity.MEDIUM.value,
                points=credential_score,
                message="Email requests sensitive credential or personal information.",
                evidence=f"Detected: {', '.join(set(credential_evidence))}",
                explanation=(
                    "The email asks for sensitive information such as passwords, OTPs, "
                    "PINs, or financial details. Legitimate organizations never request "
                    "this information via email."
                ),
                source="Content analysis",
            ))

        # 3. Threat/social engineering patterns
        threat_score = 0
        threat_evidence = []
        for pattern, weight in THREAT_PATTERNS:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                threat_score += weight
                threat_evidence.extend(matches[:2])
                matched_groups.add("THREAT")

        if threat_score > 0:
            threat_score = min(threat_score, 10)
            findings.append(Finding(
                rule_id="CONTENT_THREAT_LANGUAGE",
                category=Category.CONTENT,
                severity=Severity.HIGH.value if threat_score >= 6 else Severity.MEDIUM.value,
                points=threat_score,
                message="Email uses threatening language to create fear or panic.",
                evidence=f"Detected: {', '.join(set(threat_evidence))}",
                explanation=(
                    "The email uses threatening language (account suspension, legal action, "
                    "unauthorized access) to frighten the recipient into compliance."
                ),
                source="Content analysis",
            ))

        # 4. Social engineering patterns
        se_score = 0
        se_evidence = []
        for pattern, weight in SOCIAL_ENGINEERING_PATTERNS:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                se_score += weight
                se_evidence.extend(matches[:2])
                matched_groups.add("SOCIAL_ENGINEERING")

        if se_score > 0:
            se_score = min(se_score, 8)
            findings.append(Finding(
                rule_id="CONTENT_SOCIAL_ENGINEERING",
                category=Category.CONTENT,
                severity=Severity.MEDIUM.value if se_score <= 5 else Severity.HIGH.value,
                points=se_score,
                message="Email uses social engineering tactics to manipulate the recipient.",
                evidence=f"Detected: {', '.join(set(se_evidence))}",
                explanation=(
                    "The email uses social engineering techniques such as generic greetings, "
                    "emotional manipulation, or false rewards to influence the recipient."
                ),
                source="Content analysis",
            ))

        # 5. Financial scam patterns
        financial_score = 0
        financial_evidence = []
        for pattern, weight in FINANCIAL_PATTERNS:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                financial_score += weight
                financial_evidence.extend(matches[:2])
                matched_groups.add("FINANCIAL")

        if financial_score > 0:
            financial_score = min(financial_score, 8)
            findings.append(Finding(
                rule_id="CONTENT_FINANCIAL_SCAM",
                category=Category.CONTENT,
                severity=Severity.HIGH.value if financial_score >= 6 else Severity.MEDIUM.value,
                points=financial_score,
                message="Email contains financial scam indicators.",
                evidence=f"Detected: {', '.join(set(financial_evidence))}",
                explanation=(
                    "The email contains language associated with financial scams "
                    "(wire transfers, lottery winnings, gift cards, inheritance claims)."
                ),
                source="Content analysis",
            ))

        # 6. Combination bonuses
        if "URGENCY" in matched_groups and "CREDENTIALS" in matched_groups:
            findings.append(Finding(
                rule_id="CONTENT_URGENCY_CREDENTIAL_COMBO",
                category=Category.CONTENT,
                severity=Severity.HIGH.value,
                points=5,
                message="Email combines urgency language with credential requests — strong phishing pattern.",
                evidence="Urgency + credential request combination detected",
                explanation=(
                    "The simultaneous use of urgency pressure and credential requests "
                    "is one of the most common and effective phishing techniques."
                ),
                source="Content analysis",
            ))

        if "THREAT" in matched_groups and "CREDENTIALS" in matched_groups:
            findings.append(Finding(
                rule_id="CONTENT_THREAT_CREDENTIAL_COMBO",
                category=Category.CONTENT,
                severity=Severity.HIGH.value,
                points=5,
                message="Email threatens account action while requesting credentials — strong phishing pattern.",
                evidence="Threat + credential request combination detected",
                explanation=(
                    "The email threatens negative consequences (account suspension, "
                    "closure) while requesting credentials — a high-pressure phishing tactic."
                ),
                source="Content analysis",
            ))

        return findings
