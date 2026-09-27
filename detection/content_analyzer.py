"""
Email content analysis module.
Detects urgency language, credential requests, social engineering patterns.
Enhanced with full explainability.
"""

import re
import unicodedata
from .rules import Finding, Severity, Category


# F-12: zero-width / invisible formatting characters that are safe to remove
# for security analysis. They are used to smuggle keywords past naive filters
# ("pa\u200bssword") and carry no legitimate meaning in email bodies.
_INVISIBLE_CHARS = (
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # BOM / zero-width no-break space
    "\u00ad",  # soft hyphen
    "\u180e",  # Mongolian vowel separator (legacy invisible)
)

# Common leet-substitutions for credential-vocabulary matching (F-12).
# Bounded by design: only digits/symbols that visually substitute letters
# inside words map back, so "passw0rd" matches while ordinary prose with
# digits ("2024 report") is untouched.
_LEET_FOLD = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "!": "i", "|": "l", "\u00a3": "l", "\u20ac": "e",
})

# F-12/F-11: request semantics — the de-obfuscation fallback only runs when
# the message actually ASKS for something. Mere vocabulary mention ("password
# policy was updated") never becomes a credential-request finding.
_REQUEST_VERB_RE = re.compile(
    r"\b(?:enter|provide|send|confirm|share|submit|give|reveal|supply|"
    r"disclose|verify|validate|update)\b",
    re.IGNORECASE,
)


def normalize_content(text: str) -> str:
    """Produce the ANALYSIS representation of email content (F-12).

    Pipeline (deterministic, bounded, non-destructive to the original):
      1. Unicode NFKC normalization (full-width -> ASCII, ligatures split);
      2. zero-width/invisible formatting characters removed;
      3. whitespace collapsed (no other mutation).

    The ORIGINAL text is preserved for evidence/display; analyzers run on
    this normalized copy only.
    """
    if not text:
        return ""
    # 1. Unicode compatibility normalization.
    normalized = unicodedata.normalize("NFKC", text)
    # 2. Strip invisible formatting characters.
    for ch in _INVISIBLE_CHARS:
        normalized = normalized.replace(ch, "")
    # 3. Collapse whitespace runs.
    normalized = re.sub(r"[ \t\r\n\u00a0]+", " ", normalized)
    return normalized.strip()


def _credential_variants(token: str) -> set[str]:
    """Analysis variants of one whitespace-separated token (F-12).

    Returns the token itself plus bounded de-obfuscation variants:
    - punctuation between letters removed ("p.a.s.s.w.o.r.d" -> "password");
    - leet substitutions folded ("passw0rd" -> "password").
    Only candidate tokens up to a sane keyword length are expanded, keeping
    the cost deterministic and bounded.
    """
    variants = {token.lower()}
    if len(token) > 24:
        return variants  # bounded: not a plausible keyword carrier

    # Punctuation/spacing injected between letters.
    stripped = re.sub(r"[^a-z0-9]+", "", token.lower())
    if stripped != token.lower():
        variants.add(stripped)
        # Also fold leet on the de-punctuated form ("p.a.s.s.w.0.r.d").
        variants.add(stripped.translate(_LEET_FOLD))

    # Direct leet fold ("passw0rd" -> "password").
    leet = token.lower().translate(_LEET_FOLD)
    if leet != token.lower():
        variants.add(leet)
    return variants


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
    # Credential TYPE patterns — unambiguous sensitive-data vocabulary.
    # Singular forms with optional plural 's'. An optional trailing 's' is
    # appended after each keyword (or after the final word of a multi-word
    # pattern) so singular and plural forms both match without duplicate
    # rules.
    #
    # F-11: the bare "account" alternative was REMOVED. "account" alone is
    # ordinary business language ("Your account dashboard has new features",
    # "The account manager will present quarterly results") and produced a
    # flood of CONTENT_CREDENTIAL_REQUEST false positives.
    (r'\b(?:one.?time.?password|otp)s?\b', 6),
    (r'\b(?:verification code|verify(?:ing)? code)s?\b', 5),
    (r'\b(?:pin(?:\s*code)?)s?\b', 5),
    (r'\b(?:banking details|bank details|account number|account numbers|account credentials)s?\b', 6),
    (r'\b(?:social security|ssn|aadhaar)s?\b', 7),
    (r'\b(?:credit card|debit card|card number)s?\b', 6),
    (r'\b(?:cvv|cvc|security code)\b', 6),
]

# F-12/F-11: bare credential NOUNS — these words alone are ordinary prose
# ("The password policy was updated", "the login page moved"). They only
# indicate a credential REQUEST when paired with request/disclosure semantics
# (checked via _REQUEST_VERB_RE plus these patterns). Compounds with explicit
# sensitive-data semantics ("login details", "login credentials") stay in the
# type list only when they cannot be read as ordinary nouns — "login details"
# requested is covered by the context patterns below.
BARE_NOUN_CREDENTIAL_PATTERNS = [
    (r'\b(?:password|passwd|pwd)s?\b', 5),
    (r'\b(?:credentials|sign.?in details)s?\b', 5),
    (r'\b(?:login credentials|login details|login information)\b', 5),
    # Context-required: "account"/"username" with a request verb.
    (r'\b(?:enter|provide|send|confirm|share|submit|give|reveal)\s+(?:us\s+)?your\s+(?:account\s+)?(?:username|password|credentials|login)s?\b', 6),
    (r'\b(?:enter|provide|send|confirm|share|submit|give|reveal)\s+(?:us\s+)?your\s+account\s+(?:password|details|information|number)s?\b', 6),
    (r'\b(?:verify|validate)\s+your\s+account\s+(?:credentials|details|information)s?\b', 6),
    (r'\b(?:username|user name)\s*(?:and|&|/)\s*password\b', 6),
    (r'\b(?:enter|provide|send|confirm|share|submit|give|reveal)\s+(?:us\s+)?(?:your\s+)?login\b', 5),
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
    # Singular forms with optional plural 's'.
    (r'\b(?:gift card|itunes card|google play card)s?\b', 6),
    (r'\b(?:send money|transfer funds)\b', 7),
    (r'\b(?:inheritance|beneficiary|next of kin)\b', 8),
    (r'\b(?:lottery|lotto|prize winner)\b', 8),
]


class ContentAnalyzer:
    """Analyzes email content for phishing and social engineering indicators."""

    def analyze(self, body_text: str, body_html: str = "") -> list[Finding]:
        """
        Analyze email content and return findings.

        F-12: pattern matching runs on the NORMALIZED analysis representation
        (NFKC + invisible-character removal + whitespace collapse, plus
        bounded de-obfuscation variants for credential vocabulary). The
        original text is preserved for evidence/display; URL and sender
        analysis are entirely separate analyzers and are unaffected.
        """
        findings = []

        # F-12: normalized analysis representation (original never mutated).
        normalized_text = normalize_content(body_text)
        normalized_html = normalize_content(re.sub(r'<[^>]+>', ' ', body_html)) if body_html else ""

        # Combine text and stripped HTML for analysis
        combined_text = normalized_text.lower()
        if normalized_html:
            combined_text = (combined_text + " " + normalized_html.lower()).strip()

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
        #
        # F-12 + F-11 semantics, two pattern tiers:
        #   Tier 1 (CREDENTIAL_PATTERNS): unambiguous sensitive-data TYPES
        #   (OTP, account number, credit card, CVV, SSN, banking details...) —
        #   count whenever present.
        #   Tier 2 (BARE_NOUN_CREDENTIAL_PATTERNS): bare credential nouns
        #   ("password", "credentials") and request-verb context patterns —
        #   only count when the message actually carries REQUEST semantics
        #   (_REQUEST_VERB_RE). "The password policy was updated" stays benign;
        #   "Please enter your password" is detected.
        #   Pass 2 (only when both tiers found nothing AND a request verb is
        #   present): bounded de-obfuscation — token variants (punctuation-
        #   collapsed, leet-folded) and joined single-letter runs are matched
        #   against the core credential vocabulary, so obfuscated requests
        #   ("enter your p.a.s.s.w.o.r.d", "passw0rd", zero-width-split words)
        #   stay detectable.
        credential_score = 0
        credential_evidence = []
        for pattern, weight in CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                credential_score += weight
                credential_evidence.extend(matches[:2])
                matched_groups.add("CREDENTIALS")

        has_request_semantics = bool(_REQUEST_VERB_RE.search(combined_text))
        if has_request_semantics:
            for pattern, weight in BARE_NOUN_CREDENTIAL_PATTERNS:
                matches = re.findall(pattern, combined_text, re.IGNORECASE)
                if matches:
                    credential_score += weight
                    credential_evidence.extend(matches[:2])
                    matched_groups.add("CREDENTIALS")

        if credential_score == 0 and has_request_semantics:
            core_vocab = (
                "password", "passwd", "passw0rd", "otp", "username",
                "credentials", "credential", "login", "logins",
                "verification code", "one time password", "pin code",
                "security code", "credit card", "banking details",
                "social security", "cvv", "cvc",
            )
            tokens = combined_text.split()
            for raw_token in tokens:
                for variant in _credential_variants(raw_token):
                    if variant in core_vocab:
                        credential_score = 5
                        credential_evidence.append(raw_token)
                        matched_groups.add("CREDENTIALS")
                        break
                if credential_score:
                    break

            # F-12 (spaced-letter obfuscation): "p a s s w o r d" splits into
            # single-letter tokens that no per-token variant can match. Join
            # bounded runs of single-character tokens and re-check the
            # vocabulary. A trailing token like "d." (letter + punctuation)
            # is stripped of its punctuation so sentence-final runs match.
            # Runs of 8+ single letters in ordinary prose are vanishingly
            # rare, so this stays high-precision.
            if credential_score == 0:
                def _run_core(tokens_, start_):
                    """Joined letters of the single-char run starting at start_."""
                    j = start_
                    parts = []
                    while j < len(tokens_):
                        tok = tokens_[j]
                        if len(tok) == 1 and tok.isalpha():
                            parts.append(tok)
                        elif (
                            len(tok) == 2 and tok[0].isalpha()
                            and not tok[1].isalpha() and parts
                        ):
                            parts.append(tok[0])  # sentence-final "d."
                            j += 1
                            break
                        else:
                            break
                        j += 1
                    return "".join(parts), j

                i = 0
                n_tokens = len(tokens)
                while i < n_tokens and not credential_score:
                    if len(tokens[i]) == 1 and tokens[i].isalpha():
                        joined, next_i = _run_core(tokens, i)
                        for variant in _credential_variants(joined):
                            if variant in core_vocab:
                                credential_score = 5
                                credential_evidence.append(" ".join(tokens[i:next_i]))
                                matched_groups.add("CREDENTIALS")
                                break
                        i = next_i
                    else:
                        i += 1

        if credential_score > 0:
            credential_score = min(credential_score, 10)
            findings.append(Finding(
                rule_id="CONTENT_CREDENTIAL_REQUEST",
                category=Category.CONTENT,
                severity=Severity.HIGH.value if credential_score >= 5 else Severity.MEDIUM.value,
                points=credential_score,
                message="Email requests sensitive credential or personal information.",
                evidence=f"Detected: {', '.join(sorted(set(credential_evidence)))}",
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
