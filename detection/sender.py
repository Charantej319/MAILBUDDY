"""
Sender and domain analysis module.
Detects lookalike domains, display name mismatches, brand impersonation, etc.
Enhanced with full explainability.
"""

import re
from difflib import SequenceMatcher
from .rules import Finding, Severity, Category
from .intelligence.domain_intelligence import DISTINCTIVE_NAME_BRANDS
from typing import Optional


def similarity_ratio(s1: str, s2: str) -> float:
    """Calculate string similarity ratio."""
    return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()


# Known brand domains for impersonation detection.
# Maps each brand to its OFFICIAL domains (registrable domains + known
# regional/regional-ccTLD variants). A domain is "official" when its
# registrable domain (see _split_domain) is in this set — which transparently
# covers legitimate subdomains (mail.google.com) without any allowlist of
# subdomains.
BRAND_DOMAINS = {
    "google": {"google.com", "google.co.uk", "google.co.in", "google.de",
               "google.ca", "google.com.au", "gmail.com", "googlemail.com",
               "youtube.com", "android.com"},
    "microsoft": {"microsoft.com", "microsoft.co.uk", "microsoftonline.com",
                  "microsoft365.com", "office.com", "office365.com",
                  "outlook.com", "live.com", "hotmail.com", "windows.com",
                  "xbox.com", "azure.com", "teams.microsoft.com"},
    "apple": {"apple.com", "apple.co.uk", "icloud.com", "me.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in", "amazon.de",
               "amazon.ca", "amazon.co.jp", "amazon.com.au", "aws.amazon.com",
               "amazonaws.com", "primevideo.com"},
    "paypal": {"paypal.com", "paypal.co.uk", "paypal.de", "paypal.in"},
    "facebook": {"facebook.com", "fb.com", "instagram.com", "whatsapp.com"},
    "netflix": {"netflix.com", "netflix.co.uk", "netflix.in"},
    "linkedin": {"linkedin.com", "licdn.com"},
    "twitter": {"twitter.com", "x.com"},
    "github": {"github.com", "github.io"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com"},
    "spotify": {"spotify.com", "spotify.co.uk"},
    "dhl": {"dhl.com", "dhl.de", "dhl.co.in", "dhl.co.uk"},
    "fedex": {"fedex.com", "fedex.co.uk", "fedex.in"},
    "ups": {"ups.com", "ups.co.uk"},
    "usps": {"usps.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.in", "ebay.de"},
    "wellsfargo": {"wellsfargo.com"},
    "citibank": {"citibank.com", "citi.com", "citibank.co.in"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "hdfcbank": {"hdfcbank.com", "hdfcbank.net"},
    "icicibank": {"icicibank.com"},
    "chase": {"chase.com", "chaseonline.com"},
    "zoom": {"zoom.us", "zoom.com"},
    "slack": {"slack.com"},
}

# All official registrable domains flattened (kept as a set for O(1) checks
# and backward compatibility with previous API).
KNOWN_BRANDS = {d for domains in BRAND_DOMAINS.values() for d in domains}

# Decisional brand stems for impersonation/homoglyph targeting.
# DELIBERATELY EXCLUDES generic words that legitimately appear in countless
# company names ("bank", "target", "secure", "verify", "account", "login",
# "auth", "visa", "office", "outlook", "apple"-the-fruit risk, etc.):
# a brand stem must be a distinctive token — it should essentially only
# appear in a domain because someone is talking about that brand.
BRAND_STEMS = {
    "google": "Google",
    "gmail": "Gmail",
    "youtube": "YouTube",
    "microsoft": "Microsoft",
    "msn": "Microsoft",
    "appleid": "Apple",
    "icloud": "Apple",
    "amazon": "Amazon",
    "amzn": "Amazon",
    "paypal": "PayPal",
    "paypa1": "PayPal",
    "facebook": "Facebook",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
    "netflix": "Netflix",
    "linkedin": "LinkedIn",
    "twitter": "Twitter",
    "github": "GitHub",
    "dropbox": "Dropbox",
    "spotify": "Spotify",
    "dhl": "DHL",
    "fedex": "FedEx",
    "usps": "USPS",
    "ebay": "eBay",
    "wellsfargo": "Wells Fargo",
    "citibank": "Citibank",
    "bankofamerica": "Bank of America",
    "hdfcbank": "HDFC Bank",
    "icicibank": "ICICI Bank",
    "chase": "Chase",
    "zoom": "Zoom",
    "slack": "Slack",
}

# Free/personal mailbox providers used by the sender analysis below.
FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "protonmail.com", "proton.me", "icloud.com",
    "mail.com", "gmx.com", "yandex.com", "zoho.com",
}

# Display-name / content terms that indicate claimed organisational authority.
# F-8: matching is done on WORD BOUNDARIES via _authority_term_pattern(), not
# naive substring 'in'. Two past bugs are fixed here:
#   1. The original tuple was missing a comma after "vp ", concatenating it
#      with "manager" into the literal "vp manager" — "VP" or "Manager" alone
#      never claimed authority (BEC blind spot).
#   2. Naive substring matching also needed the entries padded with spaces,
#      which failed when the term touches the name edge or punctuation
#      ("John VP", "VP, Finance").
_AUTHORITY_TERMS = (
    "ceo", "cfo", "cto", "coo", "chief", "president", "director",
    "vp", "vice president", "manager", "head of", "founder", "owner",
    "principal", "hr department", "human resources",
    "it department", "it support", "admin", "administrator",
    "system administrator",
)

# Phishing-relevant actions that make claimed authority dangerous when the
# address is a freemail account (classic BEC pattern).
_BEC_ACTION_TERMS = (
    "wire transfer", "wire", "transfer", "payment", "invoice", "bank",
    "gift card", "credentials", "password", "payroll", "tax",
    "urgent", "confidential", "verify", "confirm", "account number",
    "routing", "iban", "swift",
)


def _authority_term_pattern(terms=_AUTHORITY_TERMS) -> re.Pattern:
    """F-8: ONE precompiled regex matching any authority term on word
    boundaries, so every variant ('VP', 'Vice President', 'Manager', 'CEO')
    is recognized regardless of case, position, or adjacent punctuation.

    The alternation is ordered longest-first so 'vice president' is preferred
    over the overlapping shorter terms inside it.
    """
    alternatives = sorted((re.escape(t) for t in terms), key=len, reverse=True)
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(alternatives) + r")(?![a-z0-9])", re.IGNORECASE)


_AUTHORITY_TERM_RE = _authority_term_pattern()


def display_name_claims_authority(sender_name: str) -> bool:
    """True when the display name claims organisational authority (F-8).

    Word-boundary aware: 'Operations Manager' and 'VP' match; 'managerial
    economics course' does not ('manager' is not a standalone word there).
    """
    if not sender_name:
        return False
    return bool(_AUTHORITY_TERM_RE.search(sender_name))

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


def _split_domain(domain: str) -> tuple[str, str, str]:
    """Split a domain into (subdomain_label, registrable_domain, tld).

    Uses a lightweight two-label heuristic: the registrable domain is the
    last two labels ("mail.google.com" -> ("mail", "google.com", "com")),
    except for well-known second-level suffixes ("co.uk", "com.au", "co.in",
    "co.jp", "com.br", "org.uk", "gov.uk", "ac.uk", "net.au"), where the
    last three labels form the registrable domain ("bbc.co.uk" ->
    ("", "bbc.co.uk", "co.uk")). This is sufficient for brand checks and
    deliberately avoids external dependencies.
    """
    domain = (domain or "").lower().strip().rstrip(".")
    if not domain:
        return "", "", ""
    labels = domain.split(".")
    if len(labels) < 2:
        return "", domain, ""
    two_level_suffixes = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in",
        "com.br", "co.jp", "co.za", "com.mx", "co.nz", "co.kr",
    }
    if len(labels) >= 3 and ".".join(labels[-2:]) in two_level_suffixes:
        registrable = ".".join(labels[-3:])
        tld = ".".join(labels[-2:])
        rest = labels[:-3]
    else:
        registrable = ".".join(labels[-2:])
        tld = labels[-1]
        rest = labels[:-2]
    subdomain_label = rest[-1] if rest else ""
    return subdomain_label, registrable, tld


def _registrable_domain(domain: str) -> str:
    """Return the registrable domain (last two labels, suffix-aware)."""
    return _split_domain(domain)[1]


def is_official_brand_domain(domain: str) -> tuple[Optional[str], str]:
    """Return (brand, official_domain) when `domain` belongs to a brand by its
    REGISTRABLE domain — i.e. exact domains and their legitimate subdomains
    ("mail.google.com", "s3.amazonaws.com") are official; unrelated domains
    sharing one label are not.
    """
    registrable = _registrable_domain(domain)
    for brand, domains in BRAND_DOMAINS.items():
        if registrable in domains:
            return brand, registrable
    return None, ""


def _domain_similarity(a: str, b: str) -> float:
    """Similarity between two registrable domains, fall back to full compare."""
    ra, rb = _registrable_domain(a), _registrable_domain(b)
    return SequenceMatcher(None, ra, rb).ratio()


def _strip_skeleton(domain: str) -> str:
    """Reduce a registrable domain to a comparable skeleton: registrable
    domain without its TLD, hyphens/dots removed and digits stripped.

    The skeleton is what the human eye effectively compares against a brand
    ("micr0soft-support.example" -> "micr0softsupport" vs "microsoft"),
    which makes digit-substitution attacks measurable without flagging every
    domain that happens to contain a digit ("office365", "s3").
    """
    registrable = _registrable_domain(domain)
    name = registrable.rsplit(".", 1)[0]
    name = name.replace("-", "").replace(".", "")
    return name.translate(str.maketrans("", "", "0123456789"))


# Distinctive brand tokens for skeleton comparison. Same rationale as
# BRAND_STEMS: generic words ("bank", "office", "secure") must not participate.
_SKELETON_BRANDS = {
    "google": "google.com", "gmail": "gmail.com", "youtube": "youtube.com",
    "microsoft": "microsoft.com", "msn": "microsoft.com",
    "amazon": "amazon.com", "amzn": "amazon.com",
    "paypal": "paypal.com", "facebook": "facebook.com",
    "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "netflix": "netflix.com", "linkedin": "linkedin.com",
    "github": "github.com", "dropbox": "dropbox.com",
    "spotify": "spotify.com", "dhl": "dhl.com", "fedex": "fedex.com",
    "usps": "usps.com", "ebay": "ebay.com",
    "wellsfargo": "wellsfargo.com", "citibank": "citibank.com",
    "bankofamerica": "bankofamerica.com", "hdfcbank": "hdfcbank.com",
    "icicibank": "icicibank.com",
}


def detect_character_substitutions(domain: str, brand_context: Optional[str] = None) -> list[str]:
    """Detect homoglyph character substitutions that impersonate a brand.

    Context-aware: digits alone are meaningless — "office365.com" and
    "s3.amazonaws.com" contain digits legitimately. A substitution is only
    reported when normalising digits to letters (and vice versa) produces a
    token that is *meaningfully similar to a known brand*:

      - digit->letter substitution landing on a brand stem or on a similar
        token of an official brand name ("micr0soft" -> "microsoft"), or
      - letter->digit substitution of a brand stem ("paypa1" ~ "paypal"), or
      - a skeleton ratio >= 0.75 against the brand token when the domain also
        mentions the brand (e.g. "microsoft-0nline").

    This keeps realistic attacks detectable
    ("micr0soft-support.example", "paypa1-login.example",
    "microsoft-0nline.com") while never flagging digit-bearing legitimate
    domains ("office365.com", "microsoft365.com", "s3.amazonaws.com").
    """
    domain = (domain or "").lower().strip()
    if not domain:
        return []

    # The legitimate registrable domain (if any) is not evidence of attack.
    brand, official = is_official_brand_domain(domain)
    if brand:
        return []

    registrable = _registrable_domain(domain)
    name = registrable.rsplit(".", 1)[0]
    tokens = set(re.split(r"[\-.]+", name)) - {""}
    skeleton = _strip_skeleton(domain)

    # Brand tokens to compare against: the brand that owns any official
    # reference found in the domain, plus all distinctive stems when nothing
    # specific is mentioned (so "micr0soft-support" still resolves).
    candidate_brands: set[str] = set()
    for stem, display in BRAND_STEMS.items():
        if stem in name:
            candidate_brands.add(display)
    if not candidate_brands:
        candidate_brands = set(_SKELETON_BRANDS.keys())

    # Official brand tokens (from the official domain names themselves).
    official_tokens: dict[str, set[str]] = {}
    for b in candidate_brands:
        for official_domain in BRAND_DOMAINS.get(_display_to_key(b), set()):
            official_tokens.setdefault(b, set()).update(
                set(re.split(r"[\-.]", official_domain.rsplit(".", 1)[0])) - {""}
            )

    digit_to_letter = str.maketrans("0123456789", "olehsb6789")
    substitutions = []
    for token in tokens:
        if not token:
            continue
        has_digit = any(c.isdigit() for c in token)
        # 1) Letter->digit: token LOOKS like a digit-substituted brand stem
        #    ("paypa1" -> skeleton "paypa" vs "paypal").
        token_skeleton = token.translate(str.maketrans("", "", "0123456789"))
        for stem, display in BRAND_STEMS.items():
            if token == stem:
                continue  # exact stem mention is brand-impersonation's job
            if token_skeleton == stem and token != stem:
                substitutions.append(
                    f"'{token}' appears to substitute characters in '{display}' brand name"
                )
                break
        if substitutions:
            break
        if not has_digit:
            continue
        # 2) Digit->letter: normalising digits to letters produces a brand
        #    token ("micr0soft" -> "microsoft", "microsoft-0nline" ->
        #    "microsoftonline").
        decoded = token.translate(digit_to_letter)
        decoded_skeleton = decoded.translate(str.maketrans("", "", "0123456789"))
        decoded_skeleton = decoded.translate(str.maketrans("", "", "0123456789"))
        matched_brand = None
        matched_target = None
        for b, toks in official_tokens.items():
            for ot in toks:
                if decoded == ot or decoded_skeleton == ot:
                    matched_brand, matched_target = b, ot
                    break
                # Length guard: digit substitution REPLACES characters, it
                # does not add them. Without this guard digit noise inflates
                # the ratio ("office365" -> "officehs" ~ "office" = 0.86)
                # and legitimate product domains get flagged.
                if abs(len(decoded_skeleton) - len(ot)) > 1:
                    continue
                r = SequenceMatcher(None, decoded_skeleton, ot).ratio()
                if r >= 0.75:
                    matched_brand, matched_target = b, ot
                    break
            if matched_brand:
                break
        if matched_brand:
            substitutions.append(
                f"'{token}' normalises to '{matched_target}' of brand {matched_brand}"
            )
            break
        # No brand token matched.
        # 3) Letters that were substituted for digits are only significant
        #    if they resolve to a brand name (e.g. "micr0soft" ->
        #    "microsoft" or "paypa1" -> "paypal"). Generic letter tokens are
        #    not evidence of substitution.
        if not has_digit and token_skeleton:
            for stem, display in BRAND_STEMS.items():
                if token_skeleton == stem and token != stem:
                    substitutions.append(
                        f"'{token}' appears to substitute characters in '{display}' brand name"
                    )
                    break
            else:
                continue
            break

    return substitutions[:2]

def _is_legit_domain_with_digits(domain: str) -> bool:
    """Return True when a digit-bearing domain is legitimate.
    
    This is intentionally conservative: any digit in the domain is only
    treated as suspicious when the token that carries the digit resolves to a
    *brand name* after digit stripping. Ordinary substance domains such as
    office365.com / microsoft365.com / s3.amazonaws.com are legitimate.
    """
    registrable = _registrable_domain(domain)
    name = registrable.rsplit('.', 1)[0]
    tokens = set(re.split(r'[\-.]+', name)) - {''}
    digit_to_letter = str.maketrans('0123456789', 'olehsb')
    for token in tokens:
        if not token or not any(c.isdigit() for c in token):
            continue
        decoded = token.translate(digit_to_letter)
        decoded_skeleton = decoded.translate(str.maketrans('', '', '0123456789'))
        for stem, display in BRAND_STEMS.items():
            if decoded_skeleton == stem or decoded == stem:
                return False
        if token.translate(str.maketrans('', '', '0123456789')) in _SKELETON_BRANDS:
            return False
        if any(stem in decoded_skeleton for stem in _SKELETON_BRANDS):
            return False
    return False


def _display_to_key(display: str) -> str:
    """Map a brand display name back to its BRAND_DOMAINS key."""
    return display.lower().replace(" ", "")


def check_brand_impersonation(domain: str) -> list[Finding]:
    """Check if a domain impersonates a known brand (registrable-domain-aware).

    Rules (all checks run against the REGISTRABLE domain, i.e. the last
    two labels, so legitimate subdomains and legitimate regional/generic
    TLDs are never flagged):
      - exact official domains and their legitimate subdomains are never
        impersonation ("amazon.in", "mail.google.com", "s3.amazonaws.com"
        all pass);
      - a distinctive brand stem (e.g. "paypal", "amazon", "hdfcbank") only
        triggers when it appears in the REGISTRABLE part of a NON-official
        domain ("dhl.example" -> DHL; "amazon-support.co.uk" is fine because
        "amazon.co.uk" is an official Amazon domain). Brand tokens found
        only in the SUBDOMAIN chain ("google.docs.share.example") are not
        standalone impersonation evidence — arbitrary subdomains are not
        independent brand identities;
      - generic words ("bank", "target", "secure", "auth", "office", "visa")
        are not brand stems and never trigger on their own;
      - AT MOST ONE brand-impersonation finding per domain (F-1): multiple
        matching stems are consolidated into a single finding whose evidence
        lists every implicated brand;
      - display names are not considered here at all.

    Every finding carries ``dedup_key`` = the canonical brand key so the
    scorer can collapse duplicate brand findings from other analyzers
    (INTEL_BRAND_IMPERSONATION / *_LOOKALIKE_DOMAIN) describing the same
    domain↔brand relationship.
    """
    findings = []

    domain = (domain or "").lower().strip().rstrip(".")
    if not domain:
        return findings

    # Official domains (incl. subdomains and regional TLDs) can never
    # impersonate a brand.
    if is_official_brand_domain(domain)[0]:
        return findings

    registrable = _registrable_domain(domain)
    base = registrable.rsplit(".", 1)[0]

    matched_brands: list[tuple[str, str]] = []  # (stem, display)

    # Phase 1 — distinctive brand stem inside the REGISTRABLE name.
    for stem, display in BRAND_STEMS.items():
        if stem in base:
            matched_brands.append((stem, display))

    # Phase 2 — token-level lookalike (character substitutions such as
    # "paypai" ~ "paypal"). Only runs when phase 1 found nothing, so one
    # domain can never yield two impersonation findings. The 0.75 threshold
    # demands a NEAR match: ordinary short words that happen to share letters
    # with a brand ("share" ~ "chase" = 0.60) must not be flagged.
    if not matched_brands:
        for token in re.split(r"[\-\.]+", base):
            if not token or len(token) < 4:
                continue
            best = None
            for stem, display in BRAND_STEMS.items():
                if len(stem) < 4 or token == stem:
                    continue
                r = SequenceMatcher(None, stem, token).ratio()
                if 0.75 <= r < 1.0 and (best is None or r > best[2]):
                    best = (stem, display, r)
            if best:
                matched_brands.append((best[0], best[1]))
                break  # one lookalike relationship is enough evidence

    if matched_brands:
        # Canonical dedup identity: the brand family key of the FIRST match
        # (all matches share the domain, so one finding per domain is right).
        stem, display = matched_brands[0]
        others = "", ", ".join(sorted({d for _, d in matched_brands[1:]}))
        brand_key = _display_to_key(display)
        extra = (
            f" (also referencing: {others[1]})" if others[1] else ""
        )
        findings.append(Finding(
            rule_id="SENDER_BRAND_IMPERSONATION",
            category=Category.SENDER,
            severity=Severity.HIGH.value,
            points=15,
            message=(f"Domain '{domain}' references the {display} brand but is not "
                     f"an official {display} domain."),
            evidence=domain,
            explanation=(
                f"The sender domain '{domain}' contains the distinctive brand token "
                f"'{stem}' in its registrable domain ({registrable}){extra}, but that "
                f"registrable domain is not an official {display} domain. This is a "
                f"strong indicator of brand impersonation."
            ),
            source="Local domain analysis",
            dedup_key=brand_key,
        ))

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

        # 1. Check for display name vs sender mismatch (F-7).
        # Only DISTINCTIVE brand tokens participate — generic words such as
        # "bank", "secure", "verify", "account", "login", "auth", "office",
        # "outlook" (used by thousands of legitimate companies) must never
        # fire this rule on their own. A distinctive brand word in the name
        # ("PayPal Security Team") whose registrable sender domain does not
        # belong to that brand is meaningful impersonation evidence; a name
        # like "Chase Business Bank" from chase.com is not.
        if sender_name and sender_email:
            name_lower = sender_name.lower()
            matched_name_brands: list[tuple[str, str]] = []
            for token in re.split(r"[^a-z0-9]+", name_lower):
                if not token or len(token) < 4:
                    continue
                display = DISTINCTIVE_NAME_BRANDS.get(token)
                if not display:
                    continue
                # The brand is consistent when the registrable domain itself
                # belongs to the brand ("chase.com" for "Chase ...").
                brand_of_domain = is_official_brand_domain(domain)[0]
                if brand_of_domain == _display_to_key(display):
                    continue  # legitimate brand/domain combination
                if token in domain:
                    continue  # the domain itself references the brand
                matched_name_brands.append((token, display))
            if matched_name_brands:
                token, display = matched_name_brands[0]
                findings.append(Finding(
                    rule_id="SENDER_NAME_DOMAIN_MISMATCH",
                    category=Category.SENDER,
                    severity=Severity.HIGH.value,
                    points=15,
                    message=f"Display name references '{display}' but sender domain is '{domain}'.",
                    evidence=f"Name: {sender_name}, Domain: {domain}",
                    explanation=(
                        f"The display name '{sender_name}' references the distinctive "
                        f"brand token '{token}' ({display}), but the registrable sender "
                        f"domain '{_registrable_domain(domain) or domain}' is not associated "
                        f"with {display}. Impersonating a well-known brand in the display "
                        f"name while sending from an unrelated domain is a common "
                        f"phishing technique."
                    ),
                    source="Local analysis",
                    dedup_key=_display_to_key(display),
                ))

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

        # 3+4. Lookalike and brand-impersonation checks (F-1).
        # Both operate on the REGISTRABLE domain and produce AT MOST ONE
        # sender-level brand finding per domain↔brand relationship:
        #   - brand impersonation (distinctive stem / near-token match in the
        #     registrable name) takes precedence;
        #   - the substring-lookalike check only runs when impersonation did
        #     NOT fire, so "dhl.example" scores once, not twice;
        #   - the lookalike substring search runs against the registrable
        #     domain only — brand tokens appearing solely in the subdomain
        #     chain ("google.docs.share.example") are not evidence.
        if not is_official_brand_domain(domain)[0]:
            brand_findings = check_brand_impersonation(domain)
            findings.extend(brand_findings)

            if not brand_findings:
                registrable = _registrable_domain(domain)
                for known_domain in KNOWN_BRANDS:
                    known_name = known_domain.split('.')[0]
                    if len(known_name) < 3:
                        continue
                    if known_name in registrable and registrable != known_domain:
                        ratio = similarity_ratio(registrable, known_domain)
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
                                dedup_key=known_name,
                            ))
                            break

        # 5. Suspicious domain patterns (F-13).
        # Digits are NOT a standalone strong signal: "7-eleven.com",
        # "office365.com" and year-like domains are legitimate. The digit
        # heuristic only contributes when the digit-bearing domain ALSO
        # normalises to a brand token (digit-substitution attack evidence,
        # see detect_character_substitutions) — pattern hits remain limited
        # to structural anomalies (long digit runs, hyphen abuse, bad TLD).
        suspicious_patterns = [
            (r'\d{5,}', "Domain contains a long digit run"),
            (r'-{2,}', "Domain contains consecutive hyphens"),
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

        # 7. From/Reply-To / Return-Path mismatch — one event per mismatch
        #    (canonical identity + deduplication key below).
        mismatched_domains = []

        if reply_to:
            reply_domain = reply_to.split('@')[-1].lower().strip() if '@' in reply_to else ""
            reply_domain = reply_domain.strip().strip('<>').strip().rstrip('.')
            if reply_domain and reply_domain != domain:
                mismatched_domains.append(('reply_to', reply_domain))

        if return_path:
            return_domain = return_path.split('@')[-1].lower().strip() if '@' in return_path else ""
            return_domain = return_domain.strip().strip('<>').strip().rstrip('.')
            if return_domain and return_domain != domain:
                mismatched_domains.append(('return_path', return_domain))

        # ONE underlying mismatch = ONE scoring contribution.
        #  - Reply-To and Return-Path disagreeing with From AND with each
        #    other describe the same underlying forgery, so we keep the more
        #    informative single finding (Reply-To wins: higher severity, more
        #    evidence).
        #  - Distinct domains among the mismatched headers still generate a
        #    header-level finding for understandable evidence.
        mismatch_domains = {d for _, d in mismatched_domains}
        if mismatch_domains:
            if len(mismatch_domains) == 1:
                # Canonical events: dedupe identical underlying mismatches
                # (REPLY_TO_MISMATCH and RETURN_PATH_MISMATCH) into one
                # scoring finding per distinct underlying domain.
                distinct_mismatch = next(iter(mismatch_domains))
                if not any(f.rule_id in ("SENDER_REPLY_TO_MISMATCH",
                                          "SENDER_RETURN_PATH_MISMATCH")
                           and f.dedup_key == distinct_mismatch
                           for f in findings):
                    findings.append(Finding(
                        rule_id="SENDER_REPLY_TO_MISMATCH",
                        category=Category.SENDER,
                        severity=Severity.MEDIUM.value,
                        points=8,
                        message=f"Reply-To/Return-Path domain '{distinct_mismatch}' differs from sender domain '{domain}'.",
                        evidence=f"From: {sender_email}, Reply-To: {reply_to or ''}, Return-Path: {return_path or ''}",
                        explanation=(
                            f"The envelope/routing addresses ({', '.join(sorted(mismatch_domains))}) "
                            f"do not match the From address ('{domain}'). This can redirect "
                            f"replies or the SPF check and is a sign of email spoofing."
                        ),
                        source="Local analysis",
                        dedup_key=distinct_mismatch,
                    ))
            else:
                # Reply-To and Return-Path disagree with FROM and with each
                # other: still ONE finding, but with evidence covering both.
                mismatch_list = ", ".join(sorted(mismatch_domains))
                if not any(f.rule_id == "SENDER_REPLY_TO_MISMATCH"
                           and f.dedup_key == "mixed"
                           for f in findings):
                    findings.append(Finding(
                        rule_id="SENDER_REPLY_TO_MISMATCH",
                        category=Category.SENDER,
                        severity=Severity.MEDIUM.value,
                        points=8,
                        message=f"Misrouted address(es) differ from sender domain '{domain}'.",
                        evidence=f"From: {sender_email}, Reply-To: {reply_to or ''}, Return-Path: {return_path or ''}",
                        explanation=(
                            f"The routing addresses ({mismatch_list}) do not match the "
                            f"From address ('{domain}'). Reply-To and Return-Path both "
                            f"divert to attacker-controlled domains — a strong spoofing signal."
                        ),
                        source="Local analysis",
                        dedup_key="mixed",
                    ))

        # 9. Business Email Compromise (BEC) signals.
        #     A free mailbox address that claims organisational authority is a
        #     classic BEC pattern — executives' mail domains rarely match
        #     gmail.com/outlook.com, and attackers know display names are
        #     unverified. Body context is checked by the engine (see
        #     engine.analyze → BEC pass) before this finding is kept.
        if domain in FREE_MAIL_PROVIDERS and sender_name:
            if display_name_claims_authority(sender_name):
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
