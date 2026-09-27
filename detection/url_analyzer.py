"""
Static URL analysis module.
Analyzes URLs without visiting them (no SSRF risk).
Enhanced with better explainability and evidence tracking.
"""

import re
from urllib.parse import urlparse, parse_qs, unquote
from .rules import Finding, Severity, Category
from difflib import SequenceMatcher


# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bl.ink", "lnkd.in", "rb.gy", "cutt.ly",
    "shorturl.at", "shorte.st", "clk.sh", "tiny.cc", "t.ly",
    "dwz.cn", "bc.vc", "v.gd", "j.mp", "ift.tt",
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".click", ".link", ".online", ".site", ".work", ".icu",
    ".cam", ".rest", ".support", ".racing", ".win", ".bid",
    ".download", ".accountant", ".science", ".cricket",
}

# Known brand domains for URL/domain mismatch detection
KNOWN_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "instagram.com", "netflix.com", "linkedin.com",
    "twitter.com", "github.com", "bankofamerica.com", "chase.com",
    "wellsfargo.com", "citibank.com", "dhl.com", "fedex.com", "ups.com",
    "usps.com", "dropbox.com", "office.com", "outlook.com",
}

# Legitimate regional / official variants (F-2): registrable domains that
# BELONG to a brand and must never be flagged as lookalikes of its canonical
# .com domain merely because the registrable label matches while the TLD
# differs. Subdomains of these ("mail.google.de") resolve via the
# registrable-domain comparison and pass automatically.
REGIONAL_DOMAINS = {
    "google.com": {"google.de", "google.co.uk", "google.co.in", "google.ca",
                   "google.com.au", "google.fr", "google.it", "google.es",
                   "google.nl", "google.pl", "google.com.br", "google.co.jp",
                   "gmail.com", "googlemail.com", "youtube.com", "android.com"},
    "microsoft.com": {"microsoft.de", "microsoft.co.uk", "microsoftonline.com",
                      "microsoft365.com", "office.com", "office365.com",
                      "outlook.com", "live.com", "hotmail.com", "windows.com",
                      "xbox.com", "azure.com"},
    "office.com": {"outlook.office.com", "outlook.office365.com",
                   "microsoftonline.com", "microsoft365.com", "office365.com"},
    "outlook.com": {"outlook.office.com", "outlook.office365.com",
                    "hotmail.com", "live.com"},
    "apple.com": {"apple.co.uk", "apple.de", "icloud.com", "me.com"},
    "amazon.com": {"amazon.de", "amazon.co.uk", "amazon.in", "amazon.ca",
                   "amazon.co.jp", "amazon.fr", "amazon.it", "amazon.es",
                   "amazon.com.au", "amazon.com.br", "amazon.com.mx",
                   "primevideo.com", "amazonaws.com"},
    "paypal.com": {"paypal.de", "paypal.co.uk", "paypal.in", "paypal.fr"},
    "facebook.com": {"facebook.de", "fb.com", "instagram.com", "whatsapp.com"},
    "netflix.com": {"netflix.co.uk", "netflix.in", "netflix.de"},
    "dhl.com": {"dhl.de", "dhl.co.uk", "dhl.co.in", "dhl.fr", "dhl.it"},
    "fedex.com": {"fedex.co.uk", "fedex.in", "fedex.de"},
    "ups.com": {"ups.co.uk", "ups.de"},
    "citibank.com": {"citi.com", "citibank.co.in", "citibank.de"},
    "chase.com": {"chaseonline.com"},
    "github.com": {"github.io"},
    "dropbox.com": {"dropboxusercontent.com"},
    "linkedin.com": {"licdn.com"},
}

# Suspicious URL paths (credential harvesting)
SUSPICIOUS_PATHS = [
    "/login", "/signin", "/verify", "/auth", "/authenticate",
    "/account", "/password", "/credential", "/reset", "/confirm",
    "/secure", "/update", "/banking", "/payment", "/transfer",
    "/download", "/install", "/activate", "/reactivate",
]


def extract_domain_from_url(url: str) -> str:
    """Extract the domain from a URL."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def is_ip_address(domain: str) -> bool:
    """Check if a domain is an IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _registrable_domain(domain: str) -> str:
    """Registrable domain (last two labels, common two-level suffix aware).

    Dependency-free and consistent with detection.sender._split_domain.
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


def _is_official_regional(domain: str) -> bool:
    """True when the registrable domain is a known official brand variant."""
    registrable = _registrable_domain(domain)
    if registrable in KNOWN_DOMAINS:
        return True
    for regional in REGIONAL_DOMAINS.values():
        if registrable in regional:
            return True
    return False


# Distinctive brand tokens checked against DECODED punycode labels (F-4).
# "apple" IS included here despite being excluded from the display-name
# brand sets in Session 2: a NON-ASCII label that decodes to "apple" is
# overwhelmingly a homoglyph attack — legitimate fruit-themed IDN domains
# effectively do not exist, whereas "Apple Valley Plumbing" display names do.
_PUNYCODE_BRAND_STEMS = {
    "google", "gmail", "youtube", "microsoft", "apple", "amazon", "amzn",
    "paypal", "facebook", "instagram", "whatsapp", "netflix",
    "linkedin", "github", "dropbox", "spotify", "dhl", "fedex",
    "usps", "ebay", "wellsfargo", "citibank", "bankofamerica",
    "hdfcbank", "icicibank",
}

# Common Cyrillic/Greek homoglyph codepoints -> Latin equivalents. Mixed and
# full-script homoglyph attacks ("аpple" with Cyrillic а, "аррӏе" all-Cyrillic)
# do not survive Latin-accent folding, so they need explicit folding.
_CONFUSABLE_FOLD = str.maketrans({
    # Cyrillic
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0455': 's', '\u04bb': 'h', '\u0451': 'e', '\u04d1': 'a',
    '\u04cf': 'l',  # palochka (looks like l/I) — used in "аррӏе"
    '\u0454': 'e',  # Ukrainian ye lookalike
    '\u04a1': 'b',  # Cyrillic Komi b
    '\u0501': 'd',
    '\u051b': 'q',
    '\u0408': 'j',
    # Greek
    '\u03b1': 'a', '\u03b5': 'e', '\u03bf': 'o', '\u03c1': 'p',
    '\u03c5': 'y', '\u03c7': 'x', '\u03b9': 'i', '\u03ba': 'k',
    '\u03bd': 'v', '\u03c4': 't',
    # Latin-extended confusables
    '\u0261': 'g',  # script g
    '\u029f': 'l',  # small capital L
    '\u0280': 'r',  # small capital R
})


def decode_punycode_domain(domain: str) -> str | None:
    """Decode an IDNA/punycode domain to its Unicode form (F-4).

    Returns None for domains with no 'xn--' label or when decoding fails —
    malformed punycode must fail SAFELY (no exception escapes, no crash).
    """
    domain = (domain or "").lower().strip().rstrip(".")
    if "xn--" not in domain:
        return None
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError, ValueError, AttributeError):
        return None


def detect_punycode_brand_lookalike(domain: str) -> str | None:
    """Return the brand a decoded punycode label impersonates, if any (F-4).

    Only a MEANINGFUL resemblance to a distinctive brand stem counts — a
    legitimate IDN ("xn--mnchen-3ya.de" = "münchen.de") never matches, and
    malformed punycode fails safely to None. Returns the matched stem.
    """
    decoded = decode_punycode_domain(domain)
    if not decoded:
        return None

    # ASCII-fold tables: accented Latin (ä->a) + homoglyph codepoints
    # (Cyrillic а->a, Greek ο->o, ...).
    _FOLD = str.maketrans(
        "àáâãäåèéêëìíîïòóôõöùúûüñçšž",
        "aaaaaaeeeeiiiiooooouuuuncsz",
    )

    for label in decoded.split("."):
        if not label:
            continue
        # A punycode label matters when the decoded form contains ANY
        # non-ASCII character (mixed-script labels like "аpple" with a
        # Cyrillic 'а' included) — pure-ASCII labels were never punycode.
        if label.isascii():
            continue
        skeleton = label.lower().replace("-", "")
        ascii_folded = (skeleton
                        .translate(_CONFUSABLE_FOLD)
                        .translate(_FOLD))
        for stem in _PUNYCODE_BRAND_STEMS:
            if stem == ascii_folded:
                return stem
            if len(stem) >= 5 and abs(len(stem) - len(ascii_folded)) <= 1:
                from difflib import SequenceMatcher
                if SequenceMatcher(None, ascii_folded, stem).ratio() >= 0.85:
                    return stem
    return None


def check_domain_similarity(url_domain: str, known_domain: str) -> float:
    """Check how similar a URL domain is to a known brand domain (F-2).

    Compares REGISTRABLE names ("google.de" vs "google.com" -> "google" vs
    "google") instead of first DNS labels, so a legitimate regional domain
    scores an exact match against its own brand — and the caller's official-
    variant check then prevents it from ever being flagged.
    """
    url_registrable = _registrable_domain(url_domain)
    known_registrable = _registrable_domain(known_domain)

    url_name = url_registrable.rsplit(".", 1)[0] if "." in url_registrable else url_registrable
    known_name = known_registrable.rsplit(".", 1)[0] if "." in known_registrable else known_registrable

    url_lower = url_name.lower()
    known_lower = known_name.lower()

    # Full registrable-name comparison
    full_ratio = SequenceMatcher(None, url_lower, known_lower).ratio()

    # Without hyphens ("paypa1-secure" ~ "paypal")
    url_clean = url_lower.replace('-', '')
    known_clean = known_lower.replace('-', '')
    clean_ratio = SequenceMatcher(None, url_clean, known_clean).ratio()

    # Token-level comparison: hyphenated lookalikes ("paypai-secure.com")
    # dilute the full-name ratio, but the individual token "paypai" is a
    # near-exact match for the brand "paypal". Compare every hyphen/dot
    # separated token of the candidate against the brand name.
    token_ratio = 0.0
    for token in re.split(r"[\-.]+", url_lower):
        if len(token) >= 4:
            token_ratio = max(
                token_ratio,
                SequenceMatcher(None, token, known_lower).ratio(),
            )

    return max(full_ratio, clean_ratio, token_ratio)


class URLAnalyzer:
    """Analyzes URLs for phishing indicators with full explainability."""

    def analyze(self, urls: list[str], anchor_text: str = "",
                anchors: list[tuple[str, str]] | None = None) -> list[Finding]:
        """
        Analyze a list of URLs and return findings.

        anchor_text: the visible text of the <a> elements that produced these
        URLs (may be empty for plain-text emails with no anchor tags).

        anchors: F-3 — (href, visible_text) pairs extracted from the email
        HTML by the parser. The visible text is the DISPLAYED link content,
        never inferred from the href, so a displayed "https://google.com/..."
        pointing at an unrelated href is detectable end-to-end.
        """
        findings = []
        pairs = self._build_anchor_pairs(urls, anchor_text, anchors)

        for url, visible, href in pairs:
            if not self._visible_matches_href(visible, href):
                findings.append(Finding(
                    rule_id="URL_VISIBLE_LINK_MISMATCH",
                    category=Category.URL,
                    severity=Severity.HIGH.value,
                    # 15 points: a displayed URL pointing elsewhere is one of
                    # the strongest single URL indicators (a deliberate trick,
                    # not an anomaly) — 12 left this attack capable of scoring
                    # SAFE when the URL category contained nothing else.
                    points=15,
                    message=f"Visible link text '{visible[:80]}' points to a different destination than the real href '{href[:80]}'.",
                    evidence=f"Visible: {visible[:100]!r}, Href: {href[:100]!r}, URL: {url[:100]!r}",
                    explanation=(
                        "The link text a user sees (or reads aloud / gets from "
                        "screen readers / sees in search results) resolves to a "
                        "different address than the real href. This is a classic "
                        "phishing/trick-link pattern — the displayed destination "
                        "differs from the actual destination."
                    ),
                    source="Static URL analysis",
                ))

        for url in urls:
            findings.extend(self._analyze_single_url(url))

        # Deduplicate findings by rule_id + evidence
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f.rule_id, f.evidence)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    @staticmethod
    def _normalize_visible_url(text: str) -> str:
        """Normalize visible anchor text for URL-to-URL comparison (F-3).

        Strips surrounding whitespace, removes ALL internal whitespace and
        common separator noise (hyphens are ambiguous in URLs), lowercases,
        and drops an optional trailing slash / punctuation. HTML entities are
        already decoded by the parser (html.parser convert_charrefs).
        """
        t = (text or "").strip().lower()
        t = re.sub(r"\s+", "", t)
        t = t.rstrip("./;-_")
        return t

    @staticmethod
    def _extract_domains(text: str) -> set[str]:
        """Extract registrable-ish domain candidates from arbitrary text."""
        return {
            d.lower().rstrip(".").lstrip(".")
            for d in re.findall(r"(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}",
                                (text or "").lower())
        }

    @staticmethod
    def _visible_matches_href(visible: str, href: str) -> bool:
        """Return True when visible anchor text matches its href.

        F-3 rules:
          - empty/whitespace text (icon links, images, ordinary wording like
            "Reset your password") is NEVER a mismatch — only text that
            itself looks like a URL can disagree with a URL destination;
          - a visible URL matches when the normalized strings agree OR the
            visible text's domains are consistent with the href's domain
            (allowing subdomain/path differences, e.g. displayed
            "google.com/verify" for href "https://mail.google.com/verify");
          - a displayed URL claiming a DIFFERENT domain than the href is a
            mismatch (the trick-link attack).
        """
        if not visible or not visible.strip():
            return True
        if not href:
            return True

        visible_stripped = visible.strip()
        looks_like_url = bool(re.match(
            r"^(?:https?://|www\.)[\w\-._~:/?#\[\]@!$&'()*+,;=%]+$",
            visible_stripped, re.IGNORECASE,
        )) or bool(re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}(?:/\S*)?",
            visible_stripped, re.IGNORECASE,
        ))

        # Ordinary text anchors ("Reset your password") are not URL claims.
        if not looks_like_url:
            return True

        # Same normalized URL?
        if (URLAnalyzer._normalize_visible_url(visible_stripped)
                == URLAnalyzer._normalize_visible_url(href)):
            return True

        # Domain-consistency check: every domain the visible text claims must
        # belong to the href's domain family (same registrable domain or a
        # subdomain of it).
        try:
            href_host = (urlparse(href).hostname or "").lower()
        except Exception:
            href_host = ""
        if not href_host:
            return True

        visible_domains = URLAnalyzer._extract_domains(visible_stripped)
        if not visible_domains:
            return True

        for claimed in visible_domains:
            if (claimed == href_host
                    or href_host.endswith("." + claimed)
                    or claimed.endswith("." + href_host)):
                continue
            # This displayed domain is unrelated to the actual destination.
            return False
        return True

    def _build_anchor_pairs(self, urls: list[str], anchor_text: str = "",
                            anchors: list[tuple[str, str]] | None = None) -> list[tuple[str, str, str]]:
        """Pair each URL with its visible anchor text and real href (F-3).

        Preferred source: ``anchors`` — (href, visible_text) pairs extracted
        from the email HTML by the parser. Only URL-scheme anchors take part
        in the comparison (ordinary links whose visible text is wording are
        never mismatches by definition in _visible_matches_href).

        Fallback (no parser anchors, e.g. legacy callers): a URL from an
        <a href> without captured text is paired with itself — visible==href
        means "no claim to verify", which can never create a false mismatch.
        """
        pairs: list[tuple[str, str, str]] = []

        if anchors:
            normalized_urls = {u.strip() for u in urls}
            for href, visible in anchors:
                href_clean = (href or "").strip()
                if not href_clean:
                    continue
                if href_clean.startswith(("http://", "https://", "mailto:")):
                    # Only compare anchors whose href is actually among the
                    # extracted URLs (mailto anchors carry no URL analysis).
                    if href_clean in normalized_urls or not urls:
                        pairs.append((href_clean, visible or "", href_clean))
            return pairs

        # Legacy fallback: self-paired URLs (no visible text claims).
        for url in urls:
            pairs.append((url, url, url))
        return pairs

    def _analyze_single_url(self, url: str, anchor_text: str = "") -> list[Finding]:
        """Analyze a single URL.

        anchor_text: the visible text of the <a> element that produced this
        URL (e.g. the words between the opening and closing anchor tag).
        Non-empty only for parsed anchor pairs.
        """
        findings = []

        try:
            parsed = urlparse(url)
        except Exception:
            return findings

        domain = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        port = parsed.port

    def _analyze_single_url(self, url: str) -> list[Finding]:
        """Analyze a single URL."""
        findings = []

        try:
            parsed = urlparse(url)
        except Exception:
            return findings

        domain = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        port = parsed.port

        if not domain:
            return findings

        full_path = (path + ("?" + query if query else "")).lower()
        subdomain_count = len(domain.split('.')) - 2  # Subtract domain + TLD

        # 1. HTTP instead of HTTPS
        if scheme == "http":
            findings.append(Finding(
                rule_id="URL_HTTP",
                category=Category.URL,
                severity=Severity.LOW.value,
                points=3,
                message="URL uses HTTP instead of HTTPS — unencrypted connection.",
                evidence=url,
                explanation=(
                    "The URL uses plain HTTP, meaning data is transmitted without encryption. "
                    "While not inherently malicious, this is unusual for legitimate services "
                    "that handle sensitive information."
                ),
                source="Static URL analysis",
            ))

        # 2. IP address URL
        if is_ip_address(domain):
            findings.append(Finding(
                rule_id="URL_IP_ADDRESS",
                category=Category.URL,
                severity=Severity.HIGH.value,
                points=12,
                message="URL uses an IP address instead of a domain name.",
                evidence=url,
                explanation=(
                    "Phishing emails often use IP addresses to bypass domain-based filtering. "
                    "Legitimate services almost always use domain names, not raw IPs."
                ),
                source="Static URL analysis",
            ))

        # 2b. Punycode/IDN homoglyph detection (F-4).
        # Only fires when a DECODED punycode label meaningfully resembles a
        # distinctive brand stem — a legitimate IDN is never flagged merely
        # for being IDN, and malformed punycode fails safely (no finding,
        # no crash).
        punycode_brand = detect_punycode_brand_lookalike(domain)
        if punycode_brand:
            decoded = decode_punycode_domain(domain) or domain
            findings.append(Finding(
                rule_id="URL_PUNYCODE_HOMOGLYPH",
                category=Category.URL,
                severity=Severity.HIGH.value,
                points=12,
                message=(
                    f"URL domain '{domain}' contains punycode that decodes to "
                    f"'{decoded}' resembling the '{punycode_brand}' brand."
                ),
                evidence=f"URL: {url[:100]}, Decoded: {decoded}",
                explanation=(
                    f"The domain uses internationalized (punycode) encoding. When decoded, "
                    f"its label closely resembles the '{punycode_brand}' brand name — a "
                    f"classic homoglyph attack where visually identical Unicode characters "
                    f"substitute Latin letters to impersonate a trusted domain."
                ),
                source="Static URL analysis",
                dedup_key=punycode_brand,
            ))

        # 3. URL shortener
        if domain in URL_SHORTENERS:
            findings.append(Finding(
                rule_id="URL_SHORTENER",
                category=Category.URL,
                severity=Severity.MEDIUM.value,
                points=7,
                message=f"URL uses a shortener service ({domain}) — destination is hidden.",
                evidence=url,
                explanation=(
                    "URL shorteners obscure the true destination. While commonly used for "
                    "legitimate purposes, they are also frequently used in phishing to "
                    "hide malicious destinations."
                ),
                source="Static URL analysis",
            ))

        # 4. Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append(Finding(
                    rule_id="URL_SUSPICIOUS_TLD",
                    category=Category.URL,
                    severity=Severity.MEDIUM.value,
                    points=6,
                    message=f"URL uses a suspicious TLD ({tld}).",
                    evidence=f"Domain: {domain}, TLD: {tld}",
                    explanation=(
                        f"The TLD '{tld}' is commonly associated with phishing and "
                        f"disposable domain registrations."
                    ),
                    source="Static URL analysis",
                ))
                break

        # 5. Excessively long URL
        if len(url) > 200:
            findings.append(Finding(
                rule_id="URL_LONG",
                category=Category.URL,
                severity=Severity.MEDIUM.value,
                points=5,
                message=f"URL is unusually long ({len(url)} characters).",
                evidence=url[:100] + "...",
                explanation=(
                    "Long URLs are commonly used to obscure the actual destination "
                    "or to include tracking parameters that hide the true link."
                ),
                source="Static URL analysis",
            ))

        # 6. Excessive subdomains
        if subdomain_count > 2:
            findings.append(Finding(
                rule_id="URL_EXCESSIVE_SUBDOMAINS",
                category=Category.URL,
                severity=Severity.MEDIUM.value,
                points=6,
                message=f"URL has {subdomain_count + 2} domain levels — may disguise the true domain.",
                evidence=f"Domain: {domain}",
                explanation=(
                    "Multiple subdomains can be used to make a phishing URL appear "
                    "legitimate (e.g., 'secure.login.example.com' looks like it could be real)."
                ),
                source="Static URL analysis",
            ))

        # 7. Suspicious path keywords
        for suspicious_path in SUSPICIOUS_PATHS:
            if suspicious_path in full_path:
                findings.append(Finding(
                    rule_id="URL_SUSPICIOUS_PATH",
                    category=Category.URL,
                    severity=Severity.MEDIUM.value,
                    points=5,
                    message=f"URL path contains '{suspicious_path}' — commonly used in credential harvesting.",
                    evidence=f"URL: {url}",
                    explanation=(
                        f"Path '{suspicious_path}' is associated with login, verification, "
                        f"or account management pages — common targets for credential phishing."
                    ),
                    source="Static URL analysis",
                ))
                break

        # 8. Encoded/obfuscated URL components
        if '%' in url and url != unquote(url):
            decoded = unquote(url)
            if decoded != url:
                findings.append(Finding(
                    rule_id="URL_OBFUSCATED",
                    category=Category.URL,
                    severity=Severity.MEDIUM.value,
                    points=6,
                    message="URL contains encoded characters that may hide the true destination.",
                    evidence=f"Encoded: {url[:80]}, Decoded: {decoded[:80]}",
                    explanation=(
                        "URL encoding can be used to bypass security filters and "
                        "obfuscate the actual URL destination from both users and scanners."
                    ),
                    source="Static URL analysis",
                ))

        # 9. Explicit port
        if port and port not in (80, 443):
            findings.append(Finding(
                rule_id="URL_EXPLICIT_PORT",
                category=Category.URL,
                severity=Severity.MEDIUM.value,
                points=5,
                message=f"URL uses non-standard port ({port}).",
                evidence=f"URL: {url}",
                explanation=(
                    "Phishing URLs sometimes use non-standard ports to bypass "
                    "URL filtering or to reach services on unusual ports."
                ),
                source="Static URL analysis",
            ))

        # 10. Username/password in URL
        if parsed.username or parsed.password:
            findings.append(Finding(
                rule_id="URL_CREDENTIALS_IN_URL",
                category=Category.URL,
                severity=Severity.HIGH.value,
                points=10,
                message="URL contains embedded credentials — strong phishing indicator.",
                evidence=f"URL: {url}",
                explanation=(
                    "Embedding usernames or passwords directly in a URL is a strong "
                    "indicator of a phishing attempt, as legitimate services never "
                    "require credentials in the URL."
                ),
                source="Static URL analysis",
            ))

        # 11. Domain mismatch with known brands (F-2).
        # Registrable-domain-aware: official brand domains, their legitimate
        # subdomains AND their regional variants (google.de, amazon.de,
        # outlook.office.com) are never reported; genuine lookalikes
        # (paypai-secure.com) still are.
        if not _is_official_regional(domain):
            for known_domain in KNOWN_DOMAINS:
                similarity = check_domain_similarity(domain, known_domain)

                if domain != known_domain and similarity > 0.7:
                    findings.append(Finding(
                        rule_id="URL_LOOKALIKE_DOMAIN",
                        category=Category.URL,
                        severity=Severity.HIGH.value,
                        points=12,
                        message=f"URL domain '{domain}' resembles known brand '{known_domain}' (similarity: {similarity:.0%}).",
                        evidence=f"URL domain: {domain}, Known: {known_domain}",
                        explanation=(
                            f"The URL domain '{domain}' closely resembles '{known_domain}' "
                            f"but is not the same domain. This is a common typosquatting "
                            f"technique used in phishing attacks."
                        ),
                        source="Static URL analysis",
                        dedup_key=known_domain.rsplit(".", 1)[0],
                    ))
                    break

        # 12. Suspicious query parameters
        suspicious_params = ['token', 'session', 'sid', 'redirect', 'next', 'continue', 'callback']
        parsed_params = parse_qs(parsed.query)
        for param in suspicious_params:
            if param in parsed_params:
                findings.append(Finding(
                    rule_id="URL_SUSPICIOUS_PARAMS",
                    category=Category.URL,
                    severity=Severity.LOW.value,
                    points=3,
                    message=f"URL contains suspicious parameter '{param}' — may be used for redirect attacks.",
                    evidence=f"URL: {url[:100]}",
                    explanation=(
                        f"Parameter '{param}' can be used in open redirect or "
                        f"session hijacking attacks."
                    ),
                    source="Static URL analysis",
                ))

        return findings
