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


def check_domain_similarity(url_domain: str, known_domain: str) -> float:
    """Check how similar a URL domain is to a known domain."""
    url_name = url_domain.split('.')[0] if '.' in url_domain else url_domain
    known_name = known_domain.split('.')[0] if '.' in known_domain else known_domain

    url_lower = url_name.lower()
    known_lower = known_name.lower()

    # Full base comparison
    full_ratio = SequenceMatcher(None, url_lower, known_lower).ratio()

    # Without hyphens
    url_clean = url_lower.replace('-', '')
    known_clean = known_lower.replace('-', '')
    clean_ratio = SequenceMatcher(None, url_clean, known_clean).ratio()

    # Compare the prefix of the domain to the brand name
    prefix = url_clean[:len(known_clean)]
    prefix_ratio = SequenceMatcher(None, prefix, known_clean).ratio()

    return max(full_ratio, clean_ratio, prefix_ratio)


class URLAnalyzer:
    """Analyzes URLs for phishing indicators with full explainability."""

    def analyze(self, urls: list[str]) -> list[Finding]:
        """
        Analyze a list of URLs and return findings.
        """
        findings = []

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

        # 11. Domain mismatch with known brands
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
