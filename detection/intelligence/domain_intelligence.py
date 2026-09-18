"""
Domain Intelligence Module.
Performs passive, safe lookups to assess sender domain legitimacy.
Does NOT perform intrusive scanning, mailbox verification, or port scanning.
"""

import time
import re
import hashlib
from typing import Optional
from ..rules import Finding, Severity, Category


# Cache for domain intelligence results
_intel_cache: dict[str, dict] = {}
CACHE_TTL = 3600  # 1 hour

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".click", ".link", ".online", ".site", ".work", ".icu",
    ".cam", ".rest", ".support", ".racing", ".win", ".bid",
    ".download", ".accountant", ".science", ".cricket",
    ".zip", ".mov", ".php", ".js", ".exe",
}

# Known brand domains for lookalike detection
KNOWN_BRANDS = {
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "live.com",
    "apple.com", "icloud.com", "amazon.com", "paypal.com",
    "facebook.com", "fb.com", "instagram.com",
    "netflix.com", "linkedin.com", "twitter.com", "x.com",
    "github.com", "dropbox.com", "office.com", "office365.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com",
    "zoom.us", "slack.com", "teams.microsoft.com",
}

# Brand names for impersonation detection
BRAND_NAMES = {
    "google", "microsoft", "apple", "amazon", "paypal", "facebook",
    "netflix", "linkedin", "twitter", "instagram", "github",
    "bank", "secure", "verify", "account", "login", "auth",
    "outlook", "office", "dropbox", "dhl", "fedex", "ups", "usps",
    "chase", "wellsfargo", "citibank", "visa", "mastercard", "amex",
}


def _cache_key(domain: str) -> str:
    return hashlib.md5(domain.lower().strip().encode()).hexdigest()


def _get_cached(domain: str) -> Optional[dict]:
    key = _cache_key(domain)
    entry = _intel_cache.get(key)
    if entry and (time.time() - entry["timestamp"]) < CACHE_TTL:
        return entry["result"]
    return None


def _set_cached(domain: str, result: dict):
    key = _cache_key(domain)
    _intel_cache[key] = {
        "timestamp": time.time(),
        "result": result,
    }


def clear_cache():
    """Clear the intelligence cache."""
    _intel_cache.clear()


class DomainIntelligence:
    """
    Performs passive domain intelligence lookups.
    All lookups are read-only and non-intrusive.
    """

    def analyze(self, domain: str) -> dict:
        """
        Analyze a domain and return intelligence results.
        
        Returns dict with:
            domain, suspicious_tld, lookalike_detected, brand_impersonation,
            domain_indicators, findings
        """
        if not domain:
            return self._empty_result("")

        # Check cache
        cached = _get_cached(domain)
        if cached:
            return cached

        result = {
            "domain": domain,
            "suspicious_tld": False,
            "tld": "",
            "lookalike_detected": False,
            "lookalike_target": "",
            "brand_impersonation": False,
            "impersonated_brand": "",
            "domain_indicators": [],
            "findings": [],
        }

        # 1. Check suspicious TLD
        tld = self._extract_tld(domain)
        result["tld"] = tld
        if tld in SUSPICIOUS_TLDS:
            result["suspicious_tld"] = True
            result["domain_indicators"].append("suspicious_tld")

        # 2. Check for brand impersonation
        brand_result = self._check_brand_impersonation(domain)
        if brand_result:
            result["brand_impersonation"] = True
            result["impersonated_brand"] = brand_result
            result["domain_indicators"].append("brand_impersonation")

        # 3. Check for lookalike domains
        lookalike = self._check_lookalike(domain)
        if lookalike:
            result["lookalike_detected"] = True
            result["lookalike_target"] = lookalike
            result["domain_indicators"].append("lookalike_domain")

        # 4. Check for suspicious patterns
        patterns = self._check_suspicious_patterns(domain)
        result["domain_indicators"].extend(patterns)

        # 5. DNS resolution check (passive)
        dns_result = self._check_dns_resolution(domain)
        result["dns_resolves"] = dns_result
        if not dns_result:
            result["domain_indicators"].append("no_dns_resolution")

        # 6. MX record check (passive)
        mx_result = self._check_mx_records(domain)
        result["has_mx"] = mx_result
        if mx_result:
            result["domain_indicators"].append("has_mx_records")

        # Generate findings
        result["findings"] = self._generate_findings(result)

        _set_cached(domain, result)
        return result

    def _empty_result(self, domain: str) -> dict:
        return {
            "domain": domain,
            "suspicious_tld": False,
            "tld": "",
            "lookalike_detected": False,
            "lookalike_target": "",
            "brand_impersonation": False,
            "impersonated_brand": "",
            "domain_indicators": [],
            "dns_resolves": False,
            "has_mx": False,
            "findings": [],
        }

    def _extract_tld(self, domain: str) -> str:
        """Extract the TLD from a domain."""
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            return "." + parts[-1]
        return ""

    def _check_brand_impersonation(self, domain: str) -> Optional[str]:
        """Check if domain impersonates a known brand."""
        if domain in KNOWN_BRANDS:
            return None  # It IS the legitimate domain

        base = domain.lower().split(".")[0] if "." in domain else domain.lower()
        for brand in BRAND_NAMES:
            if len(brand) < 4:
                continue
            if brand in base and domain not in KNOWN_BRANDS:
                return brand
        return None

    def _check_lookalike(self, domain: str) -> Optional[str]:
        """Check for lookalike domains targeting known brands."""
        from difflib import SequenceMatcher

        base = domain.lower().split(".")[0] if "." in domain else domain.lower()

        for known in KNOWN_BRANDS:
            known_name = known.split(".")[0]
            if known_name in base and domain != known:
                ratio = SequenceMatcher(None, base, known_name).ratio()
                if 0.5 < ratio < 1.0:
                    return known
        return None

    def _check_suspicious_patterns(self, domain: str) -> list[str]:
        """Check for suspicious domain patterns."""
        indicators = []
        
        # Many consecutive digits
        if re.search(r'\d{4,}', domain):
            indicators.append("excessive_digits")
        
        # Consecutive hyphens
        if re.search(r'-{2,}', domain):
            indicators.append("consecutive_hyphens")
        
        # Starts with digits/hyphens
        if re.search(r'^[\d-]+', domain):
            indicators.append("starts_with_digit_hyphen")
        
        # Punycode/IDN detection
        if 'xn--' in domain.lower():
            indicators.append("punycode_domain")
        
        return indicators

    def _check_dns_resolution(self, domain: str) -> bool:
        """
        Check if domain resolves via DNS (passive lookup).
        Returns True if it resolves, False if not.
        Does NOT perform any intrusive operations.
        """
        try:
            import socket
            socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            return True
        except (socket.gaierror, socket.timeout, OSError):
            return False

    def _check_mx_records(self, domain: str) -> bool:
        """
        Check if domain has MX records (passive lookup).
        Returns True if MX records exist.
        """
        try:
            import socket
            result = socket.getaddrinfo(domain, 'smtp', socket.AF_INET, socket.SOCK_STREAM)
            return len(result) > 0
        except (socket.gaierror, socket.timeout, OSError):
            return False

    def _generate_findings(self, result: dict) -> list[Finding]:
        """Generate findings from intelligence results."""
        findings = []
        domain = result["domain"]

        if not domain:
            return findings

        # Brand impersonation
        if result["brand_impersonation"]:
            findings.append(Finding(
                rule_id="INTEL_BRAND_IMPERSONATION",
                category=Category.INTEL,
                severity=Severity.HIGH.value,
                points=15,
                message=f"Domain '{domain}' impersonates brand '{result['impersonated_brand']}'.",
                evidence=f"Domain: {domain}, Brand: {result['impersonated_brand']}",
                explanation=(
                    f"The sender domain '{domain}' contains or closely resembles "
                    f"the '{result['impersonated_brand']}' brand name but is not an "
                    f"official domain. This is a strong indicator of brand impersonation."
                ),
                source="Local domain intelligence",
            ))

        # Lookalike domain
        if result["lookalike_detected"]:
            findings.append(Finding(
                rule_id="INTEL_LOOKALIKE_DOMAIN",
                category=Category.INTEL,
                severity=Severity.HIGH.value,
                points=12,
                message=f"Domain '{domain}' resembles known brand '{result['lookalike_target']}'.",
                evidence=f"Domain: {domain}, Target: {result['lookalike_target']}",
                explanation=(
                    f"The domain '{domain}' uses character substitution or similar "
                    f"construction to mimic '{result['lookalike_target']}'. This is "
                    f"a common phishing technique."
                ),
                source="Local domain intelligence",
            ))

        # Suspicious TLD
        if result["suspicious_tld"]:
            findings.append(Finding(
                rule_id="INTEL_SUSPICIOUS_TLD",
                category=Category.INTEL,
                severity=Severity.MEDIUM.value,
                points=6,
                message=f"Domain uses suspicious TLD ({result['tld']}).",
                evidence=f"Domain: {domain}, TLD: {result['tld']}",
                explanation=(
                    f"The TLD '{result['tld']}' is commonly associated with "
                    f"phishing and disposable domain registrations."
                ),
                source="Local domain intelligence",
            ))

        # No DNS resolution
        if not result.get("dns_resolves", True):
            findings.append(Finding(
                rule_id="INTEL_NO_DNS",
                category=Category.INTEL,
                severity=Severity.MEDIUM.value,
                points=5,
                message=f"Domain '{domain}' does not resolve via DNS.",
                evidence=f"Domain: {domain}",
                explanation=(
                    "The domain has no DNS A record. This could indicate a "
                    "newly created or already-defunct phishing domain."
                ),
                source="DNS lookup",
            ))

        # Has MX records (positive signal, carefully used)
        if result.get("has_mx", False):
            findings.append(Finding(
                rule_id="INTEL_HAS_MX",
                category=Category.INTEL,
                severity=Severity.LOW.value,
                points=-2,
                message=f"Domain '{domain}' has configured MX records.",
                evidence=f"Domain: {domain}",
                explanation=(
                    "The domain has MX records, suggesting it is configured "
                    "to receive email. This is a weak positive signal and does "
                    "NOT prove the domain is safe."
                ),
                source="DNS lookup",
            ))

        return findings
