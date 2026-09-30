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

# Session A: passive domain-age intelligence (RDAP-based, fail-safe).
# Imported lazily at call time inside analyze() as well, so a broken
# optional dependency chain can never prevent the core analyzers from
# loading; the direct import here is for clarity and static analysis.
from .domain_age import (_age_findings, clear_age_cache, get_domain_age)

# Session B: optional external URL threat intelligence (Google Safe
# Browsing). Import is fail-safe by contract: check_url NEVER raises and
# returns UNAVAILABLE when unconfigured, so Safe Browsing can never break
# the deterministic analyzers.
from .threat_intel.google_safe_browsing import GoogleSafeBrowsingProvider
from .threat_intel.base import ThreatStatus

# Session C: safe TLS/certificate intelligence (evidence, not a verdict).
# probe_tls never raises and never connects to private/local targets.
from . import tls_intelligence
from .tls_intelligence import probe_tls as _tls_probe, TLS_FINDING_RULES


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

# Legitimate regional / official domain variants per brand (F-2).
# Keys are canonical .com domains from KNOWN_BRANDS; values are the official
# regional registrable domains that must never be flagged as lookalikes of
# the canonical domain merely because their registrable name matches while
# the TLD differs ("google.de" ≈ "google.com" on the registrable label).
REGIONAL_BRAND_DOMAINS = {
    "google.com": {"google.de", "google.co.uk", "google.co.in", "google.ca",
                   "google.com.au", "google.fr", "google.it", "google.es",
                   "google.nl", "google.pl", "google.com.br", "google.co.jp",
                   "gmail.com", "googlemail.com", "youtube.com", "android.com"},
    "microsoft.com": {"microsoft.de", "microsoft.co.uk", "microsoftonline.com",
                      "microsoft365.com", "office.com", "office365.com",
                      "outlook.com", "live.com", "hotmail.com", "windows.com",
                      "xbox.com", "azure.com", "support.microsoft.com",
                      "outlook.office.com", "outlook.office365.com"},
    "apple.com": {"apple.co.uk", "apple.de", "icloud.com", "me.com"},
    "amazon.com": {"amazon.de", "amazon.co.uk", "amazon.in", "amazon.ca",
                   "amazon.co.jp", "amazon.fr", "amazon.it", "amazon.es",
                   "amazon.com.au", "amazon.com.br", "amazon.com.mx",
                   "primevideo.com", "amazonaws.com"},
    "paypal.com": {"paypal.de", "paypal.co.uk", "paypal.in", "paypal.fr"},
    "facebook.com": {"facebook.de", "fb.com", "instagram.com", "whatsapp.com"},
    "netflix.com": {"netflix.co.uk", "netflix.in", "netflix.de"},
    "linkedin.com": {"licdn.com"},
    "dhl.com": {"dhl.de", "dhl.co.uk", "dhl.co.in", "dhl.fr", "dhl.it"},
    "fedex.com": {"fedex.co.uk", "fedex.in", "fedex.de"},
    "ups.com": {"ups.co.uk", "ups.de"},
    "citibank.com": {"citi.com", "citibank.co.in", "citibank.de"},
    "wellsfargo.com": set(),
    "chase.com": {"chaseonline.com"},
}

# Brand names for impersonation detection.
# F-7: only DISTINCTIVE brand identifiers belong here. Generic/security words
# that legitimately occur in countless company and product names ("bank",
# "secure", "verify", "account", "login", "auth", "office", "outlook", "visa",
# "mastercard", "amex", "apple"-the-fruit, "ups"-the-abbreviation) are NOT
# brands — matching them in display names/domains produced a flood of
# SENDER_NAME_DOMAIN_MISMATCH false positives for ordinary names such as
# "Chase Business Bank" or "Verify My Account Team".
BRAND_NAMES = {
    "google", "gmail", "youtube", "microsoft", "amazon", "paypal",
    "facebook", "instagram", "whatsapp", "netflix", "linkedin",
    "github", "dropbox", "dhl", "fedex", "usps", "ebay",
    "wellsfargo", "citibank", "hdfcbank", "icicibank", "spotify",
}

# Distinctive brand token -> canonical display name, for display-name
# mismatch analysis (F-7). Same exclusions as BRAND_NAMES above: a single
# generic word ("bank", "secure", "verify", "account", "login", "auth",
# "outlook", "office", "visa", "chase", "amazon") is never sufficient
# evidence of impersonation — the token must be distinctive enough that its
# presence in a display name almost always refers to the brand.
# "chase"/"amazon" ARE distinctive brands, but display names like "Chase
# Business Bank" or "Amazon Seller Support" are ordinary business names that
# legitimately contain them — the mismatch rule therefore requires the
# registrable SENDER DOMAIN to be unrelated to the brand (checked in
# sender.py), not merely the absence of the exact string in the domain.
DISTINCTIVE_NAME_BRANDS = {
    "paypal": "PayPal",
    "paypa1": "PayPal",
    "netflix": "Netflix",
    "wellsfargo": "Wells Fargo",
    "facebook": "Facebook",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
    "linkedin": "LinkedIn",
    "dropbox": "Dropbox",
    "gmail": "Gmail",
    "youtube": "YouTube",
    "hdfcbank": "HDFC Bank",
    "icicibank": "ICICI Bank",
    "citibank": "Citibank",
    "wellsfarg0": "Wells Fargo",
    "paypa1": "PayPal",
}

# Multi-word brand phrases: a display name may legitimately contain a
# distinctive single token, so require the FULL phrase when the name reads
# like a normal business descriptor rather than a brand claim.
BRAND_PHRASES = {
    "amazon": "Amazon",
    "chase": "Chase",
    "google": "Google",
    "microsoft": "Microsoft",
    "dhl": "DHL",
    "fedex": "FedEx",
    "apple": "Apple",
}


def _registrable(domain: str) -> str:
    """Registrable domain (last two labels, common two-level suffix aware).

    Kept dependency-free and consistent with detection.sender._split_domain.
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
    """True when the domain is a known official regional/brand variant (F-2).

    Checks the registrable domain against every brand's regional allowlist
    (REGIONAL_BRAND_DOMAINS) plus KNOWN_BRANDS itself, so legitimate
    subdomains ("mail.google.com", "outlook.office.com") pass too.
    """
    registrable = _registrable(domain)
    if not registrable:
        return False
    if registrable in KNOWN_BRANDS:
        return True
    for regional in REGIONAL_BRAND_DOMAINS.values():
        if registrable in regional:
            return True
    return False


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
    """Clear the intelligence cache (including domain-age cache, Session A)."""
    _intel_cache.clear()
    _mx_cache.clear()
    clear_age_cache()


# ---------------------------------------------------------------------------
# F-14: bounded, cache-backed, REAL MX resolution
# ---------------------------------------------------------------------------

# Hard wall-clock budget for one DNS operation. Slow resolvers must never
# stall analysis (or the FastAPI event loop) — past this we give up and
# record 'no evidence'.
_DNS_TIMEOUT_SECONDS = 3.0

# Bound on the worker pool serving blocking DNS calls. Small by design: DNS
# lookups are rare (cache absorbs repeats) and the pool stops unbounded
# thread creation under load.
_DNS_EXECUTOR = None
_DNS_EXECUTOR_LOCK = None
_DNS_MAX_WORKERS = 4

# Per-process MX memo (domain -> True/False/None-unknown). Prevents repeated
# DNS queries for the same domain during one analysis run. Values are
# explicit True/False; a domain never queried is absent.
_mx_cache: dict[str, bool] = {}
_MX_CACHE_TTL = 3600.0

# Plausible-domain guard: getaddrinfo/dnspython happily accept nonsense
# ('localhost', '127.0.0.1', 'x', 'a"b.com'); treat those as 'no MX evidence'
# without touching the resolver at all.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def _is_plausible_domain(domain: str) -> bool:
    """Cheap structural check; garbage never reaches the resolver."""
    return bool(_DOMAIN_RE.match((domain or "").strip()))


def _get_dns_executor():
    """Lazily created shared bounded pool for blocking DNS work."""
    global _DNS_EXECUTOR, _DNS_EXECUTOR_LOCK
    if _DNS_EXECUTOR is None:
        import threading
        from concurrent.futures import ThreadPoolExecutor
        if _DNS_EXECUTOR_LOCK is None:
            _DNS_EXECUTOR_LOCK = threading.Lock()
        with _DNS_EXECUTOR_LOCK:
            if _DNS_EXECUTOR is None:
                _DNS_EXECUTOR = ThreadPoolExecutor(
                    max_workers=_DNS_MAX_WORKERS,
                    thread_name_prefix="phishguard-dns",
                )
    return _DNS_EXECUTOR


def _run_bounded(fn, timeout: float):
    """Run blocking fn() with a hard timeout on the shared bounded pool.

    Raises the underlying exception on timeout (after abandoning the worker —
    the pool keeps it bounded so repeated timeouts cannot leak threads). The
    caller is expected to treat every failure as 'no evidence'.
    """
    from concurrent.futures import ThreadPoolExecutor
    executor = _get_dns_executor()
    future = executor.submit(fn)
    try:
        return future.result(timeout=timeout)
    except TimeoutError:
        future.cancel()
        raise


def _mx_cache_get(domain: str):
    return _mx_cache.get(domain)


def _mx_cache_set(domain: str, value: bool):
    # Simple size guard: the memo is per-process and bounded by the number of
    # distinct domains seen; entries expire with clear_cache() or process end.
    if len(_mx_cache) > 2048:
        _mx_cache.clear()
    _mx_cache[domain] = value


def _query_mx_records(domain: str) -> bool:
    """TRUE MX record query via dnspython, bounded in time.

    Returns True only when the domain has at least one MX record. A/AAAA
    resolution is NOT treated as MX (an A-only domain returns False).
    Raises on timeout/network failure; callers must fail safe.
    """
    try:
        import dns.resolver  # dnspython
    except ImportError as exc:  # pragma: no cover - dependency declared in requirements
        raise RuntimeError("dnspython not available") from exc

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = dns.resolver.get_default_resolver().nameservers
    resolver.lifetime = _DNS_TIMEOUT_SECONDS
    resolver.timeout = _DNS_TIMEOUT_SECONDS

    def _resolve() -> bool:
        answer = resolver.resolve(domain, "MX")
        # An answer containing only a NODATA-style empty exchange counts as
        # no MX; dnspython raises NoAnswer in that case, so any list here is
        # a genuine MX RRset.
        return len(answer) > 0

    return _run_bounded(_resolve, _DNS_TIMEOUT_SECONDS)


# Session B: recognized Safe Browsing threat types (mirror of
# threat_intel.base.KNOWN_THREAT_TYPES for message phrasing).
_SB_KNOWN_TYPES = {
    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
}


class DomainIntelligence:
    """
    Performs passive domain intelligence lookups.
    All lookups are read-only and non-intrusive.
    """

    # Session B: shared stateless provider instance (thread-safe: check_url
    # is pure + cache-protected). Replaceable via _set_sb_provider in tests.
    _sb_provider = None

    @classmethod
    def _get_sb_provider(cls):
        if cls._sb_provider is None:
            cls._sb_provider = GoogleSafeBrowsingProvider()
        return cls._sb_provider

    def analyze(self, domain: str, urls: Optional[list[str]] = None) -> dict:
        """
        Analyze a domain (and optionally the email's URLs for external
        threat intelligence) and return intelligence results.
        
        Returns dict with:
            domain, suspicious_tld, lookalike_detected, brand_impersonation,
            domain_age (Session A), safe_browsing (Session B),
            domain_indicators, findings
        """
        if not domain:
            return self._empty_result("")

        # Check cache
        cached = _get_cached(domain)
        if cached:
            # Session B: Safe Browsing is PER-URL and must NOT be served
            # from the per-DOMAIN cache — two emails from the same sender
            # domain usually contain different URLs. Serve the cached
            # domain intel as a base (shallow-copy the mutable lists so
            # the cached entry is never mutated) and run the per-URL SB
            # lookup fresh for this email.
            result = {
                **cached,
                "domain_indicators": list(cached.get("domain_indicators", [])),
                "findings": list(cached.get("findings", [])),
            }
            self._apply_safe_browsing(result, urls)
            self._apply_tls_intelligence(result, urls)
            return result

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

        # 7. Domain age via public RDAP (passive; Session A).
        #    Fail-safe: get_domain_age never raises and returns 'no
        #    evidence' on any failure (no network, unsupported TLD,
        #    malformed response). Age findings (INTEL_YOUNG_DOMAIN /
        #    INTEL_DOMAIN_RECENT) join the other INTEL findings and flow
        #    into the engine through intel_result["findings"].
        try:
            age_result = get_domain_age(domain)
        except Exception:
            # Defensive: get_domain_age already fail-safes internally.
            from .domain_age import _empty_age
            age_result = _empty_age()
        result["domain_age"] = age_result
        if age_result.get("age_known"):
            result["domain_indicators"].append(
                f"domain_age_{age_result.get('age_category', 'unknown')}"
            )

        # Generate findings
        result["findings"] = self._generate_findings(result)

        # Cache BEFORE Safe Browsing: the domain cache stores only
        # domain-derived intelligence. SB results are per-URL and are
        # applied after cache retrieval (both on this fresh result and on
        # every future cache hit), so one email's URLs can never leak
        # into another email's cached domain intelligence.
        _set_cached(domain, result)

        # 8. External URL threat intelligence (Session B, optional).
        self._apply_safe_browsing(result, urls)

        # 9. TLS/certificate evidence for HTTPS URLs (Session C, optional).
        self._apply_tls_intelligence(result, urls)
        return result

    # ------------------------------------------------------------------
    # Session B: Safe Browsing integration
    # ------------------------------------------------------------------

    def _apply_safe_browsing(self, result: dict, urls) -> None:
        """Run optional Safe Browsing lookups over the email's URLs.

        - Deduplicates URLs per analysis (one request per unique URL).
        - Only KNOWN_THREAT produces a Finding (INTEL_SAFE_BROWSING_THREAT).
          NO_MATCH / UNAVAILABLE / ERROR are "no evidence": they are
          recorded in the structured result and NEVER increase risk.
        - Fail-safe by contract: check_url never raises; any unexpected
          error here must not break the deterministic analyzers.
        """
        url_list = [u for u in (urls or []) if isinstance(u, str) and u.strip()]
        result["safe_browsing"] = []
        if not url_list:
            return

        try:
            provider = self._get_sb_provider()
            seen_norms: set[str] = set()
            for url in url_list:
                # Per-analysis dedup on the normalized lookup key.
                from .threat_intel.google_safe_browsing import normalize_url
                normalized = normalize_url(url)
                if normalized is None or normalized in seen_norms:
                    continue
                seen_norms.add(normalized)
                sb = provider.check_url(url)
                result["safe_browsing"].append(sb.to_dict())
                if sb.is_known_threat:
                    result["findings"].append(self._sb_finding(sb))
        except Exception:
            # Provider trouble must never break domain intelligence.
            if not result.get("safe_browsing"):
                result["safe_browsing"] = [{
                    "provider": "google_safe_browsing",
                    "status": ThreatStatus.ERROR,
                    "url": "", "threat_types": [],
                    "available": False, "error": "INTEGRATION_FAILURE",
                }]

    # ------------------------------------------------------------------
    # Session C: TLS/certificate intelligence
    # ------------------------------------------------------------------

    def _apply_tls_intelligence(self, result: dict, urls) -> None:
        """Collect TLS certificate evidence for HTTPS URLs.

        - Deduplicates by HOSTNAME per analysis (one probe per host;
          two URLs on one host never cause two TLS handshakes).
        - TLS_VALID / HTTP / TLS_UNAVAILABLE / TLS_ERROR are evidence
          only: they NEVER create findings and never change the score.
          Only expired / mismatched / invalid certificates produce
          minimal-points INTEL findings (never a verdict of phishing).
        - Fail-safe by contract: probe_tls never raises.
        """
        url_list = [u for u in (urls or []) if isinstance(u, str) and u.strip()]
        result["tls"] = []
        if not url_list:
            return

        try:
            seen_hosts: set[str] = set()
            for url in url_list:
                from .threat_intel.google_safe_browsing import normalize_url
                normalized = normalize_url(url)
                if normalized is None:
                    continue
                from urllib.parse import urlparse as _urlparse
                hostname = (_urlparse(normalized).hostname or "").lower()
                if not hostname or hostname in seen_hosts:
                    continue
                seen_hosts.add(hostname)
                tls = _tls_probe(url)
                result["tls"].append(tls)
                rule = TLS_FINDING_RULES.get(tls.get("state", ""))
                if rule:
                    result["findings"].append(self._tls_finding(tls, rule))
        except Exception:
            # TLS evidence must never break domain intelligence.
            if not result.get("tls"):
                result["tls"] = [{
                    "url": "", "state": "TLS_ERROR", "hostname": "",
                    "issuer": "", "subject_cn": "", "not_before": "",
                    "not_after": "", "error": "INTEGRATION_FAILURE",
                }]

    @staticmethod
    def _tls_finding(tls: dict, rule: tuple[str, float]) -> Finding:
        """Build the minimal INTEL finding for a certificate problem.

        Messages are strictly factual about the certificate; they never
        claim the site is phishing and never claim HTTPS proves safety.
        """
        severity, points = rule
        state = tls.get("state", "")
        hostname = tls.get("hostname") or "the requested hostname"
        if state == "TLS_EXPIRED":
            message = "TLS certificate is expired."
            explanation = (
                f"The HTTPS certificate for '{hostname}' is no longer "
                f"within its validity period. Expired certificates are "
                "sometimes used by abandoned, misconfigured, or malicious "
                "sites. This is one piece of evidence, not a verdict — "
                "evaluate it together with the other indicators."
            )
        elif state == "TLS_HOSTNAME_MISMATCH":
            message = ("TLS certificate hostname does not match the "
                       "requested hostname.")
            explanation = (
                f"The certificate served for '{hostname}' was issued for a "
                "different hostname. Legitimate sites rarely serve "
                "mismatched certificates; this pattern also appears in "
                "manipulated or fraudulent endpoints. This is evidence to "
                "weigh, not proof of phishing."
            )
        else:  # TLS_INVALID
            message = "TLS certificate validation failed."
            explanation = (
                f"The HTTPS certificate for '{hostname}' could not be "
                "validated (untrusted chain or malformed certificate). "
                "This is one piece of evidence, not a verdict."
            )
        return Finding(
            rule_id=f"INTEL_{state}",
            category=Category.INTEL,
            severity=severity,
            points=points,
            message=message,
            evidence=(f"hostname: {hostname}; state: {state}; "
                      f"issuer: {tls.get('issuer') or 'n/a'}"),
            explanation=explanation,
            source="TLS handshake (passive certificate inspection)",
        )

    @staticmethod
    def _sb_finding(sb) -> Finding:
        """Build the INTEL finding for one confirmed Safe Browsing threat."""
        types = list(sb.threat_types) or ["UNKNOWN"]
        known = [t for t in types if t in _SB_KNOWN_TYPES]
        unknown = [t for t in types if t not in _SB_KNOWN_TYPES]
        type_summary = ", ".join(types)
        if unknown:
            type_summary += " (not categorized by MailBuddy)"
        explanation = (
            f"Google Safe Browsing, an external threat-intelligence source, "
            f"currently reports this URL as {type_summary}. This is "
            f"external corroboration on top of MailBuddy's own analysis, "
            f"not a replacement for it."
        )
        if known:
            explanation += "" if not unknown else (
                " Some reported categories are not recognized by MailBuddy "
                "and are shown verbatim rather than guessed at."
            )
        else:
            explanation = (
                f"Google Safe Browsing reports this URL under category(ies) "
                f"{type_summary}. MailBuddy does not recognize these "
                "categories and treats the provider's verdict as a threat "
                "rather than assuming safety."
            )
        return Finding(
            rule_id="INTEL_SAFE_BROWSING_THREAT",
            category=Category.INTEL,
            severity=Severity.HIGH.value,
            points=10,
            message=(
                f"Google Safe Browsing reports this URL as "
                f"{type_summary}."
            ),
            evidence=f"URL: {sb.url}; provider: {sb.provider}; "
                     f"threatTypes: {', '.join(types)}",
            explanation=explanation,
            source="Google Safe Browsing (external)",
        )

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
            "domain_age": {
                "age_known": False,
                "age_days": None,
                "creation_date": None,
                "registrar": None,
                "registrar_url": None,
                "age_category": "unknown",
                "source": None,
            },
            "safe_browsing": [],
            "tls": [],
            "findings": [],
        }

    def _extract_tld(self, domain: str) -> str:
        """Extract the TLD from a domain."""
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            return "." + parts[-1]
        return ""

    def _check_brand_impersonation(self, domain: str) -> Optional[str]:
        """Check if domain impersonates a known brand (registrable-domain-aware).

        F-1: the comparison runs against the REGISTRABLE domain (last two
        labels, suffix-aware), never against arbitrary subdomains —
        "mail.dhl.com" is official, and a brand token found only in the
        subdomain chain of an unrelated registrable domain
        ("google.docs.share.example") is not standalone evidence.
        """
        if domain in KNOWN_BRANDS:
            return None  # It IS the legitimate domain

        # Legitimate regional/official variants are never impersonation.
        if _is_official_regional(domain):
            return None

        registrable = _registrable(domain)
        base = registrable.rsplit(".", 1)[0]

        for brand in BRAND_NAMES:
            if len(brand) < 4:
                continue
            # Distinctive brand stem must appear in the REGISTRABLE name.
            if brand in base:
                return brand

        # Lookalike stems: "paypa1-secure.com" does not contain "paypal"
        # literally, but its tokens are meaningfully similar to the brand.
        from difflib import SequenceMatcher

        for token in re.split(r"[\-.]+", base):
            if not token or len(token) < 4:
                continue
            for brand in BRAND_NAMES:
                if len(brand) < 4 or token == brand:
                    continue
                if SequenceMatcher(None, token, brand).ratio() >= 0.75:
                    return brand
        return None

    def _check_lookalike(self, domain: str) -> Optional[str]:
        """Check for lookalike domains targeting known brands (F-2).

        Registrable-domain-aware: the candidate's registrable domain is
        compared with each known brand's registrable domain. Legitimate
        regional variants (google.de, amazon.co.in, outlook.office.com) are
        allowlisted per brand and never reported; the similarity threshold
        is deliberately higher than before so ordinary shared-letter
        collisions between unrelated names are not reported.
        """
        from difflib import SequenceMatcher

        candidate = _registrable(domain)

        for known in KNOWN_BRANDS:
            if candidate == known:
                return None  # the brand itself

            # F-2: official regional variants never "look like" the brand.
            regional = REGIONAL_BRAND_DOMAINS.get(known, set())
            if candidate in regional:
                return None

            known_name = known.rsplit(".", 1)[0]
            candidate_name = candidate.rsplit(".", 1)[0]
            if not candidate_name or known_name not in candidate_name:
                continue
            # The brand name appears inside the candidate registrable name
            # ("google-login-security.com" targeting "google.com").
            ratio = SequenceMatcher(None, candidate_name, known_name).ratio()
            if 0.72 < ratio < 1.0:
                return known
        return None

    def _check_suspicious_patterns(self, domain: str) -> list[str]:
        """Check for suspicious domain patterns (F-13).

        Digits are NOT treated as a standalone strong signal: legitimate
        domains such as 7-eleven.com or year-named domains contain digits.
        Only structural anomalies (long digit runs, hyphen abuse, punycode)
        are reported here; digit-based brand substitution is measured by the
        sender analyzer's context-aware homoglyph logic.
        """
        indicators = []
        
        # Long digit runs (4+ consecutive digits) — structured noise, not
        # ordinary numbers like "7" in 7-eleven or "365" in office365.
        if re.search(r'\d{4,}', domain):
            indicators.append("excessive_digits")
        
        # Consecutive hyphens
        if re.search(r'-{2,}', domain):
            indicators.append("consecutive_hyphens")
        
        # Punycode/IDN detection
        if 'xn--' in domain.lower():
            indicators.append("punycode_domain")
        
        return indicators

    def _check_dns_resolution(self, domain: str) -> bool:
        """
        Check if domain resolves via DNS (passive lookup).
        Returns True if it resolves, False if not.
        Does NOT perform any intrusive operations.

        F-14: runs in a bounded worker thread with a hard timeout so a slow
        resolver can never stall the caller (the FastAPI event loop or the
        sync path) indefinitely. Failures fail SAFE (False = 'no evidence',
        never 'proof of legitimacy').
        """
        if not domain:
            return False
        try:
            import socket
            return _run_bounded(
                lambda: bool(socket.getaddrinfo(domain, None, socket.AF_INET,
                                                socket.SOCK_STREAM)),
                _DNS_TIMEOUT_SECONDS,
            )
        except (socket.gaierror, socket.timeout, OSError, Exception):
            # Any failure (timeout, resolver error, malformed domain) means
            # 'no evidence' — never an exception to the caller.
            return False

    def _check_mx_records(self, domain: str) -> bool:
        """
        Check if domain has MX records (passive lookup).
        Returns True if actual MX records exist.

        F-14: the previous implementation used socket.getaddrinfo(domain,
        'smtp', ...), which resolves A/AAAA addresses (the service hint is
        ignored for plain hostnames) — i.e. it was NOT an MX lookup and made
        A-resolvable domains look mail-capable. This now performs a REAL MX
        record query via dnspython, executed in a bounded worker thread with
        a strict timeout so the FastAPI/async event loop is never blocked.

        Failure semantics (all fail SAFE, returning False = 'no MX evidence'):
          - resolver timeout / network failure
          - malformed or unparseable domain
          - any unexpected resolver error
        DNS availability (or an MX record) is a WEAK signal at best: it is
        never treated as proof that a sender is legitimate (see
        INTEL_HAS_MX, -2 points, LOW severity).

        Per-domain memoization within this process prevents repeated queries
        for the same domain during one analysis run; results are additionally
        cached with the full intelligence result (see _set_cached).
        """
        if not domain or not _is_plausible_domain(domain):
            return False

        key = domain.lower().strip().rstrip(".")
        cached = _mx_cache_get(key)
        if cached is not None:
            return cached

        try:
            has_mx = _query_mx_records(key)
        except Exception:
            # Fail safe: DNS trouble must never break analysis.
            has_mx = False
            _mx_cache_set(key, False)
            return has_mx

        _mx_cache_set(key, has_mx)
        return has_mx

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
                # Canonical brand identity for cross-analyzer dedup (F-1).
                dedup_key=result["impersonated_brand"],
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
                dedup_key=result["lookalike_target"].rsplit(".", 1)[0],
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

        # Domain age findings (Session A): INTEL_YOUNG_DOMAIN (MEDIUM, +8)
        # for domains under 30 days, INTEL_DOMAIN_RECENT (LOW, +3) for
        # domains under a year. Established/unknown domains contribute
        # nothing — age alone never proves legitimacy or guilt.
        age_result = result.get("domain_age")
        if age_result:
            findings.extend(_age_findings(age_result))

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
