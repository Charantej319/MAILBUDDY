"""
Detection false-positive repair — focused regression tests (Session 2).

Covers:
  F-1  Brand-matching false-positive flood (registrable-domain awareness,
       subdomain tokens are not standalone evidence, single consolidated
       finding per domain↔brand relationship, cross-analyzer dedup)
  F-2  Legitimate regional brand domains (google.de, google.co.in,
       amazon.de, outlook.office.com) must not receive URL_LOOKALIKE_DOMAIN
  F-7  Generic display-name words must not trigger SENDER_NAME_DOMAIN_MISMATCH
  F-11 Bare "account" must not be a credential trigger
  F-13 Digits are not a standalone suspicious-domain signal

Genuine phishing/lookalike examples are asserted to REMAIN detectable.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from detection.sender import (
    SenderAnalyzer,
    check_brand_impersonation,
    is_official_brand_domain,
)
from detection.content_analyzer import ContentAnalyzer
from detection.rules import is_risky_level
from detection.url_analyzer import URLAnalyzer
from detection.intelligence.domain_intelligence import DomainIntelligence, clear_cache
from detection.scoring import RiskScorer
from detection.rules import Finding, Category, Severity
from detection.engine import DetectionEngine


def _rules(findings):
    return [f.rule_id for f in findings]


@pytest.fixture(autouse=True)
def _clear_intel_cache():
    clear_cache()
    yield
    clear_cache()


# ───────────────────────────── F-1 ─────────────────────────────

class TestF1BrandMatching:
    def test_dhl_example_flagged_once(self):
        """dhl.example references the DHL brand on an unrelated registrable
        domain — flagged, but exactly ONCE (no duplicate findings)."""
        findings = check_brand_impersonation("dhl.example")
        assert "SENDER_BRAND_IMPERSONATION" in _rules(findings)
        assert len(findings) == 1

    def test_google_docs_share_example_subdomain_tokens_not_evidence(self):
        """Brand tokens in the SUBDOMAIN chain (google.docs.share.example)
        are not standalone impersonation evidence — arbitrary subdomains are
        not independent brand identities."""
        findings = check_brand_impersonation("google.docs.share.example")
        assert findings == []

    def test_legitimate_dhl_domain_not_flagged(self):
        assert check_brand_impersonation("dhl.com") == []
        assert is_official_brand_domain("dhl.com")[0] == "dhl"

    def test_legitimate_google_subdomain_not_flagged(self):
        assert check_brand_impersonation("mail.google.com") == []

    def test_regional_brand_domains_not_flagged(self):
        for domain in ("amazon.co.uk", "google.de", "paypal.de"):
            assert check_brand_impersonation(domain) == [], domain

    def test_genuine_impersonation_still_detected(self):
        for domain in ("paypai-secure.com", "dhl-tracking.example"):
            assert "SENDER_BRAND_IMPERSONATION" in _rules(
                check_brand_impersonation(domain)
            ), domain

    def test_sender_yields_one_brand_finding_total(self):
        """The sender analyzer must emit ONE sender-level brand finding per
        domain↔brand relationship — impersonation takes precedence over the
        substring lookalike check (no SENDER_LOOKALIKE_DOMAIN duplicate)."""
        findings = SenderAnalyzer().analyze(
            sender_email="track@dhl.example", sender_name="DHL Express",
            sender_domain="dhl.example",
        )
        rules = _rules(findings)
        brand_rules = [r for r in rules
                       if r in ("SENDER_BRAND_IMPERSONATION",
                                "SENDER_LOOKALIKE_DOMAIN")]
        assert "SENDER_BRAND_IMPERSONATION" in brand_rules
        assert len(brand_rules) == 1, f"brand flood: {rules}"

    def test_subdomain_brand_token_no_lookalike_either(self):
        """google.docs.share.example must not be flagged by the substring
        lookalike check either — the search is registrable-domain scoped."""
        findings = SenderAnalyzer().analyze(
            sender_email="docs@google.docs.share.example", sender_name="Docs",
            sender_domain="google.docs.share.example",
        )
        rules = _rules(findings)
        assert "SENDER_BRAND_IMPERSONATION" not in rules
        assert "SENDER_LOOKALIKE_DOMAIN" not in rules

    def test_single_finding_for_multi_match_domain(self):
        """A domain matching several brand stems yields ONE consolidated
        finding listing every implicated brand — not one finding per stem."""
        findings = check_brand_impersonation("google-apple-netflix-claims.example")
        assert len(findings) == 1
        assert "SENDER_BRAND_IMPERSONATION" in _rules(findings)

    def test_engine_brand_flood_deduplicated(self):
        """Full DetectionEngine run on a phishing sender: at most ONE
        SENDER_BRAND_IMPERSONATION and at most one INTEL brand finding."""
        engine = DetectionEngine()
        parsed = type("P", (), {})()
        parsed.sender_email = "support@dhl-tracking-notify.example"
        parsed.sender_name = "DHL Delivery"
        parsed.sender_domain = "dhl-tracking-notify.example"
        parsed.urls = []
        parsed.anchor_text = ""
        parsed.body_text = "Your parcel could not be delivered. Pay the customs fee."
        parsed.body_html = ""
        parsed.headers = {}
        parsed.attachments = []
        parsed.spf_result = "none"
        parsed.dkim_result = "none"
        parsed.dmarc_result = "none"
        parsed.received_headers = []
        parsed.message_id = ""
        parsed.subject = "Parcel delivery notification"

        results = engine.analyze(parsed)
        brand_rules = [
            f["rule_id"] for f in results["findings"]
            if f["rule_id"] in ("SENDER_BRAND_IMPERSONATION",
                                "SENDER_LOOKALIKE_DOMAIN",
                                "INTEL_BRAND_IMPERSONATION",
                                "INTEL_LOOKALIKE_DOMAIN")
        ]
        assert "SENDER_BRAND_IMPERSONATION" in brand_rules
        assert len(brand_rules) <= 2, f"brand flood: {brand_rules}"

    def test_scorer_consolidates_same_brand_findings(self):
        """Two findings describing the same brand relationship score once:
        the strongest at full points, the overlap downweighted to 40%."""
        scorer = RiskScorer()
        findings = [
            Finding(rule_id="SENDER_BRAND_IMPERSONATION", category=Category.SENDER,
                    severity="HIGH", points=15, message="sender brand",
                    dedup_key="paypal"),
            Finding(rule_id="INTEL_BRAND_IMPERSONATION", category=Category.INTEL,
                    severity="HIGH", points=15, message="intel brand",
                    dedup_key="paypal"),
            Finding(rule_id="URL_LOOKALIKE_DOMAIN", category=Category.URL,
                    severity="HIGH", points=12, message="url lookalike",
                    dedup_key="paypal"),
        ]
        score, classification, out, _, _ = scorer.calculate_score(findings)
        rule_ids = [f["rule_id"] for f in out]
        assert rule_ids.count("SENDER_BRAND_IMPERSONATION") == 1
        assert rule_ids.count("INTEL_BRAND_IMPERSONATION") == 1
        assert rule_ids.count("URL_LOOKALIKE_DOMAIN") == 1
        # 15 (sender, full) + 6.0 (intel 40%) + 4.8 (url 40%) = 25.8 before caps
        points = {f["rule_id"]: f["points"] for f in out}
        assert points["SENDER_BRAND_IMPERSONATION"] == 15
        assert points["INTEL_BRAND_IMPERSONATION"] == 6.0
        assert points["URL_LOOKALIKE_DOMAIN"] == 4.8


# ───────────────────────────── F-2 ─────────────────────────────

class TestF2RegionalDomains:
    @pytest.mark.parametrize("url", [
        "https://google.de",
        "https://google.co.in",
        "https://amazon.de",
        "https://outlook.office.com",
        "https://mail.google.com",
        "https://amazon.co.uk",
        "https://dhl.de",
    ])
    def test_legitimate_regional_domains_not_lookalike(self, url):
        findings = URLAnalyzer().analyze([url])
        assert "URL_LOOKALIKE_DOMAIN" not in _rules(findings), (
            f"{url} falsely flagged: {_rules(findings)}"
        )

    @pytest.mark.parametrize("url", [
        "https://paypai-secure.com/login",
        "https://paypa1-login.com/verify",
        "https://goog1e-support.com/signin",
    ])
    def test_genuine_lookalikes_still_detected(self, url):
        findings = URLAnalyzer().analyze([url])
        assert "URL_LOOKALIKE_DOMAIN" in _rules(findings), (
            f"{url} lookalike MISSED: {_rules(findings)}"
        )

    def test_intelligence_regional_not_lookalike(self):
        intel = DomainIntelligence()
        for domain in ("google.de", "google.co.in", "amazon.de"):
            result = intel.analyze(domain)
            assert result["lookalike_detected"] is False, domain
            assert result["brand_impersonation"] is False, domain


# ───────────────────────────── F-7 ─────────────────────────────

class TestF7GenericDisplayNames:
    @pytest.mark.parametrize("name,domain", [
        ("Chase Business Bank", "chase.com"),
        ("Amazon Seller Support", "sellercentral.example"),
        ("Verify My Account Team", "acmecorp.com"),
        ("Secure Login Services", "acmecorp.com"),
        ("John Smith", "acmecorp.com"),
    ])
    def test_generic_names_no_mismatch(self, name, domain):
        findings = SenderAnalyzer().analyze(
            sender_email=f"alerts@{domain}", sender_name=name,
            sender_domain=domain,
        )
        assert "SENDER_NAME_DOMAIN_MISMATCH" not in _rules(findings), (
            f"{name!r} falsely flagged: {_rules(findings)}"
        )

    def test_generic_words_are_not_brands(self):
        from detection.intelligence.domain_intelligence import BRAND_NAMES
        for generic in ("bank", "secure", "verify", "account", "login",
                        "auth", "office", "visa", "mastercard"):
            assert generic not in BRAND_NAMES, f"'{generic}' must not be a brand"

    def test_obvious_mismatch_still_detected(self):
        findings = SenderAnalyzer().analyze(
            sender_email="alerts@secure-banking-xyz.com",
            sender_name="PayPal Security Team",
            sender_domain="secure-banking-xyz.com",
        )
        assert "SENDER_NAME_DOMAIN_MISMATCH" in _rules(findings)

    def test_legitimate_brand_domain_combo_clean(self):
        findings = SenderAnalyzer().analyze(
            sender_email="no-reply@paypal.com",
            sender_name="PayPal Service",
            sender_domain="paypal.com",
        )
        assert "SENDER_NAME_DOMAIN_MISMATCH" not in _rules(findings)


# ──────────────────────────── F-11 ─────────────────────────────

class TestF11BareAccount:
    @pytest.mark.parametrize("body", [
        "Your account dashboard has new features.",
        "The account manager will present quarterly results.",
        "Your account has been updated.",
        "We have updated our account terms.",
    ])
    def test_benign_account_messages_not_credential_requests(self, body):
        findings = ContentAnalyzer().analyze(body)
        assert "CONTENT_CREDENTIAL_REQUEST" not in _rules(findings), (
            f"{body!r} falsely flagged: {_rules(findings)}"
        )

    @pytest.mark.parametrize("body", [
        "Please enter your account password.",
        "Verify your account credentials.",
        "Send us your login details.",
        "Enter your username and password.",
        "Your account has been locked. Confirm your password immediately.",
    ])
    def test_malicious_credential_requests_still_detected(self, body):
        findings = ContentAnalyzer().analyze(body)
        assert "CONTENT_CREDENTIAL_REQUEST" in _rules(findings), (
            f"{body!r} credential request MISSED: {_rules(findings)}"
        )

    def test_account_number_still_detected(self):
        """'account number' (existing detection) must keep working."""
        findings = ContentAnalyzer().analyze("Please provide your account number.")
        assert "CONTENT_CREDENTIAL_REQUEST" in _rules(findings)

    def test_combo_not_recreated_by_correlation(self):
        """Benign 'account' text must not reach the credential correlation
        (CORR_URGENCY_CREDENTIAL / CORR_CREDENTIAL_PHISHING) indirectly."""
        from detection.engine import DetectionEngine

        class P:
            sender_email = "news@acmecorp.com"
            sender_name = "Acme News"
            sender_domain = "acmecorp.com"
            urls = []
            anchor_text = ""
            body_text = ("URGENT: Your account dashboard has new features. "
                         "The account manager will present quarterly results.")
            body_html = ""
            headers = {}
            attachments = []
            spf_result = "pass"
            dkim_result = "pass"
            dmarc_result = "pass"
            received_headers = []
            message_id = ""
            subject = "Dashboard feature announcement"

        results = DetectionEngine().analyze(P())
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "CONTENT_CREDENTIAL_REQUEST" not in rule_ids
        assert "CORR_URGENCY_CREDENTIAL" not in rule_ids
        assert "CORR_CREDENTIAL_PHISHING" not in rule_ids


# ──────────────────────────── F-13 ─────────────────────────────

class TestF13DigitDomains:
    @pytest.mark.parametrize("domain", [
        "7-eleven.com",
        "2024reports.example",
        "office365.example",
    ])
    def test_legitimate_digit_domains_not_suspicious(self, domain):
        findings = SenderAnalyzer().analyze(
            sender_email=f"mail@{domain}", sender_name="Co", sender_domain=domain,
        )
        assert "SENDER_SUSPICIOUS_DOMAIN" not in _rules(findings), domain
        assert "SENDER_HOMOGLYPH" not in _rules(findings), domain

    def test_long_digit_run_still_flagged(self):
        """A 5+ consecutive-digit run is structural noise, not a year."""
        findings = SenderAnalyzer().analyze(
            sender_email="x@123456789.example", sender_name="X",
            sender_domain="123456789.example",
        )
        assert "SENDER_SUSPICIOUS_DOMAIN" in _rules(findings)

    def test_digit_substitution_still_detected(self):
        """Digit-substitution lookalikes remain detectable via the
        context-aware homoglyph logic (digit decodes onto a brand)."""
        findings = SenderAnalyzer().analyze(
            sender_email="admin@microsoft-0nline.com",
            sender_name="Microsoft Admin",
            sender_domain="microsoft-0nline.com",
        )
        rules = _rules(findings)
        assert ("SENDER_HOMOGLYPH" in rules
                or "SENDER_BRAND_IMPERSONATION" in rules), rules

    def test_intelligence_digits_not_alone_suspicious(self):
        intel = DomainIntelligence()
        result = intel.analyze("7-eleven.com")
        assert "excessive_digits" not in result["domain_indicators"]


# ─────────────────── cross-cutting regression guard ───────────────────

class TestDetectionStillWorks:
    def test_phishing_email_still_high_risk(self):
        """A classic phishing email must still score HIGH RISK."""
        from detection.engine import DetectionEngine

        class P:
            sender_email = "security@paypa1-secure.com"
            sender_name = "PayPal Security"
            sender_domain = "paypa1-secure.com"
            urls = ["https://paypa1-secure.com/login?next=/verify"]
            anchor_text = ""
            body_text = ("URGENT: Your account has been suspended. "
                         "Enter your password and verification code within 24 hours.")
            body_html = ""
            headers = {"Reply-To": "collector@evil-libs.example"}
            attachments = []
            spf_result = "fail"
            dkim_result = "fail"
            dmarc_result = "fail"
            received_headers = []
            message_id = ""
            subject = "Your account has been suspended"

        results = DetectionEngine().analyze(P())
        assert results["risk_score"] >= 50, results["risk_score"]
        assert is_risky_level(results["classification"]), results["classification"]
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "CONTENT_CREDENTIAL_REQUEST" in rule_ids
        assert "SENDER_BRAND_IMPERSONATION" in rule_ids

    def test_legitimate_email_stays_safe(self):
        from detection.engine import DetectionEngine

        class P:
            sender_email = "john@acmecorp.com"
            sender_name = "John Smith"
            sender_domain = "acmecorp.com"
            urls = []
            anchor_text = ""
            body_text = ("Hi team, please review the attached quarterly report. "
                         "The account manager will present the results on Monday.")
            body_html = ""
            headers = {}
            attachments = []
            spf_result = "pass"
            dkim_result = "pass"
            dmarc_result = "pass"
            received_headers = []
            message_id = ""
            subject = "Quarterly report review"

        results = DetectionEngine().analyze(P())
        assert results["classification"] in ("SAFE", "LOW RISK"), (
            f"{results['classification']} ({results['risk_score']})"
        )
