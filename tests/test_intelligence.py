"""
Unit tests for new detection features:
- Domain intelligence
- Correlation engine
- Confidence calculation
- Enhanced scoring
- Benign signals
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.engine import DetectionEngine
from detection.scoring import RiskScorer
from detection.rules import Finding, Category, Severity, calculate_confidence
from detection.intelligence.domain_intelligence import DomainIntelligence, clear_cache


# ── Domain Intelligence Tests ──────────────────────────────────────

def test_domain_intelligence_empty():
    """Test domain intelligence with empty input."""
    intel = DomainIntelligence()
    result = intel.analyze("")
    assert result["domain"] == ""
    assert result["findings"] == []
    print("[PASS]  test_domain_intelligence_empty passed")


def test_domain_intelligence_legitimate():
    """Test domain intelligence on a legitimate domain."""
    intel = DomainIntelligence()
    clear_cache()
    result = intel.analyze("google.com")
    assert result["domain"] == "google.com"
    assert result["brand_impersonation"] is False
    assert result["lookalike_detected"] is False
    print("[PASS]  test_domain_intelligence_legitimate passed")


def test_domain_intelligence_brand_impersonation():
    """Test detection of brand impersonation in domain."""
    intel = DomainIntelligence()
    clear_cache()
    result = intel.analyze("paypa1-secure.com")
    assert result["brand_impersonation"] is True
    findings = result["findings"]
    rule_ids = [f.rule_id for f in findings]
    assert "INTEL_BRAND_IMPERSONATION" in rule_ids
    print("[PASS]  test_domain_intelligence_brand_impersonation passed")


def test_domain_intelligence_suspicious_tld():
    """Test detection of suspicious TLD."""
    intel = DomainIntelligence()
    clear_cache()
    result = intel.analyze("example.xyz")
    assert result["suspicious_tld"] is True
    assert result["tld"] == ".xyz"
    findings = result["findings"]
    rule_ids = [f.rule_id for f in findings]
    assert "INTEL_SUSPICIOUS_TLD" in rule_ids
    print("[PASS]  test_domain_intelligence_suspicious_tld passed")


def test_domain_intelligence_caching():
    """Test that domain intelligence results are cached."""
    intel = DomainIntelligence()
    clear_cache()
    result1 = intel.analyze("test-cache-domain.com")
    result2 = intel.analyze("test-cache-domain.com")
    # Should return same object from cache
    assert result1 is result2
    clear_cache()
    print("[PASS]  test_domain_intelligence_caching passed")


def test_domain_intelligence_lookalike():
    """Test lookalike domain detection."""
    intel = DomainIntelligence()
    clear_cache()
    result = intel.analyze("google-login-security.com")
    # Should detect brand impersonation since 'google' is in the domain
    assert result["brand_impersonation"] is True or result["lookalike_detected"] is True
    clear_cache()
    print("[PASS]  test_domain_intelligence_lookalike passed")


# ── Confidence Calculation Tests ───────────────────────────────────

def test_confidence_no_findings():
    """Test confidence with no findings."""
    level, numeric = calculate_confidence([])
    assert level == "LOW"
    assert numeric <= 0.3
    print("[PASS]  test_confidence_no_findings passed")


def test_confidence_with_many_findings():
    """Test confidence with many diverse findings."""
    findings = [
        Finding(rule_id="HEADER_SPF_FAIL", category=Category.HEADER, severity="HIGH", points=8, message="SPF fail"),
        Finding(rule_id="SENDER_BRAND_IMPERSONATION", category=Category.SENDER, severity="HIGH", points=15, message="Brand impersonation"),
        Finding(rule_id="URL_LOOKALIKE_DOMAIN", category=Category.URL, severity="HIGH", points=12, message="Lookalike"),
        Finding(rule_id="CONTENT_CREDENTIAL_REQUEST", category=Category.CONTENT, severity="HIGH", points=10, message="Credential request"),
        Finding(rule_id="CORR_CREDENTIAL_PHISHING", category=Category.CORRELATION, severity="CRITICAL", points=15, message="Correlation"),
    ]
    level, numeric = calculate_confidence(findings, has_intel=True)
    assert level in ("HIGH", "VERY HIGH")
    assert numeric >= 0.5
    print("[PASS]  test_confidence_with_many_findings passed")


def test_confidence_correlation_boosts():
    """Test that correlation findings boost confidence."""
    base_findings = [
        Finding(rule_id="HEADER_SPF_FAIL", category=Category.HEADER, severity="HIGH", points=8, message="SPF fail"),
        Finding(rule_id="SENDER_MISMATCH", category=Category.SENDER, severity="MEDIUM", points=5, message="Mismatch"),
    ]
    level_base, num_base = calculate_confidence(base_findings)

    correlated_findings = base_findings + [
        Finding(rule_id="CORR_CREDENTIAL_PHISHING", category=Category.CORRELATION, severity="CRITICAL", points=15, message="Correlation"),
    ]
    level_corr, num_corr = calculate_confidence(correlated_findings)

    assert num_corr > num_base
    print("[PASS]  test_confidence_correlation_boosts passed")


# ── Enhanced Scoring Tests ─────────────────────────────────────────

def test_scoring_returns_confidence():
    """Test that scoring returns confidence data."""
    scorer = RiskScorer()
    findings = [
        Finding(rule_id="TEST", category=Category.SENDER, severity="HIGH", points=10, message="Test"),
    ]
    score, classification, findings_list, conf_level, conf_num = scorer.calculate_score(findings)
    assert score == 10.0
    assert conf_level is not None
    assert conf_num is not None
    print("[PASS]  test_scoring_returns_confidence passed")


def test_scoring_benign_signals():
    """Test that benign signals can reduce score."""
    scorer = RiskScorer()
    # Negative points for benign signal
    findings = [
        Finding(rule_id="BENIGN_AUTH", category=Category.HEADER, severity="LOW", points=-3, message="All auth pass"),
        Finding(rule_id="URL_SAFE", category=Category.URL, severity="LOW", points=-2, message="No suspicious URLs"),
    ]
    score, _, _, _, _ = scorer.calculate_score(findings)
    assert score <= 0.0  # Score should be at or below 0 with negative findings
    print("[PASS]  test_scoring_benign_signals passed")


def test_scoring_signal_deduplication():
    """Test that correlated authentication signals are deduplicated.

    Session 3 (F-6) update: SPF+DKIM+DMARC fail (+ multiple-failures) now
    activates the composite authentication severity floor — the strongest
    header-only spoofing evidence must never be compressed below SUSPICIOUS
    by the HEADER category cap. Deduplication of the overlapping findings
    still applies to OTHER combinations (e.g. two SPF-related failures), so
    the anti-double-counting behavior itself is unchanged."""
    scorer = RiskScorer()

    # The strong all-fail combination: floor guarantees >= 50 (SUSPICIOUS).
    all_fail = [
        Finding(rule_id="HEADER_SPF_FAIL", category=Category.HEADER, severity="HIGH", points=8, message="SPF fail"),
        Finding(rule_id="HEADER_DKIM_FAIL", category=Category.HEADER, severity="HIGH", points=7, message="DKIM fail"),
        Finding(rule_id="HEADER_DMARC_FAIL", category=Category.HEADER, severity="HIGH", points=8, message="DMARC fail"),
        Finding(rule_id="HEADER_MULTIPLE_AUTH_FAILURES", category=Category.HEADER, severity="HIGH", points=10, message="Multiple failures"),
    ]
    score, _, _, _, _ = scorer.calculate_score(all_fail)
    assert score >= 50, f"composite auth floor must apply, got {score}"

    # Ordinary deduplication still works for non-floor combinations.
    partial = [
        Finding(rule_id="HEADER_SPF_FAIL", category=Category.HEADER, severity="HIGH", points=8, message="SPF fail"),
        Finding(rule_id="HEADER_SPF_SOFTFAIL", category=Category.HEADER, severity="MEDIUM", points=5, message="SPF softfail"),
        Finding(rule_id="HEADER_SPF_NONE", category=Category.HEADER, severity="LOW", points=3, message="SPF none"),
    ]
    score_partial, _, _, _, _ = scorer.calculate_score(partial)
    raw_sum = 8 + 5 + 3
    assert score_partial < raw_sum, "overlapping SPF findings must still dedup"
    print("[PASS]  test_scoring_signal_deduplication passed")


# ── Correlation Engine Tests ───────────────────────────────────────

def test_engine_correlation_credential_phishing():
    """Test correlation engine detects credential phishing pattern."""
    engine = DetectionEngine()
    # Create a parsed email with credential request + suspicious URL
    from backend.app.parser.email_parser import ParsedEmail
    parsed = ParsedEmail(
        sender_email="security@paypa1.com",
        sender_name="PayPal Security",
        sender_domain="paypa1.com",
        subject="URGENT: Verify your account",
        body_text="Please provide your password and verify your account at http://paypa1-login.com/verify",
        urls=["http://paypa1-login.com/verify"],
        headers={
            'From': 'security@paypa1.com',
            'Authentication-Results': 'spf=fail; dkim=fail; dmarc=fail',
        },
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail",
    )
    results = engine.analyze(parsed)
    correlation_findings = [f for f in results["findings"] if f.get("category") == "CORRELATION"]
    assert len(correlation_findings) > 0
    rule_ids = [f["rule_id"] for f in correlation_findings]
    assert any("CREDENTIAL" in r or "BRAND" in r for r in rule_ids)
    print("[PASS]  test_engine_correlation_credential_phishing passed")


def test_engine_benign_correlation():
    """Test that benign signals correlate for safe emails."""
    engine = DetectionEngine()
    from backend.app.parser.email_parser import ParsedEmail
    parsed = ParsedEmail(
        sender_email="john@company.com",
        sender_name="John Smith",
        sender_domain="company.com",
        subject="Meeting Reminder",
        body_text="Hi team, meeting tomorrow at 10am.",
        headers={
            'From': 'john@company.com',
            'Authentication-Results': 'spf=pass; dkim=pass; dmarc=pass',
        },
        spf_result="pass",
        dkim_result="pass",
        dmarc_result="pass",
    )
    results = engine.analyze(parsed)
    assert results["classification"] == "SAFE"
    assert results["risk_score"] == 0.0
    print("[PASS]  test_engine_benign_correlation passed")


def test_engine_returns_confidence():
    """Test that engine returns confidence in results."""
    engine = DetectionEngine()
    from backend.app.parser.email_parser import ParsedEmail
    parsed = ParsedEmail(
        sender_email="phisher@evil.com",
        sender_name="PayPal Security",
        sender_domain="evil.com",
        subject="URGENT: Verify your account",
        body_text="Please provide your password immediately. Your account will be locked within 24 hours.",
        urls=["http://evil-login.com/verify"],
        headers={
            'From': 'phisher@evil.com',
            'Authentication-Results': 'spf=fail; dkim=fail; dmarc=fail',
        },
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail",
    )
    results = engine.analyze(parsed)
    assert "confidence_level" in results
    assert "confidence_numeric" in results
    assert results["confidence_level"] is not None
    print("[PASS]  test_engine_returns_confidence passed")


def test_engine_top_findings():
    """Test that engine returns top findings."""
    engine = DetectionEngine()
    from backend.app.parser.email_parser import ParsedEmail
    parsed = ParsedEmail(
        sender_email="phisher@evil.com",
        sender_name="PayPal Security",
        sender_domain="evil.com",
        subject="URGENT: Verify your account",
        body_text="Please provide your password immediately. Your account will be locked.",
        urls=["http://evil-login.com/verify"],
        headers={
            'From': 'phisher@evil.com',
            'Authentication-Results': 'spf=fail; dkim=fail; dmarc=fail',
        },
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail",
    )
    results = engine.analyze(parsed)
    assert "top_findings" in results
    assert len(results["top_findings"]) > 0
    assert len(results["top_findings"]) <= 5
    print("[PASS]  test_engine_top_findings passed")


# ── Risk Score Boundary Tests ──────────────────────────────────────

def test_risk_score_zero():
    """Test that clean emails score 0.

    Updated (Session 6): Session 4 added HEADER_MISSING_MESSAGE_ID (2 pts),
    so a truly clean email must now include a Message-ID header. The clean
    fixture is made RFC-plausible instead of weakening the zero assertion.
    """
    engine = DetectionEngine()
    from backend.app.parser.email_parser import ParsedEmail
    parsed = ParsedEmail(
        sender_email="john@company.com",
        sender_name="John",
        sender_domain="company.com",
        subject="Hello",
        body_text="Hi, just checking in.",
        headers={
            'From': 'john@company.com',
            'Message-ID': '<abc123@company.com>',
        },
    )
    results = engine.analyze(parsed)
    assert results["risk_score"] == 0.0
    print("[PASS]  test_risk_score_zero passed")


def test_risk_score_max():
    """Test that extremely malicious emails score near 100."""
    engine = DetectionEngine()
    from backend.app.parser.email_parser import ParsedEmail
    parsed = ParsedEmail(
        sender_email="security@paypa1-verify.com",
        sender_name="PayPal Security Team",
        sender_domain="paypa1-verify.com",
        subject="URGENT: Your account has been compromised! Verify NOW!",
        body_text="Your account will be SUSPENDED. You must ACT NOW to verify your password and credit card details within 24 hours or your account will be permanently deleted. Click here: http://192.168.1.100/verify?token=abc&session=xyz",
        urls=["http://192.168.1.100/verify?token=abc&session=xyz"],
        headers={
            'From': 'security@paypa1-verify.com',
            'Reply-To': 'scam@evil.com',
            'Authentication-Results': 'spf=fail; dkim=fail; dmarc=fail',
        },
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail",
        attachments=[{'filename': 'invoice.pdf.exe', 'content_type': 'application/x-msdownload', 'size': 51200}],
    )
    results = engine.analyze(parsed)
    assert results["risk_score"] >= 75
    assert results["classification"] == "HIGH_RISK"
    print("[PASS]  test_risk_score_max passed")


# ── Header Analyzer Tests ──────────────────────────────────────────

def test_dmarc_has_own_rule_id():
    """Test that DMARC failures use HEADER_DMARC_FAIL, not HEADER_DKIM_FAIL."""
    from detection.header_analyzer import HeaderAnalyzer
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(
        headers={'From': 'user@example.com'},
        dmarc_result='fail',
    )
    rule_ids = [f.rule_id for f in findings]
    assert "HEADER_DMARC_FAIL" in rule_ids
    assert "HEADER_DKIM_FAIL" not in rule_ids
    print("[PASS]  test_dmarc_has_own_rule_id passed")


def test_benign_auth_signals():
    """Test that passing auth generates benign signals."""
    from detection.header_analyzer import HeaderAnalyzer
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(
        headers={'From': 'user@example.com'},
        spf_result='pass',
        dkim_result='pass',
        dmarc_result='pass',
    )
    rule_ids = [f.rule_id for f in findings]
    assert "HEADER_AUTH_ALL_PASS" in rule_ids
    # Check it has negative points (benign signal)
    benign = [f for f in findings if f.rule_id == "HEADER_AUTH_ALL_PASS"]
    assert len(benign) == 1
    assert benign[0].points < 0
    print("[PASS]  test_benign_auth_signals passed")


def test_auth_alignment_check():
    """Test authentication domain alignment checking."""
    from detection.header_analyzer import HeaderAnalyzer
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(
        headers={
            'From': 'user@example.com',
            'Authentication-Results': 'mx.evil.com; spf=pass; dkim=pass; dmarc=pass',
        },
        spf_result='pass',
        dkim_result='pass',
        dmarc_result='pass',
    )
    rule_ids = [f.rule_id for f in findings]
    assert "HEADER_AUTH_DOMAIN_MISMATCH" in rule_ids
    print("[PASS]  test_auth_alignment_check passed")


# ── Run all tests ──────────────────────────────────────────────────

if __name__ == '__main__':
    test_domain_intelligence_empty()
    test_domain_intelligence_legitimate()
    test_domain_intelligence_brand_impersonation()
    test_domain_intelligence_suspicious_tld()
    test_domain_intelligence_caching()
    test_domain_intelligence_lookalike()
    test_confidence_no_findings()
    test_confidence_with_many_findings()
    test_confidence_correlation_boosts()
    test_scoring_returns_confidence()
    test_scoring_benign_signals()
    test_scoring_signal_deduplication()
    test_engine_correlation_credential_phishing()
    test_engine_benign_correlation()
    test_engine_returns_confidence()
    test_engine_top_findings()
    test_risk_score_zero()
    test_risk_score_max()
    test_dmarc_has_own_rule_id()
    test_benign_auth_signals()
    test_auth_alignment_check()
    print("\nAll new tests passed!")
