"""
Unit tests for URL analysis.
Tests IP URLs, shorteners, suspicious TLDs, lookalike domains, etc.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.url_analyzer import URLAnalyzer


def test_legitimate_url():
    """Test that a legitimate HTTPS URL produces no high-severity findings."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["https://www.google.com/search?q=hello"])
    high_findings = [f for f in findings if f.severity in ('HIGH', 'CRITICAL')]
    assert len(high_findings) == 0, f"Legitimate URL should have no HIGH findings, got: {high_findings}"
    print("[PASS]  test_legitimate_url passed")


def test_ip_address_url():
    """Test detection of IP address in URL."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["http://192.168.1.100/phishing"])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_IP_ADDRESS" in rule_ids, f"Expected URL_IP_ADDRESS, got: {rule_ids}"
    print("[PASS]  test_ip_address_url passed")


def test_url_shortener():
    """Test detection of URL shortener."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["https://bit.ly/3abc123"])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_SHORTENER" in rule_ids, f"Expected URL_SHORTENER, got: {rule_ids}"
    print("[PASS]  test_url_shortener passed")


def test_suspicious_tld():
    """Test detection of suspicious TLD."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["https://secure-login.xyz/verify"])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_SUSPICIOUS_TLD" in rule_ids, f"Expected URL_SUSPICIOUS_TLD, got: {rule_ids}"
    print("[PASS]  test_suspicious_tld passed")


def test_long_url():
    """Test detection of excessively long URL."""
    analyzer = URLAnalyzer()
    long_url = "https://example.com/" + "a" * 200
    findings = analyzer.analyze([long_url])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_LONG" in rule_ids, f"Expected URL_LONG, got: {rule_ids}"
    print("[PASS]  test_long_url passed")


def test_excessive_subdomains():
    """Test detection of excessive subdomains."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["https://a.b.c.d.e.example.com/phish"])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_EXCESSIVE_SUBDOMAINS" in rule_ids, f"Expected URL_EXCESSIVE_SUBDOMAINS, got: {rule_ids}"
    print("[PASS]  test_excessive_subdomains passed")


def test_suspicious_path():
    """Test detection of suspicious URL path."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["https://example.com/login/verify"])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_SUSPICIOUS_PATH" in rule_ids, f"Expected URL_SUSPICIOUS_PATH, got: {rule_ids}"
    print("[PASS]  test_suspicious_path passed")


def test_lookalike_domain():
    """Test detection of lookalike domain impersonating a brand."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["https://paypai-secure.com/login"])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_LOOKALIKE_DOMAIN" in rule_ids, f"Expected URL_LOOKALIKE_DOMAIN, got: {rule_ids}"
    print("[PASS]  test_lookalike_domain passed")


def test_http_url():
    """Test detection of HTTP (non-HTTPS) URL."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["http://example.com/page"])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_HTTP" in rule_ids, f"Expected URL_HTTP, got: {rule_ids}"
    print("[PASS]  test_http_url passed")


def test_obfuscated_url():
    """Test detection of URL-encoded obfuscation."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["https://example.com/%6C%6F%67%69%6E"])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_OBFUSCATED" in rule_ids, f"Expected URL_OBFUSCATED, got: {rule_ids}"
    print("[PASS]  test_obfuscated_url passed")


def test_credentials_in_url():
    """Test detection of username/password in URL."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["https://user:pass@example.com/"])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_CREDENTIALS_IN_URL" in rule_ids, f"Expected URL_CREDENTIALS_IN_URL, got: {rule_ids}"
    print("[PASS]  test_credentials_in_url passed")


def test_explicit_port():
    """Test detection of explicit non-standard port."""
    analyzer = URLAnalyzer()
    findings = analyzer.analyze(["https://example.com:8443/phish"])
    rule_ids = [f.rule_id for f in findings]
    assert "URL_EXPLICIT_PORT" in rule_ids, f"Expected URL_EXPLICIT_PORT, got: {rule_ids}"
    print("[PASS]  test_explicit_port passed")


if __name__ == '__main__':
    test_legitimate_url()
    test_ip_address_url()
    test_url_shortener()
    test_suspicious_tld()
    test_long_url()
    test_excessive_subdomains()
    test_suspicious_path()
    test_lookalike_domain()
    test_http_url()
    test_obfuscated_url()
    test_credentials_in_url()
    test_explicit_port()
    print("\nAll URL tests passed! ")
