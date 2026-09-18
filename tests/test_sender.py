"""
Unit tests for sender and domain analysis.
Tests lookalike domains, brand impersonation, name mismatches, etc.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.sender import SenderAnalyzer


def test_legitimate_sender():
    """Test that a legitimate sender produces no high-severity findings."""
    analyzer = SenderAnalyzer()
    findings = analyzer.analyze(
        sender_email="john@acmecorp.com",
        sender_name="John Smith",
        sender_domain="acmecorp.com",
    )
    high_findings = [f for f in findings if f.severity in ('HIGH', 'CRITICAL')]
    assert len(high_findings) == 0, f"Legitimate sender should have no HIGH findings, got: {high_findings}"
    print("[PASS]  test_legitimate_sender passed")


def test_display_name_domain_mismatch():
    """Test detection when display name references a brand not in the domain."""
    analyzer = SenderAnalyzer()
    findings = analyzer.analyze(
        sender_email="alerts@secure-banking-xyz.com",
        sender_name="PayPal Security Team",
        sender_domain="secure-banking-xyz.com",
    )
    rule_ids = [f.rule_id for f in findings]
    assert "SENDER_NAME_DOMAIN_MISMATCH" in rule_ids, f"Expected SENDER_NAME_DOMAIN_MISMATCH, got: {rule_ids}"
    print("[PASS]  test_display_name_domain_mismatch passed")


def test_brand_impersonation():
    """Test detection of brand name in non-official domain."""
    analyzer = SenderAnalyzer()
    findings = analyzer.analyze(
        sender_email="support@paypai-secure.com",
        sender_name="PayPal Support",
        sender_domain="paypai-secure.com",
    )
    rule_ids = [f.rule_id for f in findings]
    assert "SENDER_BRAND_IMPERSONATION" in rule_ids, f"Expected SENDER_BRAND_IMPERSONATION, got: {rule_ids}"
    print("[PASS]  test_brand_impersonation passed")


def test_homoglyph_domain():
    """Test detection of character substitutions in domain."""
    analyzer = SenderAnalyzer()
    findings = analyzer.analyze(
        sender_email="admin@microsoft-0nline.com",
        sender_name="Microsoft Admin",
        sender_domain="microsoft-0nline.com",
    )
    rule_ids = [f.rule_id for f in findings]
    # Should detect the homoglyph '0' for 'o'
    has_homoglyph = any('HOMOGLYPH' in r for r in rule_ids)
    has_brand = "SENDER_BRAND_IMPERSONATION" in rule_ids
    assert has_homoglyph or has_brand, f"Expected homoglyph or brand detection, got: {rule_ids}"
    print("[PASS]  test_homoglyph_domain passed")


def test_suspicious_tld():
    """Test detection of suspicious TLD."""
    analyzer = SenderAnalyzer()
    findings = analyzer.analyze(
        sender_email="user@example.xyz",
        sender_name="Example User",
        sender_domain="example.xyz",
    )
    rule_ids = [f.rule_id for f in findings]
    assert "SENDER_SUSPICIOUS_DOMAIN" in rule_ids, f"Expected SENDER_SUSPICIOUS_DOMAIN, got: {rule_ids}"
    print("[PASS]  test_suspicious_tld passed")


def test_reply_to_mismatch():
    """Test detection of From/Reply-To domain mismatch."""
    analyzer = SenderAnalyzer()
    findings = analyzer.analyze(
        sender_email="alerts@legitbank.com",
        sender_name="Legit Bank",
        sender_domain="legitbank.com",
        reply_to="support@phishing-domain.com",
    )
    rule_ids = [f.rule_id for f in findings]
    assert "SENDER_REPLY_TO_MISMATCH" in rule_ids, f"Expected SENDER_REPLY_TO_MISMATCH, got: {rule_ids}"
    print("[PASS]  test_reply_to_mismatch passed")


def test_missing_sender():
    """Test handling of missing sender."""
    analyzer = SenderAnalyzer()
    findings = analyzer.analyze(
        sender_email="",
        sender_name="",
        sender_domain="",
    )
    rule_ids = [f.rule_id for f in findings]
    assert "SENDER_MISSING" in rule_ids, f"Expected SENDER_MISSING, got: {rule_ids}"
    print("[PASS]  test_missing_sender passed")


if __name__ == '__main__':
    test_legitimate_sender()
    test_display_name_domain_mismatch()
    test_brand_impersonation()
    test_homoglyph_domain()
    test_suspicious_tld()
    test_reply_to_mismatch()
    test_missing_sender()
    print("\nAll sender tests passed! ")
