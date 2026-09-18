"""
Unit tests for header analysis.
Tests SPF, DKIM, DMARC failures, authentication anomalies.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.header_analyzer import HeaderAnalyzer


def test_all_auth_pass():
    """Test that passing authentication produces no high-severity findings."""
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(
        headers={
            'From': 'user@example.com',
            'Reply-To': 'user@example.com',
            'Message-ID': '<test@example.com>',
        },
        spf_result='pass',
        dkim_result='pass',
        dmarc_result='pass',
    )
    high_findings = [f for f in findings if f.severity in ('HIGH', 'CRITICAL')]
    assert len(high_findings) == 0, f"Passing auth should have no HIGH findings, got: {high_findings}"
    print("[PASS]  test_all_auth_pass passed")


def test_spf_fail():
    """Test detection of SPF failure."""
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(
        headers={'From': 'user@phishing.com'},
        spf_result='fail',
    )
    rule_ids = [f.rule_id for f in findings]
    assert "HEADER_SPF_FAIL" in rule_ids, f"Expected HEADER_SPF_FAIL, got: {rule_ids}"
    print("[PASS]  test_spf_fail passed")


def test_spf_softfail():
    """Test detection of SPF softfail."""
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(
        headers={'From': 'user@example.com'},
        spf_result='softfail',
    )
    rule_ids = [f.rule_id for f in findings]
    assert "HEADER_SPF_SOFTFAIL" in rule_ids, f"Expected HEADER_SPF_SOFTFAIL, got: {rule_ids}"
    print("[PASS]  test_spf_softfail passed")


def test_dkim_fail():
    """Test detection of DKIM failure."""
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(
        headers={'From': 'user@example.com'},
        dkim_result='fail',
    )
    rule_ids = [f.rule_id for f in findings]
    assert "HEADER_DKIM_FAIL" in rule_ids, f"Expected HEADER_DKIM_FAIL, got: {rule_ids}"
    print("[PASS]  test_dkim_fail passed")


def test_dmarc_fail():
    """Test detection of DMARC failure."""
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(
        headers={'From': 'user@example.com'},
        dmarc_result='fail',
    )
    rule_ids = [f.rule_id for f in findings]
    assert "HEADER_DMARC_FAIL" in rule_ids, f"Expected HEADER_DMARC_FAIL for DMARC fail, got: {rule_ids}"
    print("[PASS]  test_dmarc_fail passed")


def test_from_replyto_mismatch():
    """Test detection of From/Reply-To domain mismatch."""
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(
        headers={
            'From': 'alerts@legitbank.com',
            'Reply-To': 'support@phishing-domain.com',
        },
    )
    rule_ids = [f.rule_id for f in findings]
    assert "HEADER_FROM_REPLYTO_MISMATCH" in rule_ids, f"Expected HEADER_FROM_REPLYTO_MISMATCH, got: {rule_ids}"
    print("[PASS]  test_from_replyto_mismatch passed")


def test_multiple_auth_failures():
    """Test detection of multiple authentication failures."""
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(
        headers={
            'Authentication-Results': 'mx.google.com; spf=fail; dkim=fail; dmarc=fail',
        },
        spf_result='fail',
        dkim_result='fail',
        dmarc_result='fail',
    )
    rule_ids = [f.rule_id for f in findings]
    assert "HEADER_MULTIPLE_AUTH_FAILURES" in rule_ids, f"Expected multiple auth failure detection, got: {rule_ids}"
    print("[PASS]  test_multiple_auth_failures passed")


if __name__ == '__main__':
    test_all_auth_pass()
    test_spf_fail()
    test_spf_softfail()
    test_dkim_fail()
    test_dmarc_fail()
    test_from_replyto_mismatch()
    test_multiple_auth_failures()
    print("\nAll header tests passed! ")
