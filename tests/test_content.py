"""
Unit tests for content analysis.
Tests urgency language, credential requests, social engineering patterns.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.content_analyzer import ContentAnalyzer


def test_legitimate_content():
    """Test that normal business content produces no high-severity findings."""
    analyzer = ContentAnalyzer()
    body = """Hi team,

Please review the attached quarterly report. Let me know if you have any questions.

Best regards,
John
"""
    findings = analyzer.analyze(body)
    high_findings = [f for f in findings if f.severity in ('HIGH', 'CRITICAL')]
    assert len(high_findings) == 0, f"Legitimate content should have no HIGH findings, got: {high_findings}"
    print("[PASS]  test_legitimate_content passed")


def test_urgency_language():
    """Test detection of urgency language."""
    analyzer = ContentAnalyzer()
    body = "You must ACT NOW to verify your account within 24 hours. Do not delay."
    findings = analyzer.analyze(body)
    rule_ids = [f.rule_id for f in findings]
    assert "CONTENT_URGENCY" in rule_ids, f"Expected CONTENT_URGENCY, got: {rule_ids}"
    print("[PASS]  test_urgency_language passed")


def test_credential_request():
    """Test detection of credential request language."""
    analyzer = ContentAnalyzer()
    body = "Please provide your password and verification code to confirm your identity."
    findings = analyzer.analyze(body)
    rule_ids = [f.rule_id for f in findings]
    assert "CONTENT_CREDENTIAL_REQUEST" in rule_ids, f"Expected CONTENT_CREDENTIAL_REQUEST, got: {rule_ids}"
    print("[PASS]  test_credential_request passed")


def test_threat_language():
    """Test detection of threatening language."""
    analyzer = ContentAnalyzer()
    body = "Your account has been suspended due to unusual activity. Legal action may follow."
    findings = analyzer.analyze(body)
    rule_ids = [f.rule_id for f in findings]
    assert "CONTENT_THREAT_LANGUAGE" in rule_ids, f"Expected CONTENT_THREAT_LANGUAGE, got: {rule_ids}"
    print("[PASS]  test_threat_language passed")


def test_social_engineering():
    """Test detection of social engineering patterns."""
    analyzer = ContentAnalyzer()
    body = "Dear valued customer, click here to update your account information immediately."
    findings = analyzer.analyze(body)
    rule_ids = [f.rule_id for f in findings]
    assert "CONTENT_SOCIAL_ENGINEERING" in rule_ids, f"Expected CONTENT_SOCIAL_ENGINEERING, got: {rule_ids}"
    print("[PASS]  test_social_engineering passed")


def test_financial_scam():
    """Test detection of financial scam indicators."""
    analyzer = ContentAnalyzer()
    body = "You have won a lottery! Send money via wire transfer to claim your prize."
    findings = analyzer.analyze(body)
    rule_ids = [f.rule_id for f in findings]
    assert "CONTENT_FINANCIAL_SCAM" in rule_ids, f"Expected CONTENT_FINANCIAL_SCAM, got: {rule_ids}"
    print("[PASS]  test_financial_scam passed")


def test_urgency_credential_combo():
    """Test combination bonus for urgency + credentials."""
    analyzer = ContentAnalyzer()
    body = "URGENT: Your account will be locked. Verify your password and PIN immediately."
    findings = analyzer.analyze(body)
    rule_ids = [f.rule_id for f in findings]
    assert "CONTENT_URGENCY_CREDENTIAL_COMBO" in rule_ids, f"Expected combo detection, got: {rule_ids}"
    print("[PASS]  test_urgency_credential_combo passed")


def test_empty_content():
    """Test handling of empty content."""
    analyzer = ContentAnalyzer()
    findings = analyzer.analyze("")
    assert len(findings) == 0, f"Empty content should produce no findings, got: {len(findings)}"
    print("[PASS]  test_empty_content passed")


if __name__ == '__main__':
    test_legitimate_content()
    test_urgency_language()
    test_credential_request()
    test_threat_language()
    test_social_engineering()
    test_financial_scam()
    test_urgency_credential_combo()
    test_empty_content()
    print("\nAll content tests passed! ")


# ---- Task 3: Plural keyword regression tests ----
# Account/accounts, account number/account numbers, credit card/credit cards,
# gift card/gift cards, password/passwords, one-time password/one-time passwords.

def test_singular_and_plural_account_number():
    """Test that 'account number' and 'account numbers' are both detected."""
    analyzer = ContentAnalyzer()
    body = "Please provide your account number."
    findings = analyzer.analyze(body)
    assert "CONTENT_CREDENTIAL_REQUEST" in [f.rule_id for f in findings], \
        f"Singular 'account number' should be detected, got: {[f.rule_id for f in findings]}"
    body_plural = "Please provide your account numbers."
    findings_plural = analyzer.analyze(body_plural)
    assert "CONTENT_CREDENTIAL_REQUEST" in [f.rule_id for f in findings_plural], \
        f"Plural 'account numbers' should be detected, got: {[f.rule_id for f in findings_plural]}"
    print("[PASS]  test_singular_and_plural_account_number passed")


def test_singular_and_plural_credit_card():
    """Test that 'credit card' and 'credit cards' are both detected."""
    analyzer = ContentAnalyzer()
    body = "Please provide your credit card."
    findings = analyzer.analyze(body)
    assert "CONTENT_CREDENTIAL_REQUEST" in [f.rule_id for f in findings], \
        f"Singular 'credit card' should be detected, got: {[f.rule_id for f in findings]}"
    body_plural = "Please provide your credit cards."
    findings_plural = analyzer.analyze(body_plural)
    assert "CONTENT_CREDENTIAL_REQUEST" in [f.rule_id for f in findings_plural], \
        f"Plural 'credit cards' should be detected, got: {[f.rule_id for f in findings_plural]}"
    print("[PASS]  test_singular_and_plural_credit_card passed")


def test_singular_and_plural_gift_card():
    """Test that 'gift card' and 'gift cards' are both detected."""
    analyzer = ContentAnalyzer()
    body = "You have won a gift card!"
    findings = analyzer.analyze(body)
    assert "CONTENT_FINANCIAL_SCAM" in [f.rule_id for f in findings], \
        f"Singular 'gift card' should be detected, got: {[f.rule_id for f in findings]}"
    body_plural = "You have won gift cards!"
    findings_plural = analyzer.analyze(body_plural)
    assert "CONTENT_FINANCIAL_SCAM" in [f.rule_id for f in findings_plural], \
        f"Plural 'gift cards' should be detected, got: {[f.rule_id for f in findings_plural]}"
    print("[PASS]  test_singular_and_plural_gift_card passed")


def test_singular_and_plural_password():
    """Test that 'password' and 'passwords' are both detected."""
    analyzer = ContentAnalyzer()
    body = "Please provide your password."
    findings = analyzer.analyze(body)
    assert "CONTENT_CREDENTIAL_REQUEST" in [f.rule_id for f in findings], \
        f"Singular 'password' should be detected, got: {[f.rule_id for f in findings]}"
    body_plural = "Please provide your passwords."
    findings_plural = analyzer.analyze(body_plural)
    assert "CONTENT_CREDENTIAL_REQUEST" in [f.rule_id for f in findings_plural], \
        f"Plural 'passwords' should be detected, got: {[f.rule_id for f in findings_plural]}"
    print("[PASS]  test_singular_and_plural_password passed")


def test_singular_and_plural_one_time_password():
    """Test that 'one-time password' and 'one-time passwords' are both detected."""
    analyzer = ContentAnalyzer()
    body = "Please provide your one-time password."
    findings = analyzer.analyze(body)
    assert "CONTENT_CREDENTIAL_REQUEST" in [f.rule_id for f in findings], \
        f"Singular 'one-time password' should be detected, got: {[f.rule_id for f in findings]}"
    body_plural = "Please provide your one-time passwords."
    findings_plural = analyzer.analyze(body_plural)
    assert "CONTENT_CREDENTIAL_REQUEST" in [f.rule_id for f in findings_plural], \
        f"Plural 'one-time passwords' should be detected, got: {[f.rule_id for f in findings_plural]}"
    print("[PASS]  test_singular_and_plural_one_time_password passed")
