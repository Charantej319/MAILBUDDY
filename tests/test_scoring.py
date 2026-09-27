"""
Unit tests for risk scoring engine.
Tests score calculation, classification, and category capping.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.scoring import RiskScorer, Finding
from detection.rules import Category, classify_risk, RiskLevel


def test_safe_classification():
    """Test that low scores are classified as SAFE."""
    assert classify_risk(0) == "SAFE"
    assert classify_risk(10) == "SAFE"
    assert classify_risk(24) == "SAFE"
    print("[PASS]  test_safe_classification passed")


def test_low_risk_classification():
    """Test that medium-low scores are classified as LOW RISK."""
    assert classify_risk(25) == RiskLevel.LOW_RISK
    assert classify_risk(35) == RiskLevel.LOW_RISK
    assert classify_risk(49) == RiskLevel.LOW_RISK
    print("[PASS]  test_low_risk_classification passed")


def test_suspicious_classification():
    """Test that medium-high scores are classified as SUSPICIOUS."""
    assert classify_risk(50) == "SUSPICIOUS"
    assert classify_risk(60) == "SUSPICIOUS"
    assert classify_risk(74) == "SUSPICIOUS"
    print("[PASS]  test_suspicious_classification passed")


def test_high_risk_classification():
    """Test that high scores are classified as HIGH RISK."""
    assert classify_risk(75) == RiskLevel.HIGH_RISK
    assert classify_risk(90) == RiskLevel.HIGH_RISK
    assert classify_risk(100) == RiskLevel.HIGH_RISK
    print("[PASS]  test_high_risk_classification passed")


def test_no_findings():
    """Test that no findings produces score 0."""
    scorer = RiskScorer()
    score, classification, findings, conf_level, conf_num = scorer.calculate_score([])
    assert score == 0.0, f"Expected 0, got {score}"
    assert classification == "SAFE", f"Expected SAFE, got {classification}"
    print("[PASS]  test_no_findings passed")


def test_single_finding():
    """Test scoring with a single finding."""
    scorer = RiskScorer()
    findings = [Finding(
        rule_id="TEST_RULE",
        category=Category.SENDER,
        severity="HIGH",
        points=10,
        message="Test finding",
    )]
    score, classification, _, _, _ = scorer.calculate_score(findings)
    assert score == 10.0, f"Expected 10, got {score}"
    assert classification == "SAFE", f"Expected SAFE, got {classification}"
    print("[PASS]  test_single_finding passed")


def test_category_capping():
    """Test that categories are capped at their maximum."""
    scorer = RiskScorer()
    # Create findings that would exceed sender category cap (20)
    findings = [
        Finding(rule_id=f"RULE_{i}", category=Category.SENDER, severity="HIGH", points=15, message=f"Finding {i}")
        for i in range(3)
    ]
    score, classification, _, _, _ = scorer.calculate_score(findings)
    # 3 findings * 15 points = 45, but capped at 20 for sender category
    assert score == 20.0, f"Expected 20 (capped), got {score}"
    print("[PASS]  test_category_capping passed")


def test_max_score_cap():
    """Test that total score is capped at 100."""
    scorer = RiskScorer()
    # Create many high-scoring findings across all categories
    findings = []
    for cat in Category:
        for i in range(5):
            findings.append(Finding(
                rule_id=f"{cat.value}_RULE_{i}",
                category=cat,
                severity="HIGH",
                points=20,
                message=f"Finding {i}",
            ))
    score, classification, _, _, _ = scorer.calculate_score(findings)
    assert score == 100.0, f"Expected 100 (max cap), got {score}"
    assert classification == RiskLevel.HIGH_RISK, f"Expected HIGH_RISK, got {classification}"
    print("[PASS]  test_max_score_cap passed")


def test_mixed_findings():
    """Test scoring with mixed severity findings."""
    scorer = RiskScorer()
    findings = [
        Finding(rule_id="URL_SHORTENER", category=Category.URL, severity="MEDIUM", points=7, message="Shortener"),
        Finding(rule_id="SENDER_MISMATCH", category=Category.SENDER, severity="HIGH", points=15, message="Mismatch"),
        Finding(rule_id="CONTENT_URGENCY", category=Category.CONTENT, severity="MEDIUM", points=5, message="Urgency"),
    ]
    score, classification, findings_list, _, _ = scorer.calculate_score(findings)
    assert score == 27.0, f"Expected 27 (7+15+5), got {score}"
    assert classification == RiskLevel.LOW_RISK, f"Expected LOW_RISK, got {classification}"
    assert len(findings_list) == 3, f"Expected 3 findings in output, got {len(findings_list)}"
    print("[PASS]  test_mixed_findings passed")


if __name__ == '__main__':
    test_safe_classification()
    test_low_risk_classification()
    test_suspicious_classification()
    test_high_risk_classification()
    test_no_findings()
    test_single_finding()
    test_category_capping()
    test_max_score_cap()
    test_mixed_findings()
    print("\nAll scoring tests passed! ")
