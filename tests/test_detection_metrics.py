"""
Detection-engine evaluation tests.

Runs the detection engine over the labeled dataset (datasets/labels.csv) and
asserts measurable quality thresholds. These tests FAIL if detection regresses
— preventing silent accuracy drops and preventing "fake improvements" (any
change to rules must keep these metrics green).

Label semantics: malicious == (HIGH RISK | SUSPICIOUS | LOW RISK)
LOW RISK is treated as "review recommended"; a ground-truth malicious email
rated LOW RISK still counts as detected, while SAFE counts as missed.
"""

import sys
import os
import csv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.engine import DetectionEngine
from detection.rules import is_risky_level, RiskLevel
from backend.app.parser.email_parser import parse_eml_file

MALICIOUS_CLASSES = ('HIGH_RISK', 'SUSPICIOUS', 'LOW_RISK')


def _load_dataset():
    base_dir = os.path.join(os.path.dirname(__file__), '..', 'datasets')
    labels_path = os.path.join(base_dir, 'labels.csv')
    if not os.path.exists(labels_path):
        return []
    rows = []
    with open(labels_path, 'r') as f:
        for row in csv.DictReader(f):
            eml_path = os.path.join(base_dir, row['filename'])
            if os.path.exists(eml_path):
                rows.append((row['filename'], int(row['label']), eml_path))
    return rows


def _run_evaluation():
    rows = _load_dataset()
    if not rows:
        return None
    engine = DetectionEngine()
    results = []
    for filename, label, eml_path in rows:
        parsed = parse_eml_file(eml_path)
        analysis = engine.analyze(parsed)
        predicted = 1 if analysis['classification'] in MALICIOUS_CLASSES else 0
        results.append({
            'filename': filename,
            'label': label,
            'predicted': predicted,
            'score': analysis['risk_score'],
            'classification': analysis['classification'],
            'confidence': analysis['confidence_numeric'],
        })
    return results


def _confusion(results):
    tp = sum(1 for r in results if r['label'] == 1 and r['predicted'] == 1)
    tn = sum(1 for r in results if r['label'] == 0 and r['predicted'] == 0)
    fp = sum(1 for r in results if r['label'] == 0 and r['predicted'] == 1)
    fn = sum(1 for r in results if r['label'] == 1 and r['predicted'] == 0)
    return tp, tn, fp, fn


def test_dataset_exists_and_is_nontrivial():
    rows = _load_dataset()
    assert len(rows) >= 20, f"Dataset too small: {len(rows)} emails"
    labels = {label for _, label, _ in rows}
    assert labels == {0, 1}, "Dataset must contain both legitimate and malicious samples"
    print("[PASS]  test_dataset_exists_and_is_nontrivial passed")


def test_metrics_meet_minimum_thresholds():
    """Accuracy ≥ 85%, precision ≥ 90%, recall ≥ 85%, FPR ≤ 10%."""
    results = _run_evaluation()
    assert results, "Dataset could not be loaded"
    tp, tn, fp, fn = _confusion(results)
    total = len(results)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    fnr = fn / (fn + tp) if fn + tp else 0

    print(f"\n  Confusion matrix: TP={tp} TN={tn} FP={fp} FN={fn}")
    print(f"  Accuracy={accuracy:.2%} Precision={precision:.2%} "
          f"Recall={recall:.2%} FPR={fpr:.2%} FNR={fnr:.2%}")

    assert accuracy >= 0.85, f"Accuracy regressed: {accuracy:.2%}"
    assert precision >= 0.90, f"Precision regressed: {precision:.2%}"
    assert recall >= 0.85, f"Recall regressed: {recall:.2%}"
    assert fpr <= 0.10, f"False-positive rate too high: {fpr:.2%}"
    print("[PASS]  test_metrics_meet_minimum_thresholds passed")


def test_legitimate_password_reset_not_flagged():
    """
    False-positive guard: a legitimate password-reset email from the real
    domain must never be classified HIGH RISK.
    """
    results = _run_evaluation()
    target = next(r for r in results if r['filename'].endswith('support_reply.eml'))
    assert target['classification'] != RiskLevel.HIGH_RISK, \
        f"Legitimate password reset flagged as {target['classification']} (score {target['score']})"
    print("[PASS]  test_legitimate_password_reset_not_flagged passed")


def test_credential_phishing_detected():
    """False-negative guard: core credential phishing must never be missed."""
    results = _run_evaluation()
    must_detect = (
        'bank_phishing.eml',
        'microsoft_credential_phishing.eml',
        'google_credential_phishing.eml',
    )
    for r in results:
        for marker in must_detect:
            if r['filename'].endswith(marker):
                assert r['predicted'] == 1, \
                    f"{marker} missed: {r['classification']} (score {r['score']})"
    print("[PASS]  test_credential_phishing_detected passed")


def test_classification_bounds_and_confidence_range():
    """Every analysis must produce a bounded score and valid confidence."""
    results = _run_evaluation()
    for r in results:
        assert 0.0 <= r['score'] <= 100.0, f"Score out of bounds: {r['score']}"
        assert 0.0 <= r['confidence'] <= 1.0, f"Confidence out of bounds: {r['confidence']}"
        assert r['classification'] in ('SAFE', 'LOW_RISK', 'SUSPICIOUS', 'HIGH_RISK')
    print("[PASS]  test_classification_bounds_and_confidence_range passed")


if __name__ == '__main__':
    test_dataset_exists_and_is_nontrivial()
    test_metrics_meet_minimum_thresholds()
    test_legitimate_password_reset_not_flagged()
    test_credential_phishing_detected()
    test_classification_bounds_and_confidence_range()
    print("\nAll detection metrics tests passed!")
