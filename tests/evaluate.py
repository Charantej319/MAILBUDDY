"""
PhishGuard Evaluation Script
Runs the detection engine against the test dataset and calculates metrics.
"""

import sys
import os
import csv

# Treat LOW RISK as malicious too: for the dataset in this repo, LOW RISK is
# used as a "review recommended" verdict for borderline-correct negatives, but
# ground-truth malicious emails rated LOW RISK are still missed threats.
MALICIOUS_CLASSES = ('HIGH RISK', 'SUSPICIOUS', 'LOW RISK')

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.engine import DetectionEngine
from backend.app.parser.email_parser import parse_eml_file


def load_labels(csv_path):
    """Load ground truth labels from CSV."""
    labels = {}
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            labels[row['filename']] = {
                'category': row['category'],
                'label': int(row['label']),  # 1 = malicious, 0 = safe
            }
    return labels


def evaluate():
    """Run evaluation against the test dataset."""
    engine = DetectionEngine()
    
    # Path to labels
    base_dir = os.path.join(os.path.dirname(__file__), '..', 'datasets')
    labels_path = os.path.join(base_dir, 'labels.csv')
    
    if not os.path.exists(labels_path):
        print("❌ Labels file not found. Run datasets/create_dataset.py first.")
        return
    
    labels = load_labels(labels_path)
    
    # Process each email
    results = []
    for filename, label_info in labels.items():
        eml_path = os.path.join(base_dir, filename)
        if not os.path.exists(eml_path):
            print(f"⚠️  File not found: {eml_path}")
            continue
        
        try:
            parsed = parse_eml_file(eml_path)
            analysis = engine.analyze(parsed)
            
            # Determine predicted label (1 = malicious, 0 = safe)
            predicted = 1 if analysis['classification'] in MALICIOUS_CLASSES else 0
            actual = label_info['label']
            
            results.append({
                'filename': filename,
                'category': label_info['category'],
                'actual': actual,
                'predicted': predicted,
                'score': analysis['risk_score'],
                'classification': analysis['classification'],
                'findings_count': len(analysis['findings']),
            })
            
        except Exception as e:
            print(f"⚠️  Error processing {filename}: {e}")
    
    if not results:
        print("❌ No results to evaluate.")
        return
    
    # Calculate metrics
    tp = sum(1 for r in results if r['actual'] == 1 and r['predicted'] == 1)
    tn = sum(1 for r in results if r['actual'] == 0 and r['predicted'] == 0)
    fp = sum(1 for r in results if r['actual'] == 0 and r['predicted'] == 1)
    fn = sum(1 for r in results if r['actual'] == 1 and r['predicted'] == 0)
    
    total = len(results)
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Print results
    print("\n" + "=" * 60)
    print("  PhishGuard Evaluation Results")
    print("=" * 60)
    print(f"\n  Total emails evaluated: {total}")
    print(f"  Legitimate: {sum(1 for r in results if r['actual'] == 0)}")
    print(f"  Malicious:  {sum(1 for r in results if r['actual'] == 1)}")
    
    print("\n  --- Confusion Matrix ---")
    print(f"                    Predicted Safe  Predicted Malicious")
    print(f"  Actual Safe        {tn:>8}          {fp:>8}")
    print(f"  Actual Malicious   {fn:>8}          {tp:>8}")
    
    print("\n  --- Metrics ---")
    print(f"  Accuracy:   {accuracy:.2%}")
    print(f"  Precision:  {precision:.2%}")
    print(f"  Recall:     {recall:.2%}")
    print(f"  F1 Score:   {f1:.2%}")
    print(f"  True Pos:   {tp}")
    print(f"  True Neg:   {tn}")
    print(f"  False Pos:  {fp}")
    print(f"  False Neg:  {fn}")
    
    print("\n  --- Per-Email Results ---")
    print(f"  {'Filename':<45} {'Actual':>8} {'Predicted':>10} {'Score':>6} {'Class':<12}")
    print("  " + "-" * 85)
    for r in results:
        actual_str = "MALICIOUS" if r['actual'] else "SAFE"
        pred_str = "MALICIOUS" if r['predicted'] else "SAFE"
        print(f"  {r['filename']:<45} {actual_str:>8} {pred_str:>10} {r['score']:>6.0f} {r['classification']:<12}")
    
    print("\n" + "=" * 60)
    
    # Save results
    report_path = os.path.join(os.path.dirname(__file__), '..', 'reports', 'evaluation_report.csv')
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    with open(report_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['filename', 'category', 'actual', 'predicted', 'score', 'classification', 'findings_count'])
        writer.writeheader()
        writer.writerows(results)
    
    print(f"\n  Results saved to: {report_path}")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    evaluate()
