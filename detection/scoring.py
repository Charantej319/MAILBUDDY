"""
Risk scoring engine with explainable weighted scoring.
Combines findings from all analyzers into a 0-100 risk score with confidence.

Features:
- Evidence-weighted scoring per category
- Anti-double-counting for correlated signals
- Benign signal support (negative points)
- Confidence calculation based on evidence richness
- Cross-signal correlation awareness
"""

from .rules import Category, CATEGORY_WEIGHTS, classify_risk, calculate_confidence, Finding


class RiskScorer:
    """
    Calculates risk score from findings with category-level capping,
    signal correlation, and confidence calculation.
    """

    def __init__(self):
        self.category_weights = CATEGORY_WEIGHTS.copy()

    def calculate_score(self, findings: list[Finding], has_intel: bool = False) -> tuple[float, str, list[dict], str, float]:
        """
        Calculate risk score from findings.

        Returns:
            (score, classification, findings_list, confidence_level, confidence_numeric)
        """
        # Phase 1: Anti-double-counting
        deduplicated = self._deduplicate_correlated_signals(findings)

        # Phase 2: Accumulate by category with capping
        category_totals: dict[Category, float] = {cat: 0.0 for cat in Category}

        for finding in deduplicated:
            cat = finding.category
            category_totals[cat] += finding.points

        # Cap each category at its maximum
        total_score = 0.0
        for cat, subtotal in category_totals.items():
            max_weight = self.category_weights.get(cat, 5)
            # Allow negative scores within a category (benign signals)
            capped = max(min(subtotal, max_weight), -5)
            total_score += capped

        # Final cap at 0-100
        total_score = max(0.0, min(total_score, 100.0))

        classification = classify_risk(total_score)

        # Phase 3: Calculate confidence
        confidence_level, confidence_numeric = calculate_confidence(deduplicated, has_intel)

        # Build findings list as dicts
        findings_dicts = [f.to_dict() for f in deduplicated]

        return total_score, classification, findings_dicts, confidence_level, confidence_numeric

    def _deduplicate_correlated_signals(self, findings: list[Finding]) -> list[Finding]:
        """
        Prevent double-counting of correlated signals.

        Example: SPF fail + DMARC fail + auth failure represent the same
        underlying problem. We reduce the combined penalty.
        """
        if not findings:
            return findings

        # Group authentication-related findings
        auth_findings = []
        other_findings = []

        auth_rule_prefixes = ('HEADER_SPF', 'HEADER_DKIM', 'HEADER_DMARC', 'HEADER_MULTIPLE_AUTH')

        for f in findings:
            if any(f.rule_id.startswith(p) for p in auth_rule_prefixes):
                auth_findings.append(f)
            else:
                other_findings.append(f)

        # If multiple auth failures, reduce individual penalties
        if len(auth_findings) > 1:
            # Keep the highest-severity auth finding at full points
            # Reduce others by 40% to account for correlation
            auth_findings.sort(key=lambda f: f.points, reverse=True)
            adjusted = []
            for i, f in enumerate(auth_findings):
                if i == 0:
                    adjusted.append(f)
                else:
                    # Create adjusted copy with reduced points
                    reduced_points = f.points * 0.6
                    adjusted_finding = Finding(
                        rule_id=f.rule_id,
                        category=f.category,
                        severity=f.severity,
                        points=round(reduced_points, 1),
                        message=f.message,
                        evidence=f.evidence,
                        explanation=f.explanation,
                        source=f.source,
                    )
                    adjusted.append(adjusted_finding)
            auth_findings = adjusted

        return other_findings + auth_findings
