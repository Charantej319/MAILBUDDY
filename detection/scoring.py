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

from .rules import (
    Category,
    CATEGORY_WEIGHTS,
    classify_risk,
    risk_display_label,
    calculate_confidence,
    severity_rank,
    Finding,
)


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

        # Composite authentication severity floor (F-6).
        #
        # The HEADER category cap (20) can compress the combined evidence of
        # SPF fail + DKIM fail + DMARC fail (+ HEADER_MULTIPLE_AUTH_FAILURES)
        # so far that a wholly unauthenticated message classified SAFE. The
        # floor lifts the total to a justified MINIMUM for that specific
        # combination without removing category caps:
        #
        #   header findings → HEADER cap → auth floor → final score (0-100)
        #
        # Justification of the floor value (from this architecture): three
        # explicit hard failures are the strongest header-only evidence of
        # spoofing this engine can observe. SUSPICIOUS begins at 50, and the
        # pre-floor capped total for the classic fail/fail/fail + multiple-
        # failures combination is ~20 (SPF 8 + DKIM 7 + DMARC 8 = 23, minus
        # the auth-dedup 0.6 downweight ≈ 14, plus multiple-failures 10,
        # capped at HEADER 20). A floor of 50 therefore guarantees the
        # combination can never be scored SAFE (score < 25) or LOW RISK
        # (< 50) while staying at the SUSPICIOUS boundary — the remaining
        # distance to HIGH RISK must come from OTHER corroborating evidence
        # (sender, URL, content), which preserves the scoring architecture:
        # header failures alone are suspicious, not automatically HIGH.
        #
        # Scope guards (all deliberate):
        #   - only EXPLICIT 'fail' verdicts count; softfail/neutral/none/
        #     temperror/permerror never activate the floor (F-5 contract);
        #   - fewer than three hard failures never activate it (single SPF
        #     failure stays proportional); no 'none' state is treated as a
        #     failure;
        #   - the floor never EXCEEDS the pre-floor score (it only raises),
        #   - the 0-100 final ceiling still applies afterwards.
        _AUTH_FAIL_RULES = {"HEADER_SPF_FAIL", "HEADER_DKIM_FAIL", "HEADER_DMARC_FAIL"}
        present_fail_rules = {f.rule_id for f in deduplicated if f.rule_id in _AUTH_FAIL_RULES}
        if len(present_fail_rules) >= 3:
            floor = 50.0
            if total_score < floor:
                total_score = floor

        # Final cap at 0-100
        total_score = max(0.0, min(total_score, 100.0))

        # F-21: canonical machine-form classification (HIGH_RISK). The API
        # layer renders risk_display_label() for the human-readable form.
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
        underlying problem. We reduce the combined penalty. The same underlying
        mismatch (e.g. From/Reply-To and From/Return-Path disagreeing with the
        sender domain) contributes ONE scoring entry, the highest-severity copy
        at full points; overlapping sibling findings are kept as evidence only.
        """
        if not findings:
            return findings

        # --- Canonical mismatch identity: SENDER_REPLY_TO_MISMATCH and
        # --- SENDER_RETURN_PATH_MISMATCH share one underlying event. Collate
        # --- by (rule_id, dedup_key); the strongest-severity copy survives at
        # --- full points and weaker duplicates are dropped entirely.
        canonical = {}
        others = []

        for f in findings:
            if f.rule_id == "SENDER_REPLY_TO_MISMATCH" and f.dedup_key:
                key = (f.rule_id, f.dedup_key)
                winner = canonical.get(key)
                # F-9: numeric severity comparison — alphabetical string
                # ordering would let "HIGH" (>=) replace a CRITICAL finding.
                # The strictly stronger copy becomes the stored winner at its
                # own full points; equal/weaker copies are dropped (never
                # merged into a mixed-identity row and never double-counted).
                if winner is None or severity_rank(f.severity) > severity_rank(winner.severity):
                    canonical[key] = f
            else:
                others.append(f)

        # Keep each canonical mismatch once at full points, drop duplicates.
        deduplicated = list(others)
        for key, f in canonical.items():
            deduplicated.append(f)

        # --- Cross-analyzer brand consolidation (F-1) ----------------------
        # SENDER_BRAND_IMPERSONATION, SENDER_LOOKALIKE_DOMAIN,
        # INTEL_BRAND_IMPERSONATION, INTEL_LOOKALIKE_DOMAIN,
        # URL_LOOKALIKE_DOMAIN and SENDER_NAME_DOMAIN_MISMATCH can all fire
        # for the SAME domain↔brand relationship (multiple analyzers
        # noticing one condition). Findings sharing a brand dedup_key
        # describe one underlying event: keep the strongest at full points,
        # downweight the other copies so the condition scores ONCE while the
        # evidence stays visible.
        BRAND_RULES = {
            "SENDER_BRAND_IMPERSONATION",
            "SENDER_LOOKALIKE_DOMAIN",
            "INTEL_BRAND_IMPERSONATION",
            "INTEL_LOOKALIKE_DOMAIN",
            "URL_LOOKALIKE_DOMAIN",
            "SENDER_NAME_DOMAIN_MISMATCH",
        }
        brand_group: dict[str, Finding] = {}
        rest: list[Finding] = []
        for f in deduplicated:
            if f.rule_id in BRAND_RULES and f.dedup_key:
                key = f.dedup_key.lower()
                winner = brand_group.get(key)
                if winner is None:
                    brand_group[key] = f
                # F-9: numeric comparison — HIGH must not replace CRITICAL.
                elif severity_rank(f.severity) > severity_rank(winner.severity):
                    brand_group[key] = f
                # equal/lower severity: keep the first (winner) copy
            else:
                rest.append(f)
        if brand_group:
            consolidated = list(rest)
            for key, winner in brand_group.items():
                consolidated.append(winner)
                # Downweight the overlapping copies (evidence retained).
                for f in deduplicated:
                    if (
                        f is not winner
                        and f.rule_id in BRAND_RULES
                        and f.dedup_key
                        and f.dedup_key.lower() == key
                    ):
                        consolidated.append(Finding(
                            rule_id=f.rule_id,
                            category=f.category,
                            severity=f.severity,
                            points=round(f.points * 0.4, 1),
                            message=f.message,
                            evidence=f.evidence,
                            explanation=f.explanation,
                            source=f.source,
                            dedup_key=f.dedup_key,
                        ))
            deduplicated = consolidated

        # If multiple auth findings still correlate, reduce the non-top ones.
        if len(deduplicated) > 1:
            auth_findings = [f for f in deduplicated
                             if any(f.rule_id.startswith(p)
                                    for p in ('HEADER_SPF', 'HEADER_DKIM',
                                              'HEADER_DMARC', 'HEADER_MULTIPLE_AUTH'))]
            other_findings = [f for f in deduplicated
                              if f not in auth_findings]
            if len(auth_findings) > 1:
                auth_findings.sort(key=lambda f: f.points, reverse=True)
                adjusted = [auth_findings[0]]
                for f in auth_findings[1:]:
                    adjusted.append(Finding(
                        rule_id=f.rule_id,
                        category=f.category,
                        severity=f.severity,
                        points=round(f.points * 0.6, 1),
                        message=f.message,
                        evidence=f.evidence,
                        explanation=f.explanation,
                        source=f.source,
                    ))
                deduplicated = other_findings + adjusted

        return deduplicated
