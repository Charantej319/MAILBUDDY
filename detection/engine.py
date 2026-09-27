"""
Main detection engine that orchestrates all analyzers.
Takes a parsed email and produces a complete risk assessment with:
- Evidence-weighted scoring (0-100)
- Analysis confidence level
- Cross-signal correlation
- Domain intelligence
- Explainable findings
"""

from .sender import SenderAnalyzer
from .url_analyzer import URLAnalyzer
from .content_analyzer import ContentAnalyzer
from .header_analyzer import HeaderAnalyzer
from .attachment_analyzer import AttachmentAnalyzer
from .scoring import RiskScorer, Finding
from .rules import Category, Severity, is_risky_level
from .intelligence.domain_intelligence import DomainIntelligence


class DetectionEngine:
    """
    Orchestrates all detection analyzers and produces a final risk assessment.
    This is the main entry point for email analysis.
    """

    def __init__(self):
        self.sender_analyzer = SenderAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.header_analyzer = HeaderAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.domain_intel = DomainIntelligence()
        self.scorer = RiskScorer()

    def analyze(self, parsed_email) -> dict:
        """
        Analyze a parsed email and return complete results.

        Args:
            parsed_email: ParsedEmail object from the parser

        Returns:
            dict with risk_score, classification, confidence, findings,
            categorized_findings, recommended_actions, and summary
        """
        all_findings: list[Finding] = []

        # 1. Sender/Domain Analysis
        sender_findings = self.sender_analyzer.analyze(
            sender_email=parsed_email.sender_email,
            sender_name=parsed_email.sender_name,
            sender_domain=parsed_email.sender_domain,
            reply_to=parsed_email.headers.get('Reply-To', ''),
            return_path=parsed_email.headers.get('Return-Path', ''),
        )
        all_findings.extend(sender_findings)

        # 2. Domain Intelligence (passive DNS lookups)
        has_intel = False
        if parsed_email.sender_domain:
            try:
                intel_result = self.domain_intel.analyze(parsed_email.sender_domain)
                if intel_result.get("findings"):
                    all_findings.extend(intel_result["findings"])
                    has_intel = True
            except Exception:
                # Intelligence failures should not break analysis
                pass

        # 3. URL Analysis
        # The URL analyzer consumes the href URLs and the visible anchor
        # text (sanitised, never rendered) so it can compare visible link
        # text with the real href.
        url_findings = self.url_analyzer.analyze(
            parsed_email.urls,
            anchor_text=getattr(parsed_email, 'anchor_text', ''),
            anchors=getattr(parsed_email, 'anchors', None),
        )
        all_findings.extend(url_findings)

        # 4. Content Analysis
        content_findings = self.content_analyzer.analyze(
            body_text=parsed_email.body_text,
            body_html=parsed_email.body_html,
        )
        all_findings.extend(content_findings)

        # 5. Header Analysis
        header_findings = self.header_analyzer.analyze(
            headers=parsed_email.headers,
            spf_result=parsed_email.spf_result,
            dkim_result=parsed_email.dkim_result,
            dmarc_result=parsed_email.dmarc_result,
            received_headers=parsed_email.received_headers,
        )
        all_findings.extend(header_findings)

        # 6. Attachment Analysis
        attachment_findings = self.attachment_analyzer.analyze(parsed_email.attachments)
        all_findings.extend(attachment_findings)

        # 6b. BEC context check: the freemail-authority finding is only kept
        #     when the body actually contains a phishing-relevant action
        #     (money/credentials/urgency). A personal Gmail signed "CEO"
        #     sharing holiday photos should not be flagged.
        body_context = (
            (parsed_email.body_text or "") + " " +
            (parsed_email.subject or "")
        ).lower()
        from .sender import _BEC_ACTION_TERMS
        has_bec_context = any(t in body_context for t in _BEC_ACTION_TERMS)
        if not has_bec_context:
            all_findings = [
                f for f in all_findings
                if f.rule_id != "SENDER_FREEMAIL_AUTHORITY"
            ]

        # 7. Cross-signal correlation (F-10: may neutralize duplicate
        #    content-level combination findings; _correlate_signals returns
        #    both the correlation findings and the pruned originals).
        correlation_findings, all_findings = self._correlate_signals(all_findings, parsed_email)
        all_findings.extend(correlation_findings)

        # 8. Calculate final score with confidence
        risk_score, classification, findings_list, confidence_level, confidence_numeric = \
            self.scorer.calculate_score(all_findings, has_intel=has_intel)

        # 9. Group findings by category for easy display
        categorized = {
            "SENDER": [],
            "URL": [],
            "CONTENT": [],
            "HEADER": [],
            "ATTACHMENT": [],
            "INTEL": [],
            "CORRELATION": [],
            "OTHER": [],
        }

        for finding_dict in findings_list:
            cat = finding_dict.get("category", "OTHER")
            if cat in categorized:
                categorized[cat].append(finding_dict)

        # 10. Build recommended action
        recommended_actions = self._build_recommended_actions(classification, findings_list)

        # 11. Sort findings by severity and points for top findings
        top_findings = self._get_top_findings(findings_list)

        return {
            "risk_score": risk_score,
            "classification": classification,
            "confidence_level": confidence_level,
            "confidence_numeric": confidence_numeric,
            "findings": findings_list,
            "top_findings": top_findings,
            "categorized_findings": categorized,
            "recommended_actions": recommended_actions,
            "summary": self._build_summary(classification, findings_list, confidence_level),
        }

    def _correlate_signals(self, findings: list[Finding], parsed_email):
        """
        Cross-signal correlation engine.
        Detects combinations of findings that together indicate higher risk.

        F-10: returns (correlation_findings, pruned_findings) — when a
        correlation layer owns a combination, the duplicate content-level
        combo finding is replaced by a zero-point authoritative marker.
        """
        correlation_findings = []

        rule_ids = {f.rule_id for f in findings}
        categories = {f.category for f in findings}
        has_content = any(f.category == Category.CONTENT for f in findings)
        has_url = any(f.category == Category.URL for f in findings)
        has_sender = any(f.category == Category.SENDER for f in findings)
        has_header = any(f.category == Category.HEADER for f in findings)
        has_intel = any(f.category == Category.INTEL for f in findings)

        # Credential request + external login URL
        has_credential = 'CONTENT_CREDENTIAL_REQUEST' in rule_ids
        has_login_url = 'URL_SUSPICIOUS_PATH' in rule_ids or 'URL_LOOKALIKE_DOMAIN' in rule_ids
        has_credential_url = 'URL_CREDENTIALS_IN_URL' in rule_ids

        if has_credential and (has_login_url or has_credential_url):
            correlation_findings.append(Finding(
                rule_id="CORR_CREDENTIAL_PHISHING",
                category=Category.CORRELATION,
                severity=Severity.CRITICAL.value,
                points=15,
                message="Email requests credentials AND contains a suspicious login URL — strong phishing pattern.",
                evidence="Credential request + suspicious URL combination",
                explanation=(
                    "The email requests sensitive credentials (password, OTP, etc.) while "
                    "also containing a URL that leads to a login or verification page. "
                    "This combination is one of the most reliable phishing indicators."
                ),
                source="Cross-signal correlation",
            ))

        # Urgency + financial request + suspicious URL
        has_urgency = 'CONTENT_URGENCY' in rule_ids
        has_financial = 'CONTENT_FINANCIAL_SCAM' in rule_ids
        has_threat = 'CONTENT_THREAT_LANGUAGE' in rule_ids

        if (has_urgency or has_threat) and has_financial and has_url:
            correlation_findings.append(Finding(
                rule_id="CORR_FINANCIAL_SCAM_COMBO",
                category=Category.CORRELATION,
                severity=Severity.HIGH.value,
                points=12,
                message="Email combines urgency/threats with financial requests and suspicious URLs.",
                evidence="Urgency/threat + financial request + URL combination",
                explanation=(
                    "The email uses pressure tactics (urgency or threats) while requesting "
                    "financial action and containing suspicious URLs. This is a common pattern "
                    "in Business Email Compromise (BEC) and invoice fraud attacks."
                ),
                source="Cross-signal correlation",
            ))

        # Urgency + credential request
        if has_urgency and has_credential:
            correlation_findings.append(Finding(
                rule_id="CORR_URGENCY_CREDENTIAL",
                category=Category.CORRELATION,
                severity=Severity.HIGH.value,
                points=10,
                message="Email combines urgency language with credential requests — strong social engineering.",
                evidence="Urgency + credential request combination",
                explanation=(
                    "Urgency language combined with credential requests is a textbook "
                    "phishing technique designed to pressure victims into acting without thinking."
                ),
                source="Cross-signal correlation",
            ))

            # F-10: ONE layer owns the urgency+credential combination bonus.
            # The CORRELATION finding above (+10) is the authoritative scoring
            # event; the content-level CONTENT_URGENCY_CREDENTIAL_COMBO (+5)
            # describes the same underlying condition and is neutralized to a
            # zero-point evidence marker so the pattern can never be paid
            # twice (content +5 AND engine +10). The content finding stays in
            # the output for explainability, and the base URGENCY and
            # CREDENTIAL findings are untouched.
            correlation_findings.append(Finding(
                rule_id="CONTENT_URGENCY_CREDENTIAL_COMBO",
                category=Category.CONTENT,
                severity=Severity.LOW.value,
                points=0,
                message=(
                    "Urgency + credential combination accounted for by "
                    "CORR_URGENCY_CREDENTIAL (no double counting)."
                ),
                evidence="Content-level duplicate of the correlation bonus",
                explanation=(
                    "The urgency + credential combination is scored once, by the "
                    "cross-signal correlation layer. This marker replaces the "
                    "content-level bonus so the same evidence is never paid "
                    "two combination bonuses."
                ),
                source="Cross-signal correlation",
                dedup_key="corr_urgency_credential",
            ))
            # Drop the original content-level combo finding (it fired with
            # points; the zero-point authoritative marker replaces it).
            findings = [f for f in findings
                        if f.rule_id != "CONTENT_URGENCY_CREDENTIAL_COMBO"]

        # Sender domain mismatch + auth failure + credential request
        if (has_sender and has_header and has_credential and
            not any(f.rule_id == "HEADER_AUTH_ALL_PASS" for f in findings)):
            correlation_findings.append(Finding(
                rule_id="CORR_SPOOFED_PHISHING",
                category=Category.CORRELATION,
                severity=Severity.HIGH.value,
                points=12,
                message="Sender domain issues + authentication failure + credential request — likely spoofed phishing.",
                evidence="Sender mismatch + auth failure + credential request",
                explanation=(
                    "The email has sender domain anomalies, failed authentication, and "
                    "requests credentials. Together, these strongly suggest the email is "
                    "spoofed and attempting credential theft."
                ),
                source="Cross-signal correlation",
            ))

        # Brand impersonation + credential request
        if has_intel and has_credential:
            brand_findings = [f for f in findings if f.rule_id == "INTEL_BRAND_IMPERSONATION"]
            if brand_findings:
                correlation_findings.append(Finding(
                    rule_id="CORR_BRAND_CREDENTIAL_PHISH",
                    category=Category.CORRELATION,
                    severity=Severity.CRITICAL.value,
                    points=18,
                    message="Brand impersonation domain requests credentials — high-confidence phishing.",
                    evidence="Brand impersonation + credential request",
                    explanation=(
                        "The sender domain impersonates a known brand while requesting "
                        "sensitive credentials. This is one of the strongest phishing indicators."
                    ),
                    source="Cross-signal correlation",
                ))

        # Business Email Compromise: freemail authority claim + money/credential ask
        has_freemail_authority = 'SENDER_FREEMAIL_AUTHORITY' in rule_ids
        has_financial_url_combo = has_financial or has_credential
        if has_freemail_authority and has_financial_url_combo:
            correlation_findings.append(Finding(
                rule_id="CORR_BEC_WIRE_FRAUD",
                category=Category.CORRELATION,
                severity=Severity.CRITICAL.value,
                points=14,
                message="Authoritative sender on a free mailbox requests money or credentials — Business Email Compromise pattern.",
                evidence="Freemail authority claim + financial/credential request",
                explanation=(
                    "The sender's display name claims an executive or support role, "
                    "but the address is a free personal mailbox, and the message asks "
                    "for a financial action or credentials. Verify via a known channel "
                    "before transferring anything — this is the classic CEO-fraud/BEC "
                    "playbook."
                ),
                source="Cross-signal correlation",
            ))

        # Strong benign signal: legitimate domain + all auth pass + no suspicious URLs
        if (has_sender and has_header and
            'HEADER_AUTH_ALL_PASS' in rule_ids and
            not has_url and not has_credential and not has_financial and not has_freemail_authority):
            # Check if sender domain is a known legitimate brand
            brand_findings = [f for f in findings if f.rule_id == "SENDER_BRAND_IMPERSONATION"]
            if not brand_findings:
                correlation_findings.append(Finding(
                    rule_id="CORR_LEGITIMATE_SIGNALS",
                    category=Category.CORRELATION,
                    severity=Severity.LOW.value,
                    points=-5,
                    message="Multiple signals suggest legitimacy: authenticated sender, no suspicious content.",
                    evidence="All auth pass + no suspicious URLs + no credential requests",
                    explanation=(
                        "The email has passing authentication, no suspicious URLs, and no "
                        "credential requests. While not definitive proof of legitimacy, "
                        "these combined signals reduce overall risk."
                    ),
                    source="Cross-signal correlation",
                ))

        return correlation_findings, findings

    def _get_top_findings(self, findings: list[dict]) -> list[dict]:
        """Get the top 5 strongest findings sorted by severity and points."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.get("severity", "LOW"), 4), -abs(f.get("points", 0)))
        )
        return sorted_findings[:5]

    def _build_recommended_actions(self, classification: str, findings: list) -> list[str]:
        """Generate recommended actions based on findings."""
        actions = []

        rule_ids = {f['rule_id'] for f in findings}
        has_url_issues = any(f['rule_id'].startswith('URL_') for f in findings)
        has_credential_request = 'CONTENT_CREDENTIAL_REQUEST' in rule_ids
        has_auth_failure = any(f['rule_id'].startswith('HEADER_') and 'PASS' not in f['rule_id'] for f in findings)
        has_attachment_issues = any(f['rule_id'].startswith('ATTACHMENT_') for f in findings)
        has_sender_issues = any(f['rule_id'].startswith('SENDER_') for f in findings)
        has_brand_impersonation = 'INTEL_BRAND_IMPERSONATION' in rule_ids or 'SENDER_BRAND_IMPERSONATION' in rule_ids

        if is_risky_level(classification):
            actions.append("Do not click any links in this email.")
            actions.append("Do not download or open any attachments.")

        if has_credential_request:
            actions.append("Do not provide any personal credentials or sensitive information.")
            actions.append("Verify the sender through an independent trusted channel.")

        if has_brand_impersonation:
            actions.append("The sender domain appears to impersonate a known brand — treat with high caution.")

        if has_url_issues:
            actions.append("Do not visit any URLs contained in this email.")

        if has_auth_failure:
            actions.append("Email failed authentication checks — it may be spoofed.")

        if has_attachment_issues:
            actions.append("Do not open attachments — they may contain malware.")

        if has_sender_issues:
            actions.append("Verify the sender's identity through a separate communication channel.")

        if classification == "SAFE":
            actions.append("This email appears to be legitimate, but always remain cautious.")

        if not actions:
            actions.append("Review this email carefully before taking any action.")

        return actions

    def _build_summary(self, classification: str, findings: list, confidence_level: str) -> str:
        """Build a human-readable summary of the analysis."""
        if classification == "SAFE":
            return "No significant security concerns detected."

        critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        high_count = sum(1 for f in findings if f.get('severity') == 'HIGH')
        medium_count = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
        low_count = sum(1 for f in findings if f.get('severity') == 'LOW')

        parts = []
        if critical_count:
            parts.append(f"{critical_count} critical")
        if high_count:
            parts.append(f"{high_count} high")
        if medium_count:
            parts.append(f"{medium_count} medium")
        if low_count:
            parts.append(f"{low_count} low")

        severity_str = ", ".join(parts) if parts else "no significant"
        return (
            f"Classified as {classification} with {len(findings)} findings "
            f"({severity_str} severity). Analysis confidence: {confidence_level}."
        )
