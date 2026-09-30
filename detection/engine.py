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
                intel_result = self.domain_intel.analyze(
                    parsed_email.sender_domain,
                    urls=list(getattr(parsed_email, "urls", []) or []),
                )
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

        # ------------------------------------------------------------------
        # Session D: intelligence cross-signal correlation.
        #
        # These rules combine EXISTING findings from the intelligence layer
        # (domain age, Safe Browsing, TLS), the URL layer (shortener,
        # visible-link mismatch), the content layer (credential requests)
        # and the header layer (authentication) into explicit evidence about
        # the RELATIONSHIP between signals. Deterministic: every rule keys
        # off concrete rule_ids already present in `findings`.
        #
        # Failure semantics: only CONFIRMED evidence correlates. Safe
        # Browsing NO_MATCH / UNAVAILABLE / ERROR never appear as findings
        # (see domain_intelligence), and TLS VALID / HTTP / UNAVAILABLE /
        # ERROR produce no negative finding either — inability to inspect
        # is never evidence of maliciousness.
        #
        # Scoring: correlation findings are ONE additional CORRELATION-
        # category signal (cap 10 in CATEGORY_WEIGHTS). The underlying
        # individual findings continue to score in their own categories;
        # the cap makes raw inflation impossible and no rule removes or
        # rewrites another finding (F-10 single-owner markers above remain
        # the only mechanism that neutralizes duplicate combos).
        # ------------------------------------------------------------------
        has_new_domain = "INTEL_YOUNG_DOMAIN" in rule_ids
        has_threat_intel = "INTEL_SAFE_BROWSING_THREAT" in rule_ids
        _TLS_ANOMALY_RULES = ("INTEL_TLS_EXPIRED", "INTEL_TLS_HOSTNAME_MISMATCH",
                              "INTEL_TLS_INVALID")
        has_tls_anomaly = any(rid in rule_ids for rid in _TLS_ANOMALY_RULES)
        has_shortener = "URL_SHORTENER" in rule_ids
        _BRAND_RULES = ("INTEL_BRAND_IMPERSONATION", "INTEL_LOOKALIKE_DOMAIN",
                        "SENDER_BRAND_IMPERSONATION", "SENDER_LOOKALIKE_DOMAIN")
        has_brand = any(rid in rule_ids for rid in _BRAND_RULES)
        has_url_deception = "URL_VISIBLE_LINK_MISMATCH" in rule_ids
        # Rule F: EXPLICIT hard authentication failures only — softfail,
        # neutral, none, unknown and error are weak states, never failures
        # (same boundary as the F-6 auth floor).
        _AUTH_HARD_FAILS = ("HEADER_SPF_FAIL", "HEADER_DKIM_FAIL",
                            "HEADER_DMARC_FAIL")
        has_hard_auth_failure = any(rid in rule_ids for rid in _AUTH_HARD_FAILS)

        # Evidence strings quote the actual underlying finding evidence so
        # the relevant domain/URL is identified in the correlation itself.
        age_evidence = next((f.evidence for f in findings
                             if f.rule_id == "INTEL_YOUNG_DOMAIN"), "")
        sb_evidence = next((f.evidence for f in findings
                            if f.rule_id == "INTEL_SAFE_BROWSING_THREAT"), "")
        tls_evidence = next((f.evidence for f in findings
                             if f.rule_id in _TLS_ANOMALY_RULES), "")

        _CRED_EVIDENCE = ("Message contains a credential/account "
                          "authentication request")
        _SCOPE_NOTE = ("Correlation is factual evidence about signal "
                       "relationships; the underlying findings continue to "
                       "score in their own categories and no category cap is "
                       "bypassed.")

        def _corr(rule_id, severity, points, message, evidence, explanation):
            correlation_findings.append(Finding(
                rule_id=rule_id,
                category=Category.CORRELATION,
                severity=severity,
                points=points,
                message=message,
                evidence=evidence,
                explanation=explanation,
                source="Cross-signal correlation",
            ))

        # Rule A: NEW_DOMAIN + CREDENTIAL_REQUEST
        if has_credential and has_new_domain:
            _corr(
                "CORR_NEW_DOMAIN_CREDENTIAL_REQUEST",
                Severity.MEDIUM.value, 3,
                "Recently registered domain combined with a credential/account authentication request.",
                f"{_CRED_EVIDENCE}; sender domain registration is recent"
                + (f" ({age_evidence})" if age_evidence else ""),
                "The sender domain was recently registered (see "
                "INTEL_YOUNG_DOMAIN) and the message asks for credentials or "
                "account authentication. Very new domains are "
                "disproportionately used in credential-harvesting campaigns, "
                "while most legitimate mail comes from long-established "
                "domains. This describes a relationship between two observed "
                "signals; it is not by itself proof of phishing. " + _SCOPE_NOTE,
            )

        # Rule B: NEW_DOMAIN + BRAND_IMPERSONATION
        if has_new_domain and has_brand:
            _corr(
                "CORR_NEW_DOMAIN_BRAND_IMPERSONATION",
                Severity.MEDIUM.value, 3,
                "Recently registered domain combined with brand impersonation.",
                "Sender domain registration is recent"
                + (f" ({age_evidence})" if age_evidence else "")
                + "; the domain impersonates or closely resembles a known brand",
                "A newly registered domain that also impersonates or resembles "
                "a known brand matches the throwaway-domain pattern: register, "
                "impersonate, harvest, abandon. Both underlying signals remain "
                "individually visible in this report. " + _SCOPE_NOTE,
            )

        # Rule C: THREAT_INTEL (confirmed only) + CREDENTIAL_REQUEST
        if has_credential and has_threat_intel:
            _corr(
                "CORR_THREAT_CREDENTIAL_REQUEST",
                Severity.HIGH.value, 5,
                "Externally confirmed threat URL combined with a credential/account authentication request.",
                f"{_CRED_EVIDENCE}; Google Safe Browsing reports a URL in this message as a current threat"
                + (f" ({sb_evidence})" if sb_evidence else " (KNOWN_THREAT)"),
                "At least one URL in this message is listed by Google Safe "
                "Browsing as a current threat, and the message requests "
                "credentials — an external, confirmed verdict combined with the "
                "message's own request for sensitive data. Only a confirmed "
                "provider verdict (KNOWN_THREAT) is used here: NO_MATCH, "
                "UNAVAILABLE and ERROR are never treated as threat evidence. "
                + _SCOPE_NOTE,
            )

        # Rule D: SHORTENER + CREDENTIAL_REQUEST
        if has_credential and has_shortener:
            _corr(
                "CORR_SHORTENER_CREDENTIAL_REQUEST",
                Severity.MEDIUM.value, 3,
                "Link shortener combined with a credential/account authentication request.",
                f"{_CRED_EVIDENCE}; the message contains a shortened URL that hides its true destination",
                "The message contains a shortened link and asks for credentials. "
                "Shorteners conceal the real destination, making it harder to "
                "notice where a credential request actually points. This is a "
                "relationship between two signals, not a verdict on its own. "
                + _SCOPE_NOTE,
            )

        # Rule E: BRAND_IMPERSONATION + URL_DECEPTION + CREDENTIAL_REQUEST
        if has_credential and has_brand and has_url_deception:
            _corr(
                "CORR_BRAND_URL_CREDENTIAL",
                Severity.HIGH.value, 5,
                "Brand impersonation, visible-link destination mismatch, and a credential request appear together.",
                f"{_CRED_EVIDENCE}; the domain impersonates or resembles a known brand; a displayed link's visible text points to a different destination",
                "This message displays a link that does not lead where it says, "
                "on a domain impersonating a known brand, while requesting "
                "credentials — a deliberate multi-layer deception chain. Each "
                "signal is also reported individually in this report. "
                + _SCOPE_NOTE,
            )

        # Rule F: AUTHENTICATION hard failure + CREDENTIAL_REQUEST
        if has_credential and has_hard_auth_failure:
            _corr(
                "CORR_AUTH_CREDENTIAL_REQUEST",
                Severity.HIGH.value, 5,
                "Hard authentication failure combined with a credential/account authentication request.",
                f"{_CRED_EVIDENCE}; SPF, DKIM, or DMARC returned an explicit hard failure",
                "The message failed email authentication (an explicit 'fail' "
                "verdict from SPF, DKIM or DMARC) and asks for credentials: the "
                "message does not come from the domain it claims. Weak outcomes "
                "(softfail, neutral, none) and unknown/error states never "
                "trigger this correlation. " + _SCOPE_NOTE,
            )

        # Rule G: TLS_ANOMALY + CREDENTIAL_REQUEST
        if has_credential and has_tls_anomaly:
            tls_rule = next(rid for rid in _TLS_ANOMALY_RULES
                            if rid in rule_ids)
            tls_state = tls_rule.replace("INTEL_", "", 1)
            _corr(
                "CORR_TLS_CREDENTIAL_REQUEST",
                Severity.MEDIUM.value, 3,
                "TLS certificate problem combined with a credential/account authentication request.",
                f"{_CRED_EVIDENCE}; TLS certificate state is {tls_state}"
                + (f" ({tls_evidence})" if tls_evidence else ""),
                f"The HTTPS certificate for a link in this message has a "
                f"problem ({tls_state}) while the message requests credentials. "
                "High-value login pages rarely ship expired or mismatched "
                "certificates. A valid certificate is NOT evidence of safety, "
                "and TLS states such as VALID, HTTP, UNAVAILABLE or ERROR are "
                "never treated as negative evidence here. " + _SCOPE_NOTE,
            )

        # Composite: NEW_DOMAIN + BRAND_IMPERSONATION + CREDENTIAL_REQUEST
        if has_new_domain and has_brand and has_credential:
            _corr(
                "CORR_NEW_DOMAIN_BRAND_CREDENTIAL",
                Severity.HIGH.value, 5,
                "Newly registered domain impersonating a brand while requesting credentials — composite evidence chain.",
                f"{_CRED_EVIDENCE}; sender domain registration is recent"
                + (f" ({age_evidence})" if age_evidence else "")
                + "; the domain impersonates or resembles a known brand",
                "All three signals appear together: the sender domain was "
                "registered recently, it impersonates or resembles a known "
                "brand, and the message requests credentials. This matches the "
                "lifecycle of a throwaway phishing domain. The relationship is "
                "reported as one coherent piece of evidence; the individual "
                "findings remain independently visible. " + _SCOPE_NOTE,
            )

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
