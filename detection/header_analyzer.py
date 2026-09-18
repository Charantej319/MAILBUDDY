"""
Email header analysis module.
Analyzes email headers for authentication failures, alignment problems,
and anomalies. Includes correlation-aware analysis to avoid double-counting.
"""

import re
from .rules import Finding, Severity, Category


class HeaderAnalyzer:
    """Analyzes email headers for security indicators."""

    def analyze(self, headers: dict, spf_result: str = "",
                dkim_result: str = "", dmarc_result: str = "",
                received_headers: list[str] = None) -> list[Finding]:
        """
        Analyze email headers and return findings.
        """
        findings = []

        # 1. SPF analysis
        findings.extend(self._check_spf(spf_result))

        # 2. DKIM analysis
        findings.extend(self._check_dkim(dkim_result))

        # 3. DMARC analysis
        findings.extend(self._check_dmarc(dmarc_result))

        # 4. Authentication-Results header deep analysis
        findings.extend(self._analyze_auth_results(headers.get('Authentication-Results', '')))

        # 5. From/Reply-To inconsistency
        findings.extend(self._check_from_reply_to(headers))

        # 6. Return-Path analysis
        findings.extend(self._check_return_path(headers))

        # 7. Received header analysis
        if received_headers:
            findings.extend(self._analyze_received_headers(received_headers))

        # 8. Suspicious headers
        findings.extend(self._check_suspicious_headers(headers))

        # 9. Authentication alignment checks
        findings.extend(self._check_auth_alignment(headers))

        # 10. Benign signals for passing authentication
        findings.extend(self._check_benign_signals(spf_result, dkim_result, dmarc_result))

        return findings

    def _check_spf(self, spf_result: str) -> list[Finding]:
        """Check SPF authentication result."""
        findings = []
        result = spf_result.lower().strip()

        if result == 'fail':
            findings.append(Finding(
                rule_id="HEADER_SPF_FAIL",
                category=Category.HEADER,
                severity=Severity.HIGH.value,
                points=8,
                message="SPF authentication failed — the sending server is not authorized for this domain.",
                evidence=f"SPF result: {spf_result}",
                explanation=(
                    "SPF (Sender Policy Framework) verification failed. The server that sent this "
                    "email is not listed in the sender domain's SPF record. This could indicate "
                    "email spoofing, but may also result from forwarding or misconfiguration."
                ),
                source="Email authentication headers",
            ))
        elif result == 'softfail':
            findings.append(Finding(
                rule_id="HEADER_SPF_SOFTFAIL",
                category=Category.HEADER,
                severity=Severity.MEDIUM.value,
                points=5,
                message="SPF softfail — the sending server is not explicitly authorized.",
                evidence=f"SPF result: {spf_result}",
                explanation=(
                    "SPF returned a softfail, meaning the sending server is not listed in the "
                    "domain's SPF record but the policy does not strictly reject it."
                ),
                source="Email authentication headers",
            ))
        elif result == 'none':
            findings.append(Finding(
                rule_id="HEADER_SPF_NONE",
                category=Category.HEADER,
                severity=Severity.LOW.value,
                points=3,
                message="No SPF record configured for the sender's domain.",
                evidence=f"SPF result: {spf_result}",
                explanation=(
                    "The sender's domain has no SPF record. This means there is no published "
                    "policy about which servers are authorized to send email for this domain."
                ),
                source="Email authentication headers",
            ))

        return findings

    def _check_dkim(self, dkim_result: str) -> list[Finding]:
        """Check DKIM authentication result."""
        findings = []
        result = dkim_result.lower().strip()

        if result == 'fail':
            findings.append(Finding(
                rule_id="HEADER_DKIM_FAIL",
                category=Category.HEADER,
                severity=Severity.HIGH.value,
                points=7,
                message="DKIM authentication failed — email integrity could not be verified.",
                evidence=f"DKIM result: {dkim_result}",
                explanation=(
                    "DKIM (DomainKeys Identified Mail) verification failed. The email's "
                    "cryptographic signature does not match, which could indicate the message "
                    "was modified in transit or sent from an unauthorized server."
                ),
                source="Email authentication headers",
            ))
        elif result == 'none':
            findings.append(Finding(
                rule_id="HEADER_DKIM_NONE",
                category=Category.HEADER,
                severity=Severity.MEDIUM.value,
                points=4,
                message="No DKIM signature found — email authenticity cannot be verified.",
                evidence=f"DKIM result: {dkim_result}",
                explanation=(
                    "The email has no DKIM signature. Without DKIM, we cannot verify "
                    "that the message was signed by the claimed domain."
                ),
                source="Email authentication headers",
            ))

        return findings

    def _check_dmarc(self, dmarc_result: str) -> list[Finding]:
        """Check DMARC authentication result."""
        findings = []
        result = dmarc_result.lower().strip()

        if result == 'fail':
            findings.append(Finding(
                rule_id="HEADER_DMARC_FAIL",
                category=Category.HEADER,
                severity=Severity.HIGH.value,
                points=8,
                message="DMARC authentication failed — domain anti-spoofing policy not met.",
                evidence=f"DMARC result: {dmarc_result}",
                explanation=(
                    "DMARC (Domain-based Message Authentication) verification failed. "
                    "The email did not pass either SPF or DKIM alignment as required by "
                    "the domain's DMARC policy. This is a strong indicator of potential spoofing."
                ),
                source="Email authentication headers",
            ))
        elif result == 'none':
            findings.append(Finding(
                rule_id="HEADER_DMARC_NONE",
                category=Category.HEADER,
                severity=Severity.LOW.value,
                points=2,
                message="No DMARC policy configured for the sender's domain.",
                evidence=f"DMARC result: {dmarc_result}",
                explanation=(
                    "The sender's domain has no DMARC policy. This means there is no "
                    "policy enforcement for SPF/DKIM alignment."
                ),
                source="Email authentication headers",
            ))

        return findings

    def _analyze_auth_results(self, auth_header: str) -> list[Finding]:
        """Deep analysis of Authentication-Results header."""
        findings = []

        if not auth_header:
            return findings

        # Check for multiple authentication failures
        fail_count = auth_header.lower().count('=fail')
        if fail_count >= 2:
            findings.append(Finding(
                rule_id="HEADER_MULTIPLE_AUTH_FAILURES",
                category=Category.HEADER,
                severity=Severity.HIGH.value,
                points=10,
                message=f"Multiple authentication failures detected ({fail_count} failures).",
                evidence=f"Authentication-Results: {auth_header[:200]}",
                explanation=(
                    f"The email failed {fail_count} authentication checks. Multiple failures "
                    f"strongly suggest the email was not sent from an authorized server."
                ),
                source="Email authentication headers",
            ))

        return findings

    def _check_from_reply_to(self, headers: dict) -> list[Finding]:
        """Check From/Reply-To consistency."""
        findings = []

        from_addr = headers.get('From', '')
        reply_to = headers.get('Reply-To', '')

        if reply_to and from_addr:
            from_domain = from_addr.split('@')[-1].lower().strip().rstrip('>') if '@' in from_addr else ''
            reply_domain = reply_to.split('@')[-1].lower().strip().rstrip('>') if '@' in reply_to else ''

            if from_domain and reply_domain and from_domain != reply_domain:
                findings.append(Finding(
                    rule_id="HEADER_FROM_REPLYTO_MISMATCH",
                    category=Category.HEADER,
                    severity=Severity.MEDIUM.value,
                    points=6,
                    message=f"From domain '{from_domain}' differs from Reply-To domain '{reply_domain}'.",
                    evidence=f"From: {from_addr}, Reply-To: {reply_to}",
                    explanation=(
                        f"The Reply-To address uses a different domain ({reply_domain}) than the "
                        f"From address ({from_domain}). This is a common technique to redirect "
                        f"replies to an attacker-controlled address."
                    ),
                    source="Email headers",
                ))

        return findings

    def _check_return_path(self, headers: dict) -> list[Finding]:
        """Check Return-Path consistency."""
        findings = []

        from_addr = headers.get('From', '')
        return_path = headers.get('Return-Path', '')

        if return_path and from_addr:
            from_domain = from_addr.split('@')[-1].lower().strip().rstrip('>') if '@' in from_addr else ''
            return_domain = return_path.split('@')[-1].lower().strip().rstrip('>') if '@' in return_path else ''

            if from_domain and return_domain and from_domain != return_domain:
                findings.append(Finding(
                    rule_id="HEADER_RETURN_PATH_MISMATCH",
                    category=Category.HEADER,
                    severity=Severity.LOW.value,
                    points=3,
                    message=f"Return-Path domain '{return_domain}' differs from sender domain '{from_domain}'.",
                    evidence=f"From: {from_addr}, Return-Path: {return_path}",
                    explanation=(
                        f"The Return-Path envelope sender uses a different domain than the "
                        f"displayed From address. This can indicate SPF manipulation or "
                        f"email forwarding."
                    ),
                    source="Email headers",
                ))

        return findings

    def _analyze_received_headers(self, received_headers: list[str]) -> list[Finding]:
        """Analyze Received headers for anomalies."""
        findings = []

        if not received_headers:
            return findings

        # Check for excessive number of hops
        if len(received_headers) > 8:
            findings.append(Finding(
                rule_id="HEADER_EXCESSIVE_HOPS",
                category=Category.HEADER,
                severity=Severity.LOW.value,
                points=2,
                message=f"Email passed through {len(received_headers)} mail servers — unusually many hops.",
                evidence=f"Hops: {len(received_headers)}",
                explanation=(
                    "Emails typically pass through 2-4 mail servers. An unusually high "
                    "number of hops could indicate forwarding chains or suspicious routing."
                ),
                source="Received headers",
            ))

        return findings

    def _check_suspicious_headers(self, headers: dict) -> list[Finding]:
        """Check for suspicious or missing headers."""
        findings = []

        # Missing Message-ID
        if not headers.get('Message-ID'):
            findings.append(Finding(
                rule_id="HEADER_MISSING_MESSAGE_ID",
                category=Category.HEADER,
                severity=Severity.LOW.value,
                points=2,
                message="Email is missing a Message-ID header.",
                evidence="No Message-ID header found",
                explanation=(
                    "Legitimate email servers typically generate a Message-ID header. "
                    "Missing headers may indicate manual email construction."
                ),
                source="Email headers",
            ))

        # Check for X-Mailer indicating automated/suspicious tools
        x_mailer = headers.get('X-Mailer', '').lower()
        user_agent = headers.get('User-Agent', '').lower()

        suspicious_mailers = ['phpmailer', 'mass mail', 'bulk mail', 'newsletter']
        for mailer in suspicious_mailers:
            if mailer in x_mailer or mailer in user_agent:
                findings.append(Finding(
                    rule_id="HEADER_SUSPICIOUS_MAILER",
                    category=Category.HEADER,
                    severity=Severity.LOW.value,
                    points=2,
                    message=f"Email was sent using '{x_mailer or user_agent}', which may indicate bulk mailing.",
                    evidence=f"X-Mailer/User-Agent: {x_mailer or user_agent}",
                    explanation=(
                        "The email was sent using software commonly associated with "
                        "bulk or automated mailing, which may be legitimate for newsletters "
                        "but is also common in phishing campaigns."
                    ),
                    source="Email headers",
                ))
                break

        return findings

    def _check_auth_alignment(self, headers: dict) -> list[Finding]:
        """Check authentication domain alignment."""
        findings = []

        from_addr = headers.get('From', '')
        auth_results = headers.get('Authentication-Results', '')

        if not from_addr or not auth_results:
            return findings

        from_domain = from_addr.split('@')[-1].lower().strip().rstrip('>') if '@' in from_addr else ''
        if not from_domain:
            return findings

        # Check if authentication was done against a different domain.
        #
        # A verifier (e.g. a mailing list or forwarding agent) can insert its
        # OWN Authentication-Results header evaluating a different domain than
        # the From address. Those results say nothing about the From domain, so
        # they must NOT be treated as a pass for the sender — that would be a
        # confused-deputy bypass. Instead of just flagging, we also NEUTRALIZE
        # the untrustworthy pass signal so it cannot cancel real failures.
        auth_lower = auth_results.lower()
        if from_domain and from_domain not in auth_lower:
            domain_match = re.search(r'([a-z0-9.-]+\.[a-z]{2,})', auth_lower)
            if domain_match:
                auth_domain = domain_match.group(1)
                if auth_domain != from_domain and not auth_domain.endswith(f'.{from_domain}'):
                    findings.append(Finding(
                        rule_id="HEADER_AUTH_DOMAIN_MISMATCH",
                        category=Category.HEADER,
                        severity=Severity.MEDIUM.value,
                        points=6,
                        message=(
                            f"Authentication results were generated for '{auth_domain}' "
                            f"but the From domain is '{from_domain}' — the auth verdict "
                            f"cannot be trusted for this sender."
                        ),
                        evidence=f"From: {from_addr}, Auth domain: {auth_domain}",
                        explanation=(
                            f"The Authentication-Results header evaluates a different "
                            f"domain ('{auth_domain}') than the From address domain "
                            f"('{from_domain}'). A third party (forwarder or mailing "
                            f"list) inserted these results; they provide no assurance "
                            f"about the actual sender. Authentication is treated as unknown."
                        ),
                        source="Email headers",
                    ))
                    # Neutralize any benign "all auth pass" signal — it did not
                    # apply to the From domain, so it must not reduce risk.
                    findings = [f for f in findings if f.rule_id != "HEADER_AUTH_ALL_PASS"]

        return findings

    def _check_benign_signals(self, spf_result: str, dkim_result: str, dmarc_result: str) -> list[Finding]:
        """Check for passing authentication as positive signals."""
        findings = []

        # All authentication passing
        if (spf_result.lower().strip() == 'pass' and
            dkim_result.lower().strip() == 'pass' and
            dmarc_result.lower().strip() == 'pass'):
            findings.append(Finding(
                rule_id="HEADER_AUTH_ALL_PASS",
                category=Category.HEADER,
                severity=Severity.LOW.value,
                points=-3,
                message="All email authentication checks (SPF, DKIM, DMARC) passed.",
                evidence=f"SPF: {spf_result}, DKIM: {dkim_result}, DMARC: {dmarc_result}",
                explanation=(
                    "The email passed SPF, DKIM, and DMARC authentication. This is a positive "
                    "signal, but does NOT guarantee the email is safe — compromised legitimate "
                    "accounts can still send phishing emails with valid authentication."
                ),
                source="Email authentication headers",
            ))

        return findings
