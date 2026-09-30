/**
 * Session E — Evidence chain presentation helpers.
 *
 * Pure functions that map the backend's existing findings (the
 * authoritative deterministic engine output) to human-readable evidence
 * for the investigation page. The UI never recalculates risk: no score,
 * no caps, no correlation logic — it renders what the backend returned.
 *
 * State semantics follow the intelligence modules exactly:
 *   - confirmed evidence only (KNOWN_THREAT, real TLS anomalies, real age
 *     findings) is shown as risk-relevant;
 *   - UNAVAILABLE / ERROR / unknown are neutral "could not check" lines,
 *     never "safe" and never malicious;
 *   - NO_MATCH is the only state shown as an explicit clean result.
 */

/**
 * Human-readable labels for internal rule IDs. Rule IDs are never the
 * primary user-facing label (they remain only in the technical details
 * row of the existing finding rendering).
 */
export const EVIDENCE_LABELS = {
  // Sender / Domain
  SENDER_BRAND_IMPERSONATION: 'Brand impersonation (sender)',
  SENDER_LOOKALIKE_DOMAIN: 'Lookalike domain (sender)',
  SENDER_NAME_DOMAIN_MISMATCH: 'Sender name does not match domain',
  SENDER_REPLY_TO_MISMATCH: 'Reply-To differs from sender',
  SENDER_FREEMAIL_AUTHORITY: 'Authority claim on free mailbox',
  SENDER_HOMOGLYPH: 'Homoglyph lookalike sender domain',
  SENDER_SUSPICIOUS_DOMAIN: 'Suspicious domain structure',
  SENDER_MISSING: 'Missing sender information',

  // Domain intelligence
  INTEL_BRAND_IMPERSONATION: 'Brand impersonation',
  INTEL_LOOKALIKE_DOMAIN: 'Lookalike domain',
  INTEL_SUSPICIOUS_TLD: 'Suspicious domain ending (TLD)',
  INTEL_NO_DNS: 'Domain does not resolve in DNS',
  INTEL_HAS_MX: 'Domain can receive email',
  INTEL_YOUNG_DOMAIN: 'Recently registered domain',
  INTEL_DOMAIN_RECENT: 'Domain registration is recent',
  INTEL_SAFE_BROWSING_THREAT: 'Threat intelligence match',
  INTEL_TLS_EXPIRED: 'Expired TLS certificate',
  INTEL_TLS_HOSTNAME_MISMATCH: 'TLS hostname mismatch',
  INTEL_TLS_INVALID: 'Invalid TLS certificate',

  // URL
  URL_SHORTENER: 'Link shortener',
  URL_VISIBLE_LINK_MISMATCH: 'Visible link does not match destination',
  URL_SUSPICIOUS_PATH: 'Suspicious link path',
  URL_LOOKALIKE_DOMAIN: 'Lookalike link domain',
  URL_CREDENTIALS_IN_URL: 'Credentials embedded in link',
  URL_PUNYCODE_HOMOGLYPH: 'Lookalike characters in domain (punycode)',
  URL_IP_ADDRESS: 'Raw IP address link',
  URL_HTTP: 'Unencrypted link (HTTP)',
  URL_SUSPICIOUS_TLD: 'Suspicious domain ending (TLD)',
  URL_LONG: 'Unusually long link',
  URL_EXCESSIVE_SUBDOMAINS: 'Many subdomains in link',
  URL_OBFUSCATED: 'Obfuscated link',
  URL_EXPLICIT_PORT: 'Unusual port in link',

  // Content
  CONTENT_CREDENTIAL_REQUEST: 'Credential request',
  CONTENT_URGENCY: 'Urgency pressure',
  CONTENT_SOCIAL_ENGINEERING: 'Social engineering language',
  CONTENT_THREAT_LANGUAGE: 'Threat language',
  CONTENT_FINANCIAL_SCAM: 'Financial request',
  CONTENT_URGENCY_CREDENTIAL_COMBO: 'Urgency + credential combination',

  // Authentication
  HEADER_SPF_FAIL: 'SPF authentication failed',
  HEADER_SPF_SOFTFAIL: 'SPF soft failure',
  HEADER_SPF_NEUTRAL: 'SPF neutral',
  HEADER_SPF_NONE: 'No SPF record',
  HEADER_SPF_ERROR: 'SPF error',
  HEADER_DKIM_FAIL: 'DKIM signature failed',
  HEADER_DKIM_NONE: 'No DKIM signature',
  HEADER_DKIM_ERROR: 'DKIM error',
  HEADER_DMARC_FAIL: 'DMARC authentication failed',
  HEADER_DMARC_NONE: 'No DMARC policy',
  HEADER_DMARC_ERROR: 'DMARC error',
  HEADER_AUTH_ALL_PASS: 'Authentication passed',
  HEADER_MISSING_MESSAGE_ID: 'Missing Message-ID header',

  // Attachments
  ATTACHMENT_DANGEROUS_TYPE: 'Risky attachment type',
  ATTACHMENT_DANGEROUS_EXTENSION: 'Risky attachment file type',
  ATTACHMENT_SUSPICIOUS_NAME: 'Suspicious attachment name',
  ATTACHMENT_DOUBLE_EXTENSION: 'Double file extension',
  ATTACHMENT_MALICIOUS_HASH: 'Attachment flagged as malicious',

  // Session D correlations — relationships between signals.
  CORR_NEW_DOMAIN_CREDENTIAL_REQUEST: 'New domain + credential request',
  CORR_NEW_DOMAIN_BRAND_IMPERSONATION: 'New domain + brand impersonation',
  CORR_THREAT_CREDENTIAL_REQUEST: 'Threat intelligence + credential request',
  CORR_SHORTENER_CREDENTIAL_REQUEST: 'Shortened link + credential request',
  CORR_BRAND_URL_CREDENTIAL: 'Brand + link deception + credential request',
  CORR_AUTH_CREDENTIAL_REQUEST: 'Authentication failure + credential request',
  CORR_TLS_CREDENTIAL_REQUEST: 'TLS problem + credential request',
  CORR_NEW_DOMAIN_BRAND_CREDENTIAL:
    'New domain + brand impersonation + credential request',

  // Legacy / pre-existing correlations (kept for completeness).
  CORR_CREDENTIAL_PHISHING: 'Credential request + suspicious login link',
  CORR_URGENCY_CREDENTIAL: 'Urgency + credential request',
  CORR_FINANCIAL_SCAM_COMBO: 'Urgency + financial request + link',
  CORR_SPOOFED_PHISHING: 'Sender anomaly + authentication failure',
  CORR_BRAND_CREDENTIAL_PHISH: 'Brand impersonation + credential request',
  CORR_BEC_WIRE_FRAUD: 'Free-mailbox authority claim + money/credential ask',
  CORR_LEGITIMATE_SIGNALS: 'Authentication passed; no suspicious content',
}

/**
 * One-sentence factual summaries for the evidence chain (aligned with the
 * backend's own explanations).
 */
export const EVIDENCE_SUMMARY = {
  INTEL_YOUNG_DOMAIN: 'Domain registration is recent.',
  INTEL_DOMAIN_RECENT: 'Domain registration is less than one year old.',
  INTEL_SAFE_BROWSING_THREAT:
    'A linked URL is listed as a current threat by Google Safe Browsing.',
  INTEL_TLS_EXPIRED: 'TLS certificate is expired.',
  INTEL_TLS_HOSTNAME_MISMATCH:
    'TLS certificate hostname does not match the requested hostname.',
  INTEL_TLS_INVALID: 'TLS certificate validation failed.',
  CORR_NEW_DOMAIN_CREDENTIAL_REQUEST:
    'Recently registered domain combined with a credential/account authentication request.',
  CORR_NEW_DOMAIN_BRAND_IMPERSONATION:
    'Recently registered domain combined with brand impersonation.',
  CORR_THREAT_CREDENTIAL_REQUEST:
    'Confirmed threat URL combined with a credential/account authentication request.',
  CORR_SHORTENER_CREDENTIAL_REQUEST:
    'Shortened link combined with a credential/account authentication request.',
  CORR_BRAND_URL_CREDENTIAL:
    'Brand impersonation, visible-link destination mismatch, and a credential request appear together.',
  CORR_AUTH_CREDENTIAL_REQUEST:
    'Hard authentication failure combined with a credential/account authentication request.',
  CORR_TLS_CREDENTIAL_REQUEST:
    'TLS certificate problem combined with a credential/account authentication request.',
  CORR_NEW_DOMAIN_BRAND_CREDENTIAL:
    'Newly registered domain impersonating a brand while requesting credentials.',
}

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

export function severityRank(severity) {
  const rank = SEVERITY_ORDER[(severity || '').toUpperCase()]
  return typeof rank === 'number' ? rank : 99
}

/** Human label for a rule ID; falls back to a generic label — the raw
 *  rule ID is never the primary user-facing label. */
export function evidenceLabel(ruleId) {
  if (!ruleId) return 'Security indicator'
  return EVIDENCE_LABELS[ruleId] || 'Security indicator'
}

/** True when a finding is a correlation (a relationship between signals,
 *  not an underlying signal itself). */
export function isCorrelation(finding) {
  return (finding?.rule_id || '').startsWith('CORR_')
}

/** Signals contributing to a Session D correlation, by backend rule ID.
 *  The backend's correlation finding is authoritative; this only names
 *  the participating signals in human terms. */
export const CORRELATION_CONTRIBUTORS = {
  CORR_NEW_DOMAIN_CREDENTIAL_REQUEST: [
    'Recently registered domain',
    'Credential/account authentication request',
  ],
  CORR_NEW_DOMAIN_BRAND_IMPERSONATION: [
    'Recently registered domain',
    'Brand impersonation',
  ],
  CORR_THREAT_CREDENTIAL_REQUEST: [
    'Threat intelligence match',
    'Credential/account authentication request',
  ],
  CORR_SHORTENER_CREDENTIAL_REQUEST: [
    'Shortened link',
    'Credential/account authentication request',
  ],
  CORR_BRAND_URL_CREDENTIAL: [
    'Brand impersonation',
    'Visible link does not match destination',
    'Credential/account authentication request',
  ],
  CORR_AUTH_CREDENTIAL_REQUEST: [
    'SPF, DKIM, or DMARC returned an explicit failure',
    'Credential/account authentication request',
  ],
  CORR_TLS_CREDENTIAL_REQUEST: [
    'TLS certificate problem',
    'Credential/account authentication request',
  ],
  CORR_NEW_DOMAIN_BRAND_CREDENTIAL: [
    'Recently registered domain',
    'Brand impersonation',
    'Credential/account authentication request',
  ],
}

/** Human label + one-line summary for a correlation finding. */
export function correlationParts(finding) {
  const ruleId = finding?.rule_id || ''
  return {
    label: EVIDENCE_LABELS[ruleId] || 'Correlated evidence',
    summary: EVIDENCE_SUMMARY[ruleId] || finding?.message || '',
    contributors: CORRELATION_CONTRIBUTORS[ruleId] || [],
    evidenceText: finding?.evidence || '',
    severity: (finding?.severity || '').toUpperCase(),
  }
}

/**
 * Build the evidence chain for the "Why MailBuddy flagged this" card.
 *
 * Underlying evidence and correlations are returned as separate groups so
 * an underlying signal and its correlation are clearly distinct (the TLS
 * mismatch and "TLS anomaly + credential request" never look like the
 * same thing observed twice). Sorted by backend severity — presentation
 * ordering only, no new scoring.
 */
export function buildEvidenceChain(findings) {
  const list = Array.isArray(findings) ? findings.filter(Boolean) : []
  const underlying = []
  const correlations = []

  for (const f of list) {
    const item = {
      rule_id: f.rule_id || '',
      label: evidenceLabel(f.rule_id),
      summary: EVIDENCE_SUMMARY[f.rule_id] || f.message || '',
      severity: (f.severity || '').toUpperCase(),
      category: f.category || '',
      points: typeof f.points === 'number' ? f.points : 0,
      message: f.message || '',
      explanation: f.explanation || '',
      evidence_text: f.evidence || '',
      source: f.source || '',
    }
    if (isCorrelation(f)) {
      correlations.push(item)
    } else {
      underlying.push(item)
    }
  }

  const bySeverity = (a, b) =>
    severityRank(a.severity) - severityRank(b.severity) ||
    Math.abs(b.points) - Math.abs(a.points)

  return {
    underlying: underlying.sort(bySeverity),
    correlations: correlations.sort(bySeverity),
    total: list.length,
  }
}
