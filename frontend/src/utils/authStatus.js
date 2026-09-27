/**
 * F-24: Email authentication verdict derivation.
 *
 * The backend (detection/header_analyzer.py, F-5) emits DISTINCT rule ids
 * for each authentication verdict state:
 *
 *   SPF   : HEADER_SPF_FAIL / HEADER_SPF_SOFTFAIL / HEADER_SPF_NEUTRAL /
 *           HEADER_SPF_NONE / HEADER_SPF_ERROR
 *   DKIM  : HEADER_DKIM_FAIL / HEADER_DKIM_NONE / HEADER_DKIM_ERROR
 *   DMARC : HEADER_DMARC_FAIL / HEADER_DMARC_NONE / HEADER_DMARC_ERROR
 *
 * The raw spf/dkim/dmarc verdict strings are not serialized to the API
 * payload, so the UI derives the state from these findings.
 *
 * IMPORTANT: softfail is a *weak* negative signal, not a hard failure.
 * It must be shown as SOFTFAIL — never rendered as FAIL — so users are
 * not misled about how strongly authentication failed.
 *
 * A "pass" is only recorded by the backend as the combined
 * HEADER_AUTH_ALL_PASS finding (SPF + DKIM + DMARC all pass) whose
 * evidence carries per-protocol "SPF: pass" style tokens; there is no
 * individual pass finding.
 *
 * Display classes reuse the existing .intel-value CSS variants
 * (pass / fail / warn / none) so the visual design is unchanged.
 */

const FAIL_RULES = {
  spf: ['HEADER_SPF_FAIL'],
  dkim: ['HEADER_DKIM_FAIL'],
  dmarc: ['HEADER_DMARC_FAIL'],
}

const SOFTFAIL_RULES = {
  spf: ['HEADER_SPF_SOFTFAIL'],
  dkim: [],
  dmarc: [],
}

const NEUTRAL_RULES = {
  spf: ['HEADER_SPF_NEUTRAL'],
  dkim: [],
  dmarc: [],
}

const NONE_RULES = {
  spf: ['HEADER_SPF_NONE'],
  dkim: ['HEADER_DKIM_NONE'],
  dmarc: ['HEADER_DMARC_NONE'],
}

const ERROR_RULES = {
  spf: ['HEADER_SPF_ERROR'],
  dkim: ['HEADER_DKIM_ERROR'],
  dmarc: ['HEADER_DMARC_ERROR'],
}

/**
 * Derive the verdict state for one protocol from the email's findings.
 * Returns one of: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' |
 * 'error' | 'unknown'. Hard failure wins over weaker signals; unknown is
 * the fallback when no authentication evidence exists at all.
 */
export function getAuthStatus(findings, protocol) {
  if (!Array.isArray(findings) || !protocol) return 'unknown'
  const ruleIds = findings.map((f) => (f && f.rule_id) || null)
  const has = (rules) => (rules || []).some((r) => ruleIds.includes(r))

  if (has(FAIL_RULES[protocol])) return 'fail'
  if (has(SOFTFAIL_RULES[protocol])) return 'softfail'
  if (has(NEUTRAL_RULES[protocol])) return 'neutral'
  if (has(ERROR_RULES[protocol])) return 'error'
  if (has(NONE_RULES[protocol])) return 'none'

  const allPass = findings.find((f) => f && f.rule_id === 'HEADER_AUTH_ALL_PASS')
  if (allPass && allPass.evidence && allPass.evidence.includes(`${protocol.toUpperCase()}: pass`)) {
    return 'pass'
  }

  return 'unknown'
}

/** Display metadata per verdict state (label + existing CSS class). */
export const AUTH_STATUS_META = {
  pass: { label: 'PASS', cls: 'pass' },
  fail: { label: 'FAIL', cls: 'fail' },
  softfail: { label: 'SOFTFAIL', cls: 'warn' },
  neutral: { label: 'NEUTRAL', cls: 'warn' },
  none: { label: 'NONE', cls: 'none' },
  error: { label: 'ERROR', cls: 'warn' },
  unknown: { label: 'UNKNOWN', cls: 'none' },
}

export function authStatusMeta(status) {
  return AUTH_STATUS_META[status] || AUTH_STATUS_META.unknown
}
