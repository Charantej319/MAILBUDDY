/**
 * Session E: evidence-chain helper tests (Repair 3).
 *
 * Runs with Node's built-in test runner (no test dependencies added):
 *   cd frontend && node --test src/utils/evidenceChain.test.js
 *
 * Verifies the presentation contract used by EmailAnalysis.jsx:
 * - human-readable labels exist for Session A–E rule IDs (rule IDs are never
 *   the primary label)
 * - correlations are reported separately from underlying signals, each
 *   finding counted exactly once (no duplicate rendering)
 * - correlation contributors name the participating signals
 * - presentation is derived ONLY from backend data (no risk recomputation)
 * - unknown rule IDs fall back safely instead of surfacing raw IDs as labels
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildEvidenceChain,
  evidenceLabel,
  isCorrelation,
  correlationParts,
  severityRank,
} from './evidenceChain.js'

const finding = (over = {}) => ({
  rule_id: 'URL_SHORTENER',
  category: 'URL',
  severity: 'LOW',
  points: 3,
  message: 'The message contains a shortened URL.',
  explanation: 'Shorteners hide the destination.',
  evidence: 'url: https://bit.ly/x',
  source: 'URL analyzer',
  ...over,
})

test('correlations are separated from underlying signals', () => {
  const chain = buildEvidenceChain([
    finding({ rule_id: 'INTEL_YOUNG_DOMAIN', category: 'INTEL', severity: 'MEDIUM', points: 8 }),
    finding({ rule_id: 'CONTENT_CREDENTIAL_REQUEST', category: 'CONTENT', severity: 'MEDIUM', points: 10 }),
    finding({ rule_id: 'CORR_NEW_DOMAIN_CREDENTIAL_REQUEST', category: 'CORRELATION', severity: 'MEDIUM', points: 3 }),
  ])
  assert.equal(chain.underlying.length, 2)
  assert.equal(chain.correlations.length, 1)
  assert.equal(chain.total, 3)
  assert.ok(chain.underlying.every(f => !f.rule_id.startsWith('CORR_')))
  assert.equal(chain.correlations[0].rule_id, 'CORR_NEW_DOMAIN_CREDENTIAL_REQUEST')
})

test('each finding appears exactly once in the chain (no duplicates)', () => {
  const findings = [
    finding({ rule_id: 'URL_SHORTENER' }),
    finding({ rule_id: 'URL_SHORTENER' }), // duplicated backend finding
    finding({ rule_id: 'CORR_SHORTENER_CREDENTIAL_REQUEST', category: 'CORRELATION' }),
  ]
  const chain = buildEvidenceChain(findings)
  const all = [...chain.underlying, ...chain.correlations]
  assert.equal(all.length, findings.length, 'chain must be 1:1 with backend findings')
})

test('human-readable labels exist for Session A–E rule IDs', () => {
  for (const ruleId of [
    'INTEL_YOUNG_DOMAIN',
    'INTEL_SAFE_BROWSING_THREAT',
    'INTEL_TLS_EXPIRED',
    'INTEL_TLS_HOSTNAME_MISMATCH',
    'CORR_NEW_DOMAIN_CREDENTIAL_REQUEST',
    'CORR_THREAT_CREDENTIAL_REQUEST',
    'CORR_TLS_CREDENTIAL_REQUEST',
  ]) {
    const label = evidenceLabel(ruleId)
    assert.notEqual(label, 'Security indicator', `missing label for ${ruleId}`)
    assert.notEqual(label, ruleId, 'label must not be the raw rule ID')
  }
})

test('unknown rule IDs fall back safely (never a raw ID as primary label)', () => {
  assert.equal(evidenceLabel('SOME_FUTURE_RULE'), 'Security indicator')
  assert.equal(evidenceLabel(''), 'Security indicator')
  assert.equal(evidenceLabel(undefined), 'Security indicator')
})

test('correlationParts exposes label, summary, contributors and evidence', () => {
  const f = finding({
    rule_id: 'CORR_NEW_DOMAIN_BRAND_CREDENTIAL',
    category: 'CORRELATION',
    severity: 'HIGH',
    points: 5,
    evidence: 'cred; young; brand',
  })
  const parts = correlationParts(f)
  assert.equal(parts.label, 'New domain + brand impersonation + credential request')
  assert.ok(parts.summary.length > 0)
  assert.equal(parts.contributors.length, 3)
  assert.ok(parts.contributors.some(c => /credential/i.test(c)))
  assert.ok(parts.contributors.some(c => /brand/i.test(c)))
  assert.ok(parts.contributors.some(c => /domain/i.test(c)))
  assert.equal(parts.evidenceText, 'cred; young; brand')
  assert.equal(parts.severity, 'HIGH')
})

test('chain sorting is severity-first (presentation order only)', () => {
  const chain = buildEvidenceChain([
    finding({ rule_id: 'URL_HTTP', severity: 'LOW', points: 1 }),
    finding({ rule_id: 'INTEL_SAFE_BROWSING_THREAT', category: 'INTEL', severity: 'HIGH', points: 10 }),
    finding({ rule_id: 'CONTENT_URGENCY', category: 'CONTENT', severity: 'MEDIUM', points: 5 }),
  ])
  assert.deepEqual(chain.underlying.map(f => f.severity), ['HIGH', 'MEDIUM', 'LOW'])
})

test('isCorrelation and severityRank behave as EmailAnalysis relies on', () => {
  assert.ok(isCorrelation(finding({ rule_id: 'CORR_X' })))
  assert.ok(!isCorrelation(finding({ rule_id: 'URL_X' })))
  assert.ok(severityRank('CRITICAL') < severityRank('HIGH'))
  assert.ok(severityRank('HIGH') < severityRank('MEDIUM'))
  assert.ok(severityRank('MEDIUM') < severityRank('LOW'))
  assert.equal(severityRank('UNKNOWN_STATE'), 99)
})

test('presentation carries backend values verbatim — no score recomputation', () => {
  const f = finding({ rule_id: 'INTEL_TLS_HOSTNAME_MISMATCH', category: 'INTEL', severity: 'MEDIUM', points: 4 })
  const chain = buildEvidenceChain([f])
  const item = chain.underlying[0]
  assert.equal(item.points, 4, 'points must pass through unchanged')
  assert.equal(item.severity, 'MEDIUM')
  assert.equal(item.rule_id, 'INTEL_TLS_HOSTNAME_MISMATCH')
  assert.equal(item.message, f.message)
  assert.equal(item.explanation, f.explanation)
  assert.equal(item.evidence_text, f.evidence)
  assert.equal(typeof item.points, 'number')
})

test('unavailable/error/unknown states stay neutral data (never "safe" or "malicious")', () => {
  // A Safe Browsing ERROR finding dict from the backend has no rule_id → it
  // never becomes a risk finding; the chain must not invent one.
  const chain = buildEvidenceChain([])
  assert.equal(chain.underlying.length, 0)
  assert.equal(chain.correlations.length, 0)
  assert.equal(chain.total, 0)
  // Malformed input degrades to an empty chain, not a crash.
  assert.equal(buildEvidenceChain(null).total, 0)
  assert.equal(buildEvidenceChain(undefined).total, 0)
  assert.equal(buildEvidenceChain([null, false]).total, 0)
})
