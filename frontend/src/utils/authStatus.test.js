/**
 * F-24: authentication verdict derivation tests.
 *
 * Runs with Node's built-in test runner (no test dependencies added):
 *   cd frontend && node --test src/utils/authStatus.test.js
 *
 * Core regression: SPF softfail must render as SOFTFAIL, never as FAIL —
 * softfail is a weak signal, not a hard authentication failure.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { getAuthStatus, authStatusMeta } from './authStatus.js'

const f = (rule_id, evidence) => ({ rule_id, evidence })

test('SPF softfail is distinct from fail (F-24 core regression)', () => {
  const findings = [f('HEADER_SPF_SOFTFAIL', 'SPF result: softfail')]
  assert.equal(getAuthStatus(findings, 'spf'), 'softfail')
  assert.notEqual(getAuthStatus(findings, 'spf'), 'fail')
  assert.equal(authStatusMeta(getAuthStatus(findings, 'spf')).label, 'SOFTFAIL')
})

test('SPF hard fail renders as FAIL', () => {
  const findings = [f('HEADER_SPF_FAIL', 'SPF result: fail')]
  assert.equal(getAuthStatus(findings, 'spf'), 'fail')
  assert.equal(authStatusMeta('fail').label, 'FAIL')
})

test('SPF pass via HEADER_AUTH_ALL_PASS evidence', () => {
  const findings = [f('HEADER_AUTH_ALL_PASS', 'SPF: pass, DKIM: pass, DMARC: pass')]
  assert.equal(getAuthStatus(findings, 'spf'), 'pass')
  assert.equal(getAuthStatus(findings, 'dkim'), 'pass')
  assert.equal(getAuthStatus(findings, 'dmarc'), 'pass')
  assert.equal(authStatusMeta('pass').label, 'PASS')
})

test('SPF none renders as NONE', () => {
  assert.equal(getAuthStatus([f('HEADER_SPF_NONE', 'SPF result: none')], 'spf'), 'none')
  assert.equal(authStatusMeta('none').label, 'NONE')
})

test('SPF neutral renders as NEUTRAL', () => {
  assert.equal(getAuthStatus([f('HEADER_SPF_NEUTRAL', 'SPF result: neutral')], 'spf'), 'neutral')
  assert.equal(authStatusMeta('neutral').label, 'NEUTRAL')
})

test('SPF permerror/temperror render as ERROR', () => {
  assert.equal(getAuthStatus([f('HEADER_SPF_ERROR', 'SPF result: permerror')], 'spf'), 'error')
  assert.equal(authStatusMeta('error').label, 'ERROR')
})

test('no authentication findings -> UNKNOWN', () => {
  assert.equal(getAuthStatus([], 'spf'), 'unknown')
  assert.equal(getAuthStatus([f('CONTENT_URGENCY')], 'spf'), 'unknown')
  assert.equal(authStatusMeta('unknown').label, 'UNKNOWN')
})

test('hard fail wins over softfail when both present', () => {
  const findings = [f('HEADER_SPF_SOFTFAIL'), f('HEADER_SPF_FAIL')]
  assert.equal(getAuthStatus(findings, 'spf'), 'fail')
})

test('DKIM/DMARC verdict states', () => {
  assert.equal(getAuthStatus([f('HEADER_DKIM_FAIL')], 'dkim'), 'fail')
  assert.equal(getAuthStatus([f('HEADER_DKIM_NONE')], 'dkim'), 'none')
  assert.equal(getAuthStatus([f('HEADER_DKIM_ERROR')], 'dkim'), 'error')
  assert.equal(getAuthStatus([f('HEADER_DMARC_FAIL')], 'dmarc'), 'fail')
  assert.equal(getAuthStatus([f('HEADER_DMARC_NONE')], 'dmarc'), 'none')
  assert.equal(getAuthStatus([f('HEADER_DMARC_ERROR')], 'dmarc'), 'error')
})

test('softfail is styled as a warning, not a hard-failure color', () => {
  // .warn maps to the existing amber (suspicious) token — NOT .fail (red).
  assert.equal(authStatusMeta('softfail').cls, 'warn')
  assert.notEqual(authStatusMeta('softfail').cls, 'fail')
})

test('DKIM/DMARC have no softfail/neutral rule ids (SPF-only states)', () => {
  assert.equal(getAuthStatus([f('HEADER_SPF_SOFTFAIL')], 'dkim'), 'unknown')
  assert.equal(getAuthStatus([f('HEADER_SPF_NEUTRAL')], 'dmarc'), 'unknown')
})
