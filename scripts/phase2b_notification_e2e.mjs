#!/usr/bin/env node
/**
 * TEST 2 orchestrator — Windows notification end-to-end validation.
 *
 * Steps (no app/source changes; pure observation + one ingestion POST):
 *   1. Attach to the packaged app window over CDP.
 *   2. Install an IPC spy: wraps window.electronAPI.showNotification so the
 *      EXACT title/body crossing the Electron IPC boundary is captured, then
 *      calls through to the real main-process toast.
 *   3. POST a CRITICAL-class .eml to the real ingestion endpoint
 *      (/api/analyze/eml) so the backend queues a notification (dedup ledger).
 *   4. Wait for the renderer's 60s NotificationBridge poll to fire, and verify:
 *        - pending queue returned the notification to the renderer
 *        - electronAPI.showNotification was invoked with MailBuddy branding
 *        - title/body contain the queued email's subject/priority
 *        - queue drained (acked) afterwards
 *   5. The native Windows toast is displayed by the real main-process code
 *      (the spy does not suppress it); the user visually confirms on screen.
 *
 * Usage: node phase2b_notification_e2e.mjs <cdpPort> <emlPath> [timeoutS]
 */
import http from 'http';
import fs from 'node:fs';
import crypto from 'node:crypto';

const PORT = process.argv[2] || '9348';
const EML_PATH = process.argv[3] || 'datasets/validation_critical_test.eml';
const TIMEOUT_S = Number(process.argv[4] || 150);
const BASE = `http://127.0.0.1:${PORT}`;
const APP = 'http://localhost:8000';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function send(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1e9);
    const onMessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.id === id) {
        ws.removeEventListener('message', onMessage);
        data.error ? reject(new Error(JSON.stringify(data.error))) : resolve(data.result);
      }
    };
    ws.addEventListener('message', onMessage);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

const pages = await new Promise((resolve, reject) => {
  http.get(`${BASE}/json/list`, (res) => {
    let d = '';
    res.on('data', (c) => (d += c));
    res.on('end', () => resolve(JSON.parse(d)));
  }).on('error', reject);
});
const target = pages.filter((t) => t.type === 'page')[0];
if (!target) { console.log('[FAIL] no page target — is the app running with CDP?'); process.exit(1); }
const ws = await new Promise((resolve, reject) => {
  const s = new WebSocket(`ws://127.0.0.1:${PORT}/devtools/page/${target.id}`);
  s.onopen = () => resolve(s);
  s.onerror = reject;
});
await send(ws, 'Page.enable');

const evalJs = async (expr) => {
  const r = await send(ws, 'Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) return { __exception: r.exceptionDetails.text };
  return r.result?.value;
};

// ── Step 0: baseline ──────────────────────────────────────────────────────
const origin = await evalJs('location.origin');
if (origin !== APP) { console.log(`[FAIL] window origin is ${origin}, expected ${APP}`); process.exit(1); }
console.log(`window origin OK: ${origin}`);

const preQueue = await evalJs(`fetch('${APP}/api/mailbuddy/notifications/pending', { credentials: 'include' }).then(r => r.json())`);
console.log(`pre-ingest queue: ${JSON.stringify(preQueue)}`);

// ── Step 1: install the IPC spy (before ingesting, so nothing is missed) ──
const spyOk = await evalJs(`(() => {
  if (!window.electronAPI || typeof window.electronAPI.showNotification !== 'function') return false;
  if (window.__mbIpcSpy) return true;
  const real = window.electronAPI.showNotification.bind(window.electronAPI);
  window.__mbIpcSpy = { calls: [] };
  window.electronAPI.showNotification = (payload) => {
    window.__mbIpcSpy.calls.push({
      title: payload && payload.title,
      body: payload && payload.body,
      at: new Date().toISOString(),
    });
    return real(payload); // still deliver the REAL native toast
  };
  return true;
})()`);
if (!spyOk) { console.log('[FAIL] could not install IPC spy — electronAPI.showNotification missing'); process.exit(1); }
console.log('IPC spy installed on window.electronAPI.showNotification (pass-through to native)');

// ── Step 2: ingest the CRITICAL email through the real endpoint ───────────
const emlContent = fs.readFileSync(EML_PATH, 'utf8');
const boundary = '----MailBuddyValidation' + crypto.randomBytes(8).toString('hex');
const body = Buffer.concat([
  Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="validation_critical_test.eml"\r\nContent-Type: message/rfc822\r\n\r\n`),
  Buffer.from(emlContent, 'utf8'),
  Buffer.from(`\r\n--${boundary}--\r\n`),
]);
const upload = await evalJs(`fetch('${APP}/api/analyze/eml', {
  method: 'POST',
  credentials: 'include',
  body: (() => { const fd = new FormData(); fd.append('file', new File([${JSON.stringify(emlContent)}], 'validation_critical_test.eml', { type: 'message/rfc822' })); return fd; })(),
}).then(async r => ({ status: r.status, json: await r.json() })).catch(e => ({ fetchError: e.message }))`);
if (!upload || upload.fetchError || upload.status !== 200) {
  console.log(`[FAIL] /api/analyze/eml failed: ${JSON.stringify(upload).slice(0, 500)}`);
  process.exit(1);
}
const analysisId = upload.json.id;
const classification = upload.json.classification;
console.log(`ingested: analysis id=${analysisId} security=${classification} risk=${upload.json.risk_score}`);

// ── Step 3: verify the backend queued a notification for it ───────────────
let queued = null;
for (let i = 0; i < 10 && !queued; i++) {
  const q = await evalJs(`fetch('${APP}/api/mailbuddy/notifications/pending', { credentials: 'include' }).then(r => r.json())`);
  queued = (q.notifications || []).find((n) => n.email && n.email.id === analysisId) || null;
  if (!queued) await sleep(1000);
}
if (!queued) {
  console.log('[FAIL] backend did not queue a notification for the ingested email within 10s');
  const q = await evalJs(`fetch('${APP}/api/mailbuddy/notifications/pending', { credentials: 'include' }).then(r => r.json())`);
  console.log(`queue now: ${JSON.stringify(q)}`);
  process.exit(1);
}
console.log(`backend queued: key=${queued.key} priority=${queued.email.priority_level} subject="${queued.email.subject}"`);
if (!queued.key.startsWith('priority:CRITICAL:')) {
  console.log(`[FAIL] expected a CRITICAL notification key, got ${queued.key}`);
  process.exit(1);
}

// ── Step 4: wait for the renderer poll → IPC spy capture ──────────────────
console.log(`waiting up to ${TIMEOUT_S}s for NotificationBridge poll (60s cycle)...`);
const deadline = Date.now() + TIMEOUT_S * 1000;
let captured = null;
let bridgeState = '';
while (Date.now() < deadline) {
  await sleep(5000);
  const state = await evalJs(`JSON.stringify({
    calls: (window.__mbIpcSpy && window.__mbIpcSpy.calls) || [],
    bridge: !!(window.__mbIpcSpy),
  })`);
  const parsed = JSON.parse(state || '{}');
  bridgeState = state;
  if (parsed.calls && parsed.calls.length > 0) { captured = parsed.calls; break; }
}

if (!captured) {
  console.log('[FAIL] NotificationBridge never invoked the Electron IPC within the timeout');
  console.log(`spy state: ${bridgeState}`);
  process.exit(1);
}

// ── Step 5: verify payload correctness + branding ─────────────────────────
console.log('IPC captured:');
for (const c of captured) console.log(`  title="${c.title}" body="${c.body}" at=${c.at}`);
const call = captured.find((c) => (c.body || '').includes(queued.email.subject)) || captured[captured.length - 1];
const titleOk = call.title === 'MailBuddy';
const bodyOk = (call.body || '').includes('CRITICAL') && (call.body || '').includes(queued.email.subject);

const postQueue = await evalJs(`fetch('${APP}/api/mailbuddy/notifications/pending', { credentials: 'include' }).then(r => r.json())`);
const drained = !(postQueue.notifications || []).some((n) => n.email && n.email.id === analysisId);

console.log(`[${titleOk ? 'PASS' : 'FAIL'}] title is exactly "MailBuddy" (branding)`);
console.log(`[${bodyOk ? 'PASS' : 'FAIL'}] body contains priority "CRITICAL" + the queued subject`);
console.log(`[${drained ? 'PASS' : 'FAIL'}] notification queue drained after delivery (ack ledger)`);
console.log(`[PENDING-USER-CONFIRM] native Windows toast should now be visible on screen — confirm title "MailBuddy"`);
process.exit(titleOk && bodyOk ? 0 : 1);
