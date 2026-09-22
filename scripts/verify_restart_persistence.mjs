#!/usr/bin/env node
/**
 * Restart-persistence verification (TEST 1 final check).
 * Connects to the freshly restarted app over CDP and verifies, WITHOUT any
 * interaction or navigation:
 *   1. the app window is on the app origin (no re-auth redirect)
 *   2. the phishguard_session cookie fingerprint matches the pre-restart value
 *   3. /api/gmail/status reports connected with the expected account
 *
 * Usage: node verify_restart_persistence.mjs <cdpPort> <expectedFp> <expectedEmail>
 */
import http from 'http';

const PORT = process.argv[2] || '9348';
const EXPECTED_FP = process.argv[3] || '';
const EXPECTED_EMAIL = process.argv[4] || '';
const BASE = `http://127.0.0.1:${PORT}`;
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
if (!target) { console.log('[FAIL] no page target'); process.exit(1); }
const ws = await new Promise((resolve, reject) => {
  const s = new WebSocket(`ws://127.0.0.1:${PORT}/devtools/page/${target.id}`);
  s.onopen = () => resolve(s);
  s.onerror = reject;
});
await send(ws, 'Page.enable');
await send(ws, 'Network.enable');

const evalJs = async (expr) => {
  const r = await send(ws, 'Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) return null;
  return r.result?.value;
};

await sleep(2500); // let the SPA settle after startup

const href = String(await evalJs('location.href') || '');
const onGoogle = href.includes('accounts.google.com');
const status = await evalJs(`fetch('/api/gmail/status', { credentials: 'include' }).then(r => r.json()).catch(e => ({ fetchError: e.message }))`);
const cookies = await send(ws, 'Network.getCookies', { urls: ['http://localhost:8000'] });
const sess = cookies.cookies.find((c) => c.name === 'phishguard_session');

let fp = '(none)';
if (sess) {
  const { createHash } = await import('node:crypto');
  fp = createHash('sha256').update(sess.value).digest('hex').slice(0, 16);
}

console.log(`window URL        : ${href}`);
console.log(`session fp        : ${fp} (expected ${EXPECTED_FP})`);
console.log(`cookie domain     : ${sess ? sess.domain : 'MISSING'}`);
console.log(`gmail status      : ${JSON.stringify(status)}`);

const noReauth = href.startsWith('http://localhost:8000') && !onGoogle;
const fpMatch = EXPECTED_FP ? fp === EXPECTED_FP : sess != null;
const connected = status && status.connected === true;
const emailOk = EXPECTED_EMAIL ? status && status.email === EXPECTED_EMAIL : connected;
const cookieHostOk = sess && sess.domain === 'localhost';

console.log(`[${noReauth ? 'PASS' : 'FAIL'}] no re-authentication (window on app origin, not Google)`);
console.log(`[${fpMatch ? 'PASS' : 'FAIL'}] session cookie IDENTICAL to pre-restart fingerprint`);
console.log(`[${cookieHostOk ? 'PASS' : 'FAIL'}] phishguard_session still on host localhost`);
console.log(`[${connected ? 'PASS' : 'FAIL'}] Gmail status connected=true after restart`);
console.log(`[${emailOk ? 'PASS' : 'FAIL'}] connected account is ${EXPECTED_EMAIL || '(any)'}`);

process.exit(noReauth && fpMatch && cookieHostOk && connected && emailOk ? 0 : 1);
