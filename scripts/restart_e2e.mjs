#!/usr/bin/env node
/**
 * Restart-persistence E2E (Defect-1 acceptance test) — installed-app edition.
 *
 * Simulates the exact cookie the Google OAuth callback sets (host `localhost`,
 * 7-day max-age), verifies the installed app reports Gmail connected, then the
 * caller restarts the app via the Start Menu shortcut and the `verify` phase
 * confirms the connection survived WITHOUT re-authenticating.
 *
 * Usage: node restart_e2e.mjs <cdpPort> <phase: seed|verify>
 */
import http from 'http';

const PORT = process.argv[2] || '9348';
const PHASE = process.argv[3] || 'seed';
const BASE = `http://127.0.0.1:${PORT}`;
const SESSION_ID = 'e2e-restart-persistence-session-0001';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function send(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1e9);
    const msg = { id, method, params };
    const onMessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.id === id) {
        ws.removeEventListener('message', onMessage);
        data.error ? reject(new Error(JSON.stringify(data.error))) : resolve(data.result);
      }
    };
    ws.addEventListener('message', onMessage);
    ws.send(JSON.stringify(msg));
  });
}

async function connect() {
  let target = null;
  for (let i = 0; i < 60; i++) {
    try {
      const pages = await new Promise((resolve, reject) => {
        http.get(`${BASE}/json/list`, (res) => {
          let d = '';
          res.on('data', (c) => (d += c));
          res.on('end', () => resolve(JSON.parse(d).filter((t) => t.type === 'page')));
        }).on('error', reject);
      });
      target = pages[0];
      if (target) break;
    } catch {}
    await sleep(500);
  }
  if (!target) throw new Error('No page target found');
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/devtools/page/${target.id}`);
    ws.onopen = () => resolve(ws);
    ws.onerror = reject;
  });
}

const evalJs = async (ws, expr) => {
  const r = await send(ws, 'Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text);
  return r.result?.value;
};

const ws = await connect();
await send(ws, 'Page.enable');
await send(ws, 'Network.enable');

const origin = await evalJs(ws, 'location.origin');
console.log(`window origin: ${origin}`);
if (origin !== 'http://localhost:8000') {
  console.log(`[FAIL] window origin must be http://localhost:8000 (got ${origin})`);
  process.exit(1);
}

if (PHASE === 'seed') {
  // Set the cookie EXACTLY as the backend OAuth callback would: host localhost,
  // path /, 7-day expiry (persistent cookie, survives restart), httpOnly.
  const expires = Math.floor(Date.now() / 1000) + 86400 * 7;
  const ok = await send(ws, 'Network.setCookie', {
    name: 'phishguard_session',
    value: SESSION_ID,
    domain: 'localhost',
    path: '/',
    expires,
    httpOnly: true,
    secure: false,
  });
  if (!ok.success) { console.log('[FAIL] could not set session cookie'); process.exit(1); }
  console.log('session cookie set (host localhost, 7d, httpOnly)');
}

await send(ws, 'Page.navigate', { url: 'http://localhost:8000/settings' });
await sleep(3000);

const status = await evalJs(ws,
  `fetch('/api/gmail/status', { credentials: 'include' }).then(r => r.json())`);
console.log(`phase=${PHASE} gmail status: ${JSON.stringify(status)}`);

const connected = status.connected === true && status.email === 'restart-e2e@example.com';
if (connected) {
  console.log(`[PASS] phase=${PHASE}: Gmail connection ${PHASE === 'seed' ? 'established with seeded session' : 'PERSISTED across restart'}`);
} else {
  console.log(`[FAIL] phase=${PHASE}: expected connected=true for restart-e2e@example.com`);
}

// Close the app gracefully so the backend shuts down before the next phase.
await evalJs(ws, 'window.close()').catch(() => {});
await sleep(3000);
process.exit(connected ? 0 : 1);
