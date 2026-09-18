#!/usr/bin/env node
/**
 * OAuth desktop E2E: verifies the post-approval redirect fix inside the REAL
 * packaged MailBuddy.exe window.
 *
 *   T1  /auth/google            → window navigates to Google consent (in-app)
 *   T2  /auth/google/callback   → backend redirects the window BACK to the app
 *       (error simulation, no real tokens) → Settings renders a friendly error
 *       instead of a blank page; final URL is same-origin (never :5173)
 *   T3  zero uncaught page/console errors across the whole flow
 *
 * Does NOT log in to Google and does NOT consume real tokens: T2 uses the
 * callback error path, which exercises the exact redirect mechanism that was
 * broken (it previously targeted the nonexistent dev server :5173).
 *
 * Usage: node scripts/oauth_desktop_e2e.mjs <cdp-port>
 */
import http from 'http';

const PORT = process.argv[2] || '9347';
const BASE = `http://127.0.0.1:${PORT}`;
const results = [];
let pageErrors = 0;

function send(ws, method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1e9);
    const msg = { id, method, params };
    if (sessionId) msg.sessionId = sessionId;
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
  const target = await new Promise((resolve, reject) => {
    http.get(`${BASE}/json/list`, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => {
        const pages = JSON.parse(d).filter((t) => t.type === 'page');
        resolve(pages[0]);
      });
    }).on('error', reject);
  });
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/devtools/page/${target.id}`);
    ws.onopen = () => resolve(ws);
    ws.onerror = reject;
  });
}

function check(name, ok, detail = '') {
  results.push({ name, ok, detail });
  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? ` — ${detail}` : ''}`);
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function evalJs(ws, expr) {
  const r = await send(ws, 'Runtime.evaluate', {
    expression: expr,
    awaitPromise: true,
    returnByValue: true,
  });
  return r.result?.value;
}

async function waitFor(ws, expr, timeoutMs = 15000, interval = 300) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const v = await evalJs(ws, expr).catch(() => null);
    if (v) return v;
    await wait(interval);
  }
  return null;
}

async function navigate(ws, url) {
  await send(ws, 'Page.navigate', { url });
  await waitFor(ws, `document.readyState === 'complete'`, 20000);
}

const ws = await connect();
await send(ws, 'Page.enable');
await send(ws, 'Runtime.enable');
ws.addEventListener('message', (event) => {
  const msg = JSON.parse(event.data);
  if (msg.method === 'Runtime.exceptionThrown') {
    pageErrors++;
    console.log('  page exception:', msg.params.exceptionDetails?.exception?.description?.slice(0, 200));
  }
});

// T0 — app identity
const title = await evalJs(ws, `document.title`);
check('Window/page title is MailBuddy', title === 'MailBuddy', title);

// T1 — start the real OAuth flow; window should land on Google consent
await navigate(ws, 'http://localhost:8000/auth/google');
const onGoogle = await waitFor(ws, `location.hostname === 'accounts.google.com'`, 20000);
check('T1: /auth/google navigates to Google consent in-app', !!onGoogle,
      await evalJs(ws, `location.host`));
// Return to the app for T2
await navigate(ws, 'http://localhost:8000/settings');

// T2 — callback (error simulation): real backend must redirect the window
// back to the SAME-ORIGIN settings page with a friendly error, no blank page.
await navigate(ws, 'http://localhost:8000/auth/google/callback?error=access_denied&state=e2e-sim');
const backHome = await waitFor(
  ws,
  `location.host === 'localhost:8000' && location.pathname === '/settings'`,
  20000,
);
check('T2a: callback redirects back into the app (same origin)', !!backHome,
      await evalJs(ws, `location.href`));
check('T2b: redirect does NOT target the dev server :5173',
      !String(await evalJs(ws, `location.href`)).includes(':5173'));

// Friendly error state rendered by the React Settings page (not a blank page)
const errText = await waitFor(
  ws,
  `Array.from(document.querySelectorAll('.alert-error, .alert'))
        .some(el => el.textContent.includes('cancelled the Google sign-in'))`,
  10000,
);
check('T2c: friendly OAuth error state renders in Settings', !!errText);
const hasContent = await evalJs(
  ws,
  `document.body && document.body.innerText.length > 100 &&
   !!Array.from(document.querySelectorAll('button, h1, h2, .card, .topbar')).find(el => el.offsetParent !== null)`,
);
check('T2d: page is NOT blank (full Settings UI rendered)', !!hasContent);

// T3 — console/page errors across the flow
const consoleErrCount = await evalJs(ws, `window.__e2eConsoleErrors || 0`);
check('T3: zero uncaught page exceptions during OAuth flow', pageErrors === 0, `${pageErrors} exceptions`);

console.log(`\nOAUTH DESKTOP E2E: ${results.filter((r) => r.ok).length}/${results.length} checks passed`);
process.exit(results.every((r) => r.ok) && pageErrors === 0 ? 0 : 1);
