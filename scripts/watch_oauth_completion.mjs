#!/usr/bin/env node
/**
 * Observational OAuth completion watcher.
 * Polls the window location until the REAL Google flow returns to the app
 * (http://localhost:8000), then verifies session + connection state.
 * NEVER navigates, closes, or interacts — read-only over CDP.
 *
 * Usage: node watch_oauth_completion.mjs <cdpPort> [timeoutSeconds]
 */
import http from 'http';

const PORT = process.argv[2] || '9348';
const TIMEOUT_S = Number(process.argv[3] || 300);
const BASE = `http://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function send(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1e9);
    const onMessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.id === id) { ws.removeEventListener('message', onMessage); data.error ? reject(new Error(JSON.stringify(data.error))) : resolve(data.result); }
    };
    ws.addEventListener('message', onMessage);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

const pages = await new Promise((resolve, reject) => {
  http.get(`${BASE}/json/list`, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => resolve(JSON.parse(d))); }).on('error', reject);
});
const target = pages.filter(t => t.type === 'page')[0];
const ws = await new Promise((resolve, reject) => {
  const s = new WebSocket(`ws://127.0.0.1:${PORT}/devtools/page/${target.id}`);
  s.onopen = () => resolve(s); s.onerror = reject;
});
await send(ws, 'Page.enable');

const evalJs = async (expr) => {
  const r = await send(ws, 'Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) return null;
  return r.result?.value;
};

console.log(`watching for OAuth completion (max ${TIMEOUT_S}s)...`);
const deadline = Date.now() + TIMEOUT_S * 1000;
let href = '';
while (Date.now() < deadline) {
  href = String(await evalJs('location.href') || '');
  if (href.startsWith('http://localhost:8000')) break;
  await sleep(3000);
}

if (!href.startsWith('http://localhost:8000')) {
  console.log(`[TIMEOUT] window still on: ${href.slice(0, 120)}`);
  process.exit(2);
}

// Back in the app — verify the post-auth state.
console.log(`returned to app: ${href}`);
await sleep(2500); // let React settle and verify the session

const status = await evalJs(`fetch('/api/gmail/status', { credentials: 'include' }).then(r => r.json()).catch(e => ({ error: e.message }))`);
console.log(`gmail status: ${JSON.stringify(status)}`);

const cookies = await send(ws, 'Network.getCookies', { urls: ['http://localhost:8000'] });
const sess = cookies.cookies.find(c => c.name === 'phishguard_session');
console.log(`session cookie: ${sess ? `present @ ${sess.domain} (httpOnly=${sess.httpOnly}, expires=${new Date(sess.expires * 1000).toISOString()})` : 'MISSING'}`);

const sameOriginOk = href.startsWith('http://localhost:8000/settings');
const not5173 = !href.includes(':5173');
const not127 = !href.includes('127.0.0.1');
console.log(`[${sameOriginOk ? 'PASS' : 'FAIL'}] landed on localhost:8000/settings (got ${href})`);
console.log(`[${not5173 ? 'PASS' : 'FAIL'}] no :5173 in final URL`);
console.log(`[${not127 ? 'PASS' : 'FAIL'}] no 127.0.0.1 in final URL`);
console.log(`[${status && status.connected ? 'PASS' : 'FAIL'}] /api/gmail/status connected=${status && status.connected} email=${status && status.email}`);
console.log(`[${sess && sess.domain === 'localhost' ? 'PASS' : 'FAIL'}] phishguard_session on host localhost (matches window origin)`);
process.exit(status && status.connected && sameOriginOk && sess ? 0 : 1);
