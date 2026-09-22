#!/usr/bin/env node
/**
 * Settings-page load verification (validation tooling only — no app changes).
 * Connects to the packaged app's CDP endpoint, navigates the app window to
 * /settings, and verifies the page renders with the connected Gmail account.
 *
 * Usage: node verify_settings.mjs <cdpPort> <expectedEmail>
 */
import http from 'http';

const PORT = process.argv[2] || '9348';
const EXPECTED_EMAIL = process.argv[3] || '';
const BASE = `http://127.0.0.1:${PORT}`;
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

const originBefore = await evalJs('location.origin');
console.log(`origin before: ${originBefore}`);

await send(ws, 'Page.navigate', { url: 'http://localhost:8000/settings' });
await sleep(3500);

const href = String(await evalJs('location.href') || '');
const h1 = String(await evalJs('document.querySelector("h1")?.innerText') || '');
const body = String(await evalJs('document.body.innerText') || '');
const cookies = await send(ws, 'Network.getCookies', { urls: ['http://localhost:8000'] });
const sess = cookies.cookies.find((c) => c.name === 'phishguard_session');

console.log(`final URL      : ${href}`);
console.log(`page h1        : ${h1}`);
const emailShown = EXPECTED_EMAIL && body.includes(EXPECTED_EMAIL);
console.log(`email in page  : ${emailShown ? EXPECTED_EMAIL : '(not found)'}`);
console.log(`session cookie : ${sess ? `present @ ${sess.domain}` : 'MISSING'}`);

const originOk = href.startsWith('http://localhost:8000/settings');
const not127 = !href.includes('127.0.0.1');
const not5173 = !href.includes(':5173');
const settingsRendered = h1.trim() === 'Settings' && body.includes('Gmail Connection');
const connectedShown = body.includes('Connected') && !body.includes('Not Connected');

console.log(`[${originOk ? 'PASS' : 'FAIL'}] Settings URL stays on localhost:8000/settings`);
console.log(`[${not127 ? 'PASS' : 'FAIL'}] no 127.0.0.1 in URL`);
console.log(`[${not5173 ? 'PASS' : 'FAIL'}] no :5173 in URL`);
console.log(`[${settingsRendered ? 'PASS' : 'FAIL'}] Settings page rendered (h1 + Gmail Connection section)`);
console.log(`[${connectedShown ? 'PASS' : 'FAIL'}] shows Connected (not "Not Connected")`);
console.log(`[${emailShown ? 'PASS' : 'FAIL'}] connected account ${EXPECTED_EMAIL} displayed`);
console.log(`[${sess && sess.domain === 'localhost' ? 'PASS' : 'FAIL'}] phishguard_session still on localhost`);

process.exit(originOk && not127 && not5173 && settingsRendered && connectedShown && emailShown && sess ? 0 : 1);
