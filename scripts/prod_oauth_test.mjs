#!/usr/bin/env node
/**
 * Production OAuth regression — stage runner for the INSTALLED MailBuddy exe.
 * Stages:
 *   pre        — report window-side gmail status + session cookie fingerprint
 *   disconnect — POST /auth/google/disconnect from the app window, verify
 *   connect    — open Settings, click the real "Connect Gmail" button
 *                (window navigates to Google consent; then run watch_oauth_completion.mjs)
 * Usage: node scripts/prod_oauth_test.mjs <cdpPort> <stage: pre|disconnect|connect>
 */
import http from 'http';
import crypto from 'node:crypto';

const PORT = process.argv[2] || '9348';
const STAGE = process.argv[3] || 'pre';
const BASE = `http://127.0.0.1:${PORT}`;

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
  http.get(`${BASE}/json/list`, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => resolve(JSON.parse(d))); }).on('error', reject);
});
const target = pages.filter((t) => t.type === 'page')[0];
if (!target) { console.error('no page target'); process.exit(1); }
const ws = await new Promise((resolve, reject) => {
  const s = new WebSocket(`ws://127.0.0.1:${PORT}/devtools/page/${target.id}`);
  s.onopen = () => resolve(s); s.onerror = reject;
});
await send(ws, 'Page.enable');

const evalJs = async (expr) => {
  const r = await send(ws, 'Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error('eval failed: ' + JSON.stringify(r.exceptionDetails).slice(0, 200));
  return r.result?.value;
};

const cookies = await send(ws, 'Network.getCookies', { urls: ['http://localhost:8000'] });
const sess = cookies.cookies.find((c) => c.name === 'phishguard_session');

if (STAGE === 'pre') {
  const status = await evalJs(`fetch('/api/gmail/status', { credentials: 'include' }).then(r => r.json()).catch(e => ({ error: e.message }))`);
  console.log(JSON.stringify({
    url: await evalJs('location.href'),
    gmailStatus: status,
    sessionCookie: sess ? { domain: sess.domain, httpOnly: sess.httpOnly, expires: new Date(sess.expires * 1000).toISOString(), fp: crypto.createHash('sha256').update(sess.value).digest('hex').slice(0, 16) } : null,
  }, null, 2));
  process.exit(0);
}

if (STAGE === 'disconnect') {
  const res = await evalJs(`fetch('/auth/google/disconnect', { method: 'POST', credentials: 'include' }).then(async r => ({ status: r.status, body: await r.json().catch(() => null) }))`);
  const statusAfter = await evalJs(`fetch('/api/gmail/status', { credentials: 'include' }).then(r => r.json())`);
  const cookiesAfter = await send(ws, 'Network.getCookies', { urls: ['http://localhost:8000'] });
  const sessAfter = cookiesAfter.cookies.find((c) => c.name === 'phishguard_session');
  console.log(JSON.stringify({ disconnect: res, statusAfter, sessionCleared: !sessAfter }, null, 2));
  process.exit(res?.status === 200 ? 0 : 1);
}

if (STAGE === 'connect') {
  // Go to Settings and click the REAL Connect Gmail button (source of truth: the UI).
  await evalJs(`location.href = 'http://localhost:8000/settings'`);
  await new Promise((r) => setTimeout(r, 2500));
  const clicked = await evalJs(`(function(){
    const btns = [...document.querySelectorAll('button')];
    const b = btns.find(x => x.textContent.trim() === 'Connect Gmail');
    if (!b) return 'button-not-found';
    b.click();
    return 'clicked';
  })()`);
  console.log(`connect click: ${clicked}`);
  await new Promise((r) => setTimeout(r, 4000));
  const href = await evalJs('location.href');
  console.log(`window now at: ${href.slice(0, 140)}`);
  console.log(/accounts\.google\.com/.test(href) ? '[OK] Google consent page reached' : '[WARN] not on Google yet — check again');
  process.exit(0);
}

console.error('unknown stage: ' + STAGE);
process.exit(2);
