#!/usr/bin/env node
/**
 * Fingerprint the live session cookie in the app window over CDP.
 * Usage: node get_session_fp.mjs <cdpPort>
 */
import http from 'http';
import crypto from 'node:crypto';

const PORT = process.argv[2] || '9348';
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
  http.get(`${BASE}/json/list`, (res) => {
    let d = '';
    res.on('data', (c) => (d += c));
    res.on('end', () => resolve(JSON.parse(d)));
  }).on('error', reject);
});
const target = pages.filter((t) => t.type === 'page')[0];
if (!target) { console.error('[FAIL] no page target'); process.exit(1); }
const ws = await new Promise((resolve, reject) => {
  const s = new WebSocket(`ws://127.0.0.1:${PORT}/devtools/page/${target.id}`);
  s.onopen = () => resolve(s);
  s.onerror = reject;
});

const cookies = await send(ws, 'Network.getCookies', { urls: ['http://localhost:8000'] });
const sess = cookies.cookies.find((c) => c.name === 'phishguard_session');
if (!sess) { console.error('[FAIL] phishguard_session missing'); process.exit(1); }
const hash = crypto.createHash('sha256').update(sess.value).digest('hex').slice(0, 16);
console.log(`fp=${hash}`);
console.log(`domain=${sess.domain} httpOnly=${sess.httpOnly} expires=${new Date(sess.expires * 1000).toISOString()}`);
process.exit(0);
