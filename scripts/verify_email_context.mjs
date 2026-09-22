#!/usr/bin/env node
/**
 * Email-context verification in the packaged app (correct row selector).
 * Usage: node verify_email_context.mjs <cdpPort>
 */
import http from 'http';

const PORT = process.argv[2] || '9348';
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
  http.get(`${BASE}/json/list`, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => resolve(JSON.parse(d))); }).on('error', reject);
});
const target = pages.filter((t) => t.type === 'page')[0];
const ws = await new Promise((resolve, reject) => {
  const s = new WebSocket(`ws://127.0.0.1:${PORT}/devtools/page/${target.id}`);
  s.onopen = () => resolve(s);
  s.onerror = reject;
});
await send(ws, 'Page.enable');
const evalJs = async (expr) => {
  const r = await send(ws, 'Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) return { __exc: JSON.stringify(r.exceptionDetails).slice(0, 200) };
  return r.result?.value;
};
const results = [];
const check = (name, ok, detail = '') => {
  results.push(ok);
  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? ` — ${detail}` : ''}`);
};

// Close any open panel, go to the emails list
await evalJs(`document.querySelector('.mb-assistant-close')?.click()`);
await send(ws, 'Page.navigate', { url: `${APP}/emails` });
await sleep(3000);

const rows = await evalJs(`document.querySelectorAll('table tbody tr').length`);
check('Email list has rows', rows > 0, `rows=${rows}`);

// Click the first row (tr onClick navigates)
await evalJs(`document.querySelector('table tbody tr').click()`);
await sleep(2500);
const path = await evalJs('location.pathname');
check('Navigated to email detail page', /^\/emails\/.+/.test(String(path)), String(path));

const askBtn = await evalJs(`(Array.from(document.querySelectorAll('button')).find(b => b.innerText.includes('Ask MailBuddy about this email')) || {}).innerText || null`);
check('Email page shows "Ask MailBuddy about this email"', !!askBtn, String(askBtn));

await evalJs(`Array.from(document.querySelectorAll('button')).find(b => b.innerText.includes('Ask MailBuddy about this email')).click()`);
await sleep(900);
const panel = await evalJs(`!!document.querySelector('.mb-assistant-panel')`);
const chipSubject = await evalJs(`(document.querySelector('.mb-context-subject') || {}).innerText || null`);
check('Email-context panel opened', panel === true);
check('Context chip shows current email subject', !!chipSubject, String(chipSubject));

await evalJs(`Array.from(document.querySelectorAll('.mb-assistant-chip')).find(b => b.innerText === 'Why was this flagged?')?.click()`);
let emailAnswer = null;
for (let i = 0; i < 30; i++) {
  await sleep(1000);
  const state = await evalJs(`JSON.stringify({
    busy: !!document.querySelector('.mb-msg-typing'),
    last: (Array.from(document.querySelectorAll('.mb-msg-assistant .mb-msg-bubble')).pop() || {}).innerText || null,
    err: (document.querySelector('.mb-assistant-error') || {}).innerText || null,
  })`);
  const s = JSON.parse(state);
  if ((s.last || s.err) && !s.busy) { emailAnswer = s; break; }
}
const answerOk = !!(emailAnswer && emailAnswer.last && !emailAnswer.err);
check('Email-context grounded answer produced', answerOk, ((emailAnswer && (emailAnswer.last || emailAnswer.err)) || '').slice(0, 180).replace(/\n/g, ' '));

const ok = results.every(Boolean);
console.log(ok ? '\n== EMAIL-CONTEXT VERIFICATION: ALL PASS ==' : '\n== SOME CHECKS FAILED ==');
process.exit(ok ? 0 : 1);
