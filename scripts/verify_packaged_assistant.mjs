#!/usr/bin/env node
/**
 * Packaged-app verification for the MailBuddy Assistant feature.
 * Drives the real UI over CDP: sidebar button, panel, global chat,
 * email page button, email-context chat. Read-only w.r.t. email data.
 * Usage: node verify_packaged_assistant.mjs <cdpPort>
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
if (!target) { console.log('[FAIL] no page target'); process.exit(1); }
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

await sleep(3000); // let the SPA settle

// 0. OAuth session intact after reinstall
const status = await evalJs(`fetch('/api/gmail/status', { credentials: 'include' }).then(r => r.json())`);
check('Gmail session survived reinstall (OAuth untouched)', status && status.connected === true, `email=${status && status.email}`);

// 1. Sidebar "Ask MailBuddy" exists
const sidebarBtn = await evalJs(`!!document.querySelector('.sidebar-assistant-btn') && document.querySelector('.sidebar-assistant-btn').innerText.trim()`);
check('Sidebar shows "Ask MailBuddy"', sidebarBtn === 'Ask MailBuddy', String(sidebarBtn));

// 2. Click it → panel opens (global mode)
await evalJs(`document.querySelector('.sidebar-assistant-btn').click()`);
await sleep(600);
let panel = await evalJs(`!!document.querySelector('.mb-assistant-panel')`);
check('Assistant panel opens from sidebar', panel === true);
const ctxChip = await evalJs(`!!document.querySelector('.mb-context-chip')`);
check('Global mode has NO email context chip', ctxChip === false);

// 3. Global suggestions rendered
const chips = await evalJs(`Array.from(document.querySelectorAll('.mb-assistant-chip')).map(b => b.innerText)`);
check('Global suggestions rendered', Array.isArray(chips) && chips.length >= 4, JSON.stringify(chips).slice(0, 120));

// 4. Send a real question via the input (end-to-end through packaged backend + Groq)
await evalJs(`
  const input = document.querySelector('.mb-assistant-input input');
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
  setter.call(input, 'What needs my attention?');
  input.dispatchEvent(new Event('input', { bubbles: true }));
`);
await sleep(200);
await evalJs(`document.querySelector('.mb-assistant-input button[type=submit]').click()`);
let answer = null;
for (let i = 0; i < 30; i++) {
  await sleep(1000);
  const state = await evalJs(`JSON.stringify({
    msgs: Array.from(document.querySelectorAll('.mb-msg')).length,
    busy: !!document.querySelector('.mb-msg-typing'),
    last: (Array.from(document.querySelectorAll('.mb-msg-assistant .mb-msg-bubble')).pop() || {}).innerText || null,
    refs: document.querySelectorAll('.mb-ref-card').length,
    err: (document.querySelector('.mb-assistant-error') || {}).innerText || null,
  })`);
  const s = JSON.parse(state);
  if (s.last && !s.busy) { answer = s; break; }
  if (s.err && !s.busy) { answer = s; break; }
}
check('Global chat round-trip produced an answer', !!(answer && answer.last), (answer && answer.last || '').slice(0, 140).replace(/\n/g, ' '));
check('Answer carries clickable email references', !!(answer && answer.refs > 0), `refs=${answer && answer.refs}`);

// 5. Navigate to an email page → "Ask MailBuddy about this email" button
await send(ws, 'Page.navigate', { url: `${APP}/emails` });
await sleep(2500);
await evalJs(`(document.querySelector('table tbody tr a, .email-row a, a[href^="/emails/"]') || {}).click?.()`);
await sleep(2500);
const onEmail = await evalJs(`location.pathname.startsWith('/emails/') && location.pathname.length > 8`);
check('Navigated to an email detail page', onEmail === true, await evalJs('location.pathname'));
const askBtn = await evalJs(`(Array.from(document.querySelectorAll('button')).find(b => b.innerText.includes('Ask MailBuddy about this email')) || {}).innerText || null`);
check('Email page shows "Ask MailBuddy about this email"', !!askBtn, String(askBtn));

// 6. Click it → panel opens in email-context mode
await evalJs(`Array.from(document.querySelectorAll('button')).find(b => b.innerText.includes('Ask MailBuddy about this email')).click()`);
await sleep(800);
panel = await evalJs(`!!document.querySelector('.mb-assistant-panel')`);
const chipSubject = await evalJs(`(document.querySelector('.mb-context-subject') || {}).innerText || null`);
check('Email-context panel opened', panel === true);
check('Context chip shows the current email subject', !!chipSubject, String(chipSubject));

// 7. Email-context suggestion → grounded answer about THIS email
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
check('Email-context answer produced', !!(emailAnswer && (emailAnswer.last || emailAnswer.err)), ((emailAnswer && (emailAnswer.last || emailAnswer.err)) || '').slice(0, 160).replace(/\n/g, ' '));

const ok = results.every(Boolean);
console.log(ok ? '\n== PACKAGED ASSISTANT VERIFICATION: ALL PASS ==' : '\n== SOME CHECKS FAILED ==');
process.exit(ok ? 0 : 1);
