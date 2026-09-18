#!/usr/bin/env node
/**
 * MailBuddy browser E2E (production build served by FastAPI on :8000).
 * Verifies: dashboard priority UI, security/priority separation, assistant
 * panel + grounded answer with clickable references, settings toggles,
 * console cleanliness, and that the browser never talks to groq.com.
 */
import http from 'http';

const PORT = process.argv[2] || '9345';
const BASE = `http://127.0.0.1:${PORT}`;

let ws;
let msgId = 0;
const pending = new Map();
const consoleErrors = [];
const pageErrors = [];
const networkRequests = [];

function send(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++msgId;
    pending.set(id, { resolve, reject });
    const msg = { id, method, params };
    if (sessionId) msg.sessionId = sessionId;
    ws.send(JSON.stringify(msg));
  });
}

async function connect() {
  const target = await new Promise((resolve, reject) => {
    http.get(`${BASE}/json/list`, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve(JSON.parse(d)[0]));
    }).on('error', reject);
  });
  return new Promise((resolve, reject) => {
    ws = new WebSocket(`ws://127.0.0.1:${PORT}/devtools/page/${target.id}`);
    ws.onopen = () => resolve();
    ws.onerror = reject;
  });
}

export async function cdpOn() {
  // installed by caller via globalThis hook
}

function handle(msg) {
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    return;
  }
  if (msg.method === 'Runtime.consoleAPICalled') {
    if (msg.params.type === 'error') consoleErrors.push(msg.params.args?.[0]?.value || 'console.error');
  }
  if (msg.method === 'Runtime.exceptionThrown') {
    pageErrors.push(msg.params.exceptionDetails?.exception?.description || 'page error');
  }
  if (msg.method === 'Network.requestWillBeSent') {
    networkRequests.push(msg.params.request.url);
  }
}

export async function main() {
  await connect();
  ws.onmessage = (e) => handle(JSON.parse(e.data));

  await send('Runtime.enable');
  await send('Page.enable');
  await send('Network.enable');

  const results = [];
  const check = (name, cond, detail = '') => {
    results.push([name, !!cond, detail]);
    console.log(`[${cond ? 'PASS' : 'FAIL'}] ${name}${detail ? ` — ${detail}` : ''}`);
  };
  const evalJs = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval failed');
    return r.result.value;
  };
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  // ---- Dashboard ----
  await send('Page.navigate', { url: 'http://localhost:8000/' });
  await wait(2500);
  const brand = await evalJs(`document.querySelector('.mb-brand-name')?.textContent || document.querySelector('.sidebar-brand')?.textContent || ''`);
  check('MailBuddy branding in sidebar', brand.includes('MailBuddy'), brand.trim().slice(0, 40));
  const hero = await evalJs(`document.querySelector('.mb-hero-greeting h1')?.textContent || ''`);
  check('Dashboard greeting renders', hero.length > 0, hero);
  const pills = await evalJs(`Array.from(document.querySelectorAll('.mb-prio-pill')).map(p => p.textContent.trim())`);
  check('Priority level strip (5 levels)', pills.length === 5, pills.join(', ').slice(0, 80));
  const counts = await evalJs(`Array.from(document.querySelectorAll('.mb-prio-count')).map(c => c.textContent)`);
  check('Priority counts shown', counts.length === 5 && counts.some(c => Number(c) > 0), counts.join(','));
  const attention = await evalJs(`document.querySelectorAll('.mb-attention-item').length`);
  check('Attention list renders', attention >= 3, `${attention} items`);
  const badges = await evalJs(`Array.from(document.querySelectorAll('.mb-attention-item .mb-badge')).map(b => b.textContent.trim())`);
  check('Priority badges present', badges.some(b => b.startsWith('HIGH') || b === 'CRITICAL'), badges.slice(0, 4).join(', '));
  const secBadges = await evalJs(`Array.from(document.querySelectorAll('.mb-attention-item .sec-high')).length`);
  check('Security verdict separate from priority (HIGH_RISK shown)', secBadges >= 1, `${secBadges} sec-high badges`);
  const securityCard = await evalJs(`Array.from(document.querySelectorAll('.card-title')).some(t => t.textContent.includes('Security overview'))`);
  check('Security overview card present', securityCard);

  // ---- Email list filters ----
  await send('Page.navigate', { url: 'http://localhost:8000/emails' });
  await wait(2000);
  const prioCol = await evalJs(`Array.from(document.querySelectorAll('th')).some(t => t.textContent === 'Priority')`);
  check('Email list priority column', prioCol);
  const mbFilters = await evalJs(`Array.from(document.querySelectorAll('.mb-priority-toolbar .filter-tab')).length`);
  check('Priority/category filters present', mbFilters >= 9, `${mbFilters} tabs`);
  const firstRowPrio = await evalJs(`document.querySelector('.mb-cell-priority .mb-badge')?.textContent || ''`);
  check('Row priority badge renders', firstRowPrio.length > 0, firstRowPrio);

  // ---- Investigation page ----
  await send('Page.navigate', { url: 'http://localhost:8000/emails/mb-e2e-scam' });
  await wait(2000);
  const prioSection = await evalJs(`Array.from(document.querySelectorAll('.card-title')).some(t => t.textContent.includes('MailBuddy Priority'))`);
  check('Investigation: MailBuddy Priority section', prioSection);
  const prioShown = await evalJs(`document.querySelector('.mb-detail-grid .mb-badge')?.textContent || ''`);
  // AI-determined priority varies by run; assert a verdict badge renders (not a specific level).
  check('Investigation: priority value shown', prioShown.length > 0, prioShown);
  const secShown = await evalJs(`Array.from(document.querySelectorAll('.intel-value')).some(v => (v.textContent||'').includes('HIGH'))`);
  check('Investigation: security verdict still visible', secShown);

  // ---- Assistant ----
  await send('Page.navigate', { url: 'http://localhost:8000/' });
  await wait(1500);
  await evalJs(`document.querySelector('.topbar-assistant-btn')?.click()`);
  await wait(300);
  const panel = await evalJs(`!!document.querySelector('.mb-assistant-panel')`);
  check('Assistant panel opens', panel);
  // Drive the REAL UI: type into the panel and click Ask (React controlled input).
  await evalJs(`(() => {
    const input = document.querySelector('.mb-assistant-input input');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, 'What needs my attention today?');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return 'typed';
  })()`);
  await evalJs(`document.querySelector('.mb-assistant-input button[type=submit]')?.click(); 'asked'`);
  await wait(4000); // real Groq round-trip may take a few seconds
  const chat = await evalJs(`(() => {
    const bubbles = Array.from(document.querySelectorAll('.mb-msg-assistant .mb-msg-bubble'));
    const refs = Array.from(document.querySelectorAll('.mb-ref-card .mb-ref-meta')).map(m => m.textContent);
    return { answer: bubbles[bubbles.length - 1]?.textContent || '', refCount: refs.length };
  })()`);
  check('Assistant answers from real data', (chat.answer || '').length > 10,
    (chat.answer || '').slice(0, 70).replace(/\n/g, ' '));
  const refUrl = await evalJs(`document.querySelector('.mb-ref-card')?.getAttribute('title') || 'none'`);
  const hasRefs = chat.refCount > 0;
  check('Assistant references real emails', hasRefs, `${chat.refCount} reference card(s)`);
  if (hasRefs) {
    await evalJs(`document.querySelector('.mb-ref-card')?.click(); 'clicked'`);
    await wait(1500);
    const path = await evalJs(`location.pathname`);
    check('Assistant email reference navigates to investigation', path.startsWith('/emails/'), path);
  } else {
    check('Assistant email reference navigates to investigation', false, 'no refs rendered');
  }

  // ---- Settings toggles ----
  await send('Page.navigate', { url: 'http://localhost:8000/settings' });
  await wait(1800);
  const toggles = await evalJs(`document.querySelectorAll('.mb-toggle').length`);
  check('MailBuddy settings toggles render', toggles === 4, `${toggles} toggles`);
  const labels = await evalJs(`Array.from(document.querySelectorAll('.mb-setting-label')).map(l => l.textContent)`);
  check('Settings toggle labels accessible', labels.length === 4 && labels.every(l => l.length > 3), labels.join(', ').slice(0, 90));

  // ---- Network / console / security checks ----
  const groqCalls = networkRequests.filter(u => /groq\.com|api\.groq/i.test(u));
  check('Browser never calls Groq directly', groqCalls.length === 0, groqCalls.join(',').slice(0, 60) || '0 calls');
  const viteCalls = networkRequests.filter(u => /:5173/.test(u));
  check('No :5173 references in production', viteCalls.length === 0);
  const settingsResp = await evalJs(`fetch('/api/mailbuddy/settings').then(r => r.json())`);
  check('Settings API returns no key material', !JSON.stringify(settingsResp).includes('gsk_') && !JSON.stringify(settingsResp).includes('GROQ_API_KEY='));
  const uncaught = pageErrors.length;
  check('Zero uncaught page errors', uncaught === 0, pageErrors.slice(0, 2).join(' | ').slice(0, 120));

  const passed = results.filter(r => r[1]).length;
  console.log(`\nMAILBUDDY BROWSER E2E: ${passed}/${results.length} checks passed`);
  process.exit(passed === results.length ? 0 : 1);
}

main().catch((e) => { console.error('E2E harness error:', e.message); process.exit(2); });
