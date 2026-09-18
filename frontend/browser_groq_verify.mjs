#!/usr/bin/env node
/**
 * One-off browser verification of the Groq AI integration on the Email
 * Investigation page. Same minimal-CDP pattern as headless_detail_test.mjs.
 *
 * The backend is started by scripts/browser_verify_orchestrator.py, which also
 * provides a localhost-only control route to flip AI_ENABLED and pre-seeds the
 * disagreement fixture row (DISAGREE_ID env var).
 *
 * Scenarios: legitimate / suspicious / disagreement / AI-unavailable.
 * Checks: console errors, groq.com network calls, API-key leakage, re-fetch.
 */
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const BACKEND = process.env.BACKEND_ORIGIN || 'http://localhost:8000';
const DISAGREE_ID = process.env.DISAGREE_ID || '';
const DEBUG_PORT = 9334;
const EMAILS = {
  legit: '4e9d0220-c600-43e4-b2ec-2c19302e99d3',       // SAFE 0/100 "test mail"
  phish: '5c5be3eb-6b13-4355-8c24-0d93edf432b9',       // SUSPICIOUS 60/100
  disagree: DISAGREE_ID,
  unavailable: '9dd50502-4864-46d0-b4a4-396b8cb0e8d7', // LOW RISK 27/100
};

const consoleMsgs = [];
const pageErrors = [];
const groqRequests = [];
const apiRequests = [];
const aiResponses = []; // { url, body } for /api/ai/* key-leak inspection

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getChromePath() {
  const candidates = [
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    (process.env.LOCALAPPDATA || '') + '/Google/Chrome/Application/chrome.exe',
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  throw new Error('Chrome not found');
}

async function getPageTargetWs() {
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/list`);
      const targets = await res.json();
      const page = targets.find((t) => t.type === 'page');
      if (page?.webSocketDebuggerUrl) return page.webSocketDebuggerUrl;
    } catch {}
    await sleep(400);
  }
  throw new Error('No page target found');
}

class CDP {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = new Map();
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
      } else if (msg.method && this.handlers.has(msg.method)) {
        this.handlers.get(msg.method).forEach((h) => h(msg.params));
      }
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  on(method, handler) {
    if (!this.handlers.has(method)) this.handlers.set(method, []);
    this.handlers.get(method).push(handler);
  }
}

function connectWs(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.addEventListener('open', () => resolve(ws));
    ws.addEventListener('error', (e) => reject(new Error('WS error: ' + (e.message || 'unknown'))));
  });
}

async function setAiEnabled(on) {
  const r = await fetch(`${BACKEND}/__browsertest__/ai`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled: on }),
  });
  if (!r.ok) throw new Error(`ai toggle failed: ${r.status}`);
}

const CHECKS = [];
function check(name, ok, detail = '') {
  CHECKS.push([name, ok, detail]);
  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? ' — ' + detail : ''}`);
}

function has(text, re) { return re.test(text || ''); }

async function main() {
  const chromePath = await getChromePath();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome-groqverify-'));
  const chrome = spawn(chromePath, [
    `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${userDataDir}`,
    '--headless=new', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-gpu', '--window-size=1400,900',
    'about:blank',
  ], { stdio: 'ignore' });

  let exitCode = 0;
  try {
    const wsUrl = await getPageTargetWs();
    const ws = await connectWs(wsUrl.replace('localhost', '127.0.0.1'));
    const cdp = new CDP(ws);
    await cdp.send('Runtime.enable');
    await cdp.send('Page.enable');
    await cdp.send('Network.enable');

    const aiResponseMeta = new Map(); // requestId -> url
    cdp.on('Runtime.consoleAPICalled', (p) => {
      const text = (p.args || []).map((a) => a.value !== undefined ? String(a.value) : (a.description || a.type)).join(' ');
      consoleMsgs.push(`[${p.type}] ${text.slice(0, 300)}`);
    });
    cdp.on('Runtime.exceptionThrown', (p) => {
      const d = p.exceptionDetails;
      pageErrors.push(`${d.text} ${d.exception?.description || ''}`.slice(0, 800));
    });
    cdp.on('Network.requestWillBeSent', (p) => {
      const url = p.request.url;
      if (/groq\.com/i.test(url)) groqRequests.push(url);
      if (url.includes('/api/')) apiRequests.push(`${p.request.method} ${url}`);
      if (/\/api\/ai\//.test(url)) aiResponseMeta.set(p.requestId, url);
    });
    cdp.on('Network.loadingFinished', async (p) => {
      if (aiResponseMeta.has(p.requestId)) {
        const url = aiResponseMeta.get(p.requestId);
        try {
          const b = await cdp.send('Network.getResponseBody', { requestId: p.requestId });
          const body = b?.body || '';
          aiResponses.push({ url, body });
          if (/gsk_[A-Za-z0-9]{10,}|GROQ_API_KEY\s*=/.test(body)) {
            aiResponses.push({ url, body: 'KEY-LEAK: ' + body.slice(0, 200) });
          }
        } catch {}
      }
    });

    const evalJs = async (expr) => {
      const r = await cdp.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) return { evalError: JSON.stringify(r.exceptionDetails).slice(0, 300) };
      return r.result?.value;
    };
    const scrapePage = async () => ({
      rootLen: await evalJs(`document.getElementById('root')?.innerHTML.length ?? -1`),
      text: await evalJs(`document.body.innerText`),
      html: await evalJs(`document.getElementById('root')?.innerHTML ?? ''`),
    });
    const loadPage = async (id, waitMs) => {
      consoleMsgs.length = 0; pageErrors.length = 0;
      await cdp.send('Page.navigate', { url: `http://localhost:5173/emails/${id}` });
      await sleep(waitMs);
      return scrapePage();
    };
    const noErrors = () => {
      const realErrors = pageErrors.filter((e) => !/favicon/i.test(e));
      const errConsoles = consoleMsgs.filter((m) => m.startsWith('[error]') && !/favicon/i.test(m));
      return { realErrors, errConsoles };
    };

    // ── Scenario 1: legitimate email (real Groq) ──────────────────────
    await setAiEnabled(true);
    {
      const { rootLen, text, html } = await loadPage(EMAILS.legit, 15000);
      check('S1: page rendered (root mounted)', rootLen > 1000, `rootLen=${rootLen}`);
      check('S1: deterministic analysis visible', has(text, /Security Analysis/) && has(text, /SAFE/), '');
      check('S1: AI Verification section visible', has(text, /AI Verification/), '');
      check('S1: AI verdict displayed', has(html, /AI Verdict/) && has(text, /SAFE|LOW_RISK|SUSPICIOUS|HIGH_RISK/), '');
      check('S1: AI confidence displayed', has(text, /AI Confidence/) && has(text, /%/), '');
      check('S1: AI summary/reasons displayed', has(text, /AI Summary|AI Reasons/), '');
      const { realErrors, errConsoles } = noErrors();
      check('S1: no uncaught JS/React errors', realErrors.length === 0, realErrors.slice(0, 2).join(' | '));
      check('S1: no console.error output', errConsoles.length === 0, errConsoles.slice(0, 2).join(' | '));
    }

    // ── Scenario 2: suspicious email (real Groq; AI must not replace rules) ─
    {
      const { text, html } = await loadPage(EMAILS.phish, 15000);
      check('S2: deterministic result visible', has(text, /Security Analysis/) && has(text, /SUSPICIOUS|HIGH RISK/), '');
      check('S2: AI Verification visible', has(text, /AI Verification/), '');
      check('S2: both analyses coexist (no replacement)', has(html, /Deterministic engine/) && has(html, /AI Verdict/), '');
      check('S2: recommended action displayed', has(text, /Recommended Action|recommended action/i), '');
      const { realErrors } = noErrors();
      check('S2: no uncaught JS/React errors', realErrors.length === 0, realErrors.slice(0, 2).join(' | '));
    }

    // ── Scenario 3: disagreement UI (fixture row; fake AI LOW_RISK) ────
    if (EMAILS.disagree) {
      const { text, html } = await loadPage(EMAILS.disagree, 15000);
      check('S3: disagreement banner shown', has(text, /disagreement/i), '');
      check('S3: deterministic result still visible', has(text, /Rule Engine/) && has(text, /HIGH RISK/), '');
      check('S3: AI result still visible', has(html, /AI Verdict/) && has(text, /LOW_RISK|SAFE/), '');
      const { realErrors } = noErrors();
      check('S3: no uncaught JS/React errors', realErrors.length === 0, realErrors.slice(0, 2).join(' | '));
    } else {
      check('S3: disagreement fixture available', false, 'DISAGREE_ID not provided');
    }

    // ── Scenario 4: AI unavailable ─────────────────────────────────────
    await setAiEnabled(false);
    {
      const { text } = await loadPage(EMAILS.unavailable, 10000);
      check('S4: page rendered with AI disabled', has(text, /Security Analysis/), '');
      check('S4: deterministic analysis remains visible', has(text, /Risk|Score/), '');
      check('S4: AI unavailable/not-configured state shown', has(text, /unavailable|not configured/i), '');
      const { realErrors } = noErrors();
      check('S4: no crash / no uncaught errors', realErrors.length === 0, realErrors.slice(0, 2).join(' | '));
    }

    // ── Global network/security checks ─────────────────────────────────
    check('NET: browser never called groq.com', groqRequests.length === 0, groqRequests.slice(0, 2).join(' | '));
    const aiCalls = apiRequests.filter((u) => /POST http:\/\/localhost:8000\/api\/ai\/verify|\/api\/ai\/verify/.test(u));
    check('NET: AI calls went through the backend', aiCalls.length > 0, `${aiCalls.length} /api/ai/verify request(s)`);
    check('SEC: no API key material in any /api/ai response', !aiResponses.some((r) => r.body.startsWith('KEY-LEAK')), `${aiResponses.length} response(s) inspected`);

    // ── Scenario 7: old-email body re-fetch (gmail row without stored body) ─
    await setAiEnabled(true);
    {
      const { text } = await loadPage('ba4fbd3f-5438-46f9-8c72-282e0cee55ff', 12000);
      const refetchSettled = !/Fetching email content from Gmail/i.test(text);
      check('S7: old-email re-fetch settled (content or explicit unavailable)',
        refetchSettled && (has(text, /Email Content/) || has(text, /unavailable/i)),
        has(text, /Email Content/) && !/currently unavailable/i.test(text) ? 'body content displayed' : 'unavailable state (no live Gmail session)');
      const { realErrors } = noErrors();
      check('S7: no uncaught errors during re-fetch', realErrors.length === 0, realErrors.slice(0, 2).join(' | '));
    }
  } catch (e) {
    console.error('HARNESS FAILURE:', e.message);
    exitCode = 1;
  } finally {
    try { chrome.kill(); } catch {}
    await sleep(500);
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch {}
  }

  const failed = CHECKS.filter(([, ok]) => !ok);
  console.log(`\n${'='.repeat(60)}\nBROWSER VERIFICATION: ${CHECKS.length - failed.length}/${CHECKS.length} checks passed`);
  if (failed.length || exitCode) {
    failed.forEach(([n, , d]) => console.log('  FAILED:', n, d ? `(${d})` : ''));
    process.exit(1);
  }
  console.log('All browser checks passed.');
}

main();
