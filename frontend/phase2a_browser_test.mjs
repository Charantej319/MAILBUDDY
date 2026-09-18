#!/usr/bin/env node
/**
 * Phase 2a browser test: the PRODUCTION frontend build served by FastAPI from
 * http://localhost:8000 (no vite dev server). Verifies dashboard, email list,
 * Email Investigation (incl. AI Verification card), settings, console errors,
 * and that the browser talks only to localhost:8000 — never groq.com.
 *
 * Started by scripts/phase2a_browser_launcher.py (which boots the backend).
 */
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const BASE = 'http://localhost:8000';
const DEBUG_PORT = 9335;

const consoleMsgs = [];
const pageErrors = [];
const requests = [];

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

const CHECKS = [];
function check(name, ok, detail = '') {
  CHECKS.push([name, ok, detail]);
  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? ' — ' + detail : ''}`);
}
const has = (t, re) => re.test(t || '');

async function main() {
  const emailId = process.env.EMAIL_ID;
  if (!emailId) throw new Error('EMAIL_ID env var required');

  const chromePath = await getChromePath();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome-phase2a-'));
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

    cdp.on('Runtime.consoleAPICalled', (p) => {
      const text = (p.args || []).map((a) => a.value !== undefined ? String(a.value) : (a.description || a.type)).join(' ');
      consoleMsgs.push(`[${p.type}] ${text.slice(0, 300)}`);
    });
    cdp.on('Runtime.exceptionThrown', (p) => {
      const d = p.exceptionDetails;
      pageErrors.push(`${d.text} ${d.exception?.description || ''}`.slice(0, 600));
    });
    cdp.on('Network.requestWillBeSent', (p) => requests.push(p.request.url));

    const evalJs = async (expr) => {
      const r = await cdp.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) return { evalError: JSON.stringify(r.exceptionDetails).slice(0, 200) };
      return r.result?.value;
    };
    const loadPage = async (url, waitMs) => {
      consoleMsgs.length = 0; pageErrors.length = 0;
      await cdp.send('Page.navigate', { url });
      await sleep(waitMs);
      return {
        text: await evalJs(`document.body.innerText`),
        html: await evalJs(`document.getElementById('root')?.innerHTML ?? ''`),
      };
    };
    const noErrors = () => {
      const errs = pageErrors.filter((e) => !/favicon/i.test(e));
      const cerrs = consoleMsgs.filter((m) => m.startsWith('[error]') && !/favicon/i.test(m));
      return { errs, cerrs };
    };

    // ── 1. Dashboard at http://localhost:8000/ ─────────────────────────
    {
      const { text } = await loadPage(`${BASE}/`, 9000);
      check('Dashboard renders from production build', has(text, /Dashboard|Total|Analyz/i) && has(text, /PhishGuard/i), text.slice(0, 80).replace(/\n/g, ' '));
      const { errs, cerrs } = noErrors();
      check('Dashboard: no uncaught errors', errs.length === 0 && cerrs.length === 0, [...errs, ...cerrs].slice(0, 2).join(' | '));
    }

    // ── 2. Email list (SPA route) ──────────────────────────────────────
    {
      const { text } = await loadPage(`${BASE}/emails`, 9000);
      check('Email list renders via SPA fallback', has(text, /Emails?/i), '');
      const { errs, cerrs } = noErrors();
      check('Email list: no uncaught errors', errs.length === 0 && cerrs.length === 0, [...errs, ...cerrs].slice(0, 2).join(' | '));
    }

    // ── 3. Email Investigation page (deep route) ───────────────────────
    {
      const { text } = await loadPage(`${BASE}/emails/${emailId}`, 11000);
      check('Email Investigation renders at /emails/<id>', has(text, /Security Analysis/), '');
      check('Deterministic analysis visible', has(text, /Risk|Score|\/ ?100/) || has(text, /Classification/i), '');
      check('AI Verification section visible', has(text, /AI Verification/), '');
      const aiCard = has(text, /AI Verdict|AI Confidence|AI verification (unavailable|not configured)/i);
      check('AI card shows a verdict or a graceful state', aiCard, '');
      const { errs, cerrs } = noErrors();
      check('Investigation page: no uncaught errors', errs.length === 0 && cerrs.length === 0, [...errs, ...cerrs].slice(0, 2).join(' | '));
    }

    // ── 4. Settings (Gmail area intact) ────────────────────────────────
    {
      const { text } = await loadPage(`${BASE}/settings`, 9000);
      check('Settings renders with Gmail connection area', has(text, /Gmail/i) && has(text, /Settings/i), '');
      const { errs, cerrs } = noErrors();
      check('Settings: no uncaught errors', errs.length === 0 && cerrs.length === 0, [...errs, ...cerrs].slice(0, 2).join(' | '));
    }

    // ── 5. Network hygiene ─────────────────────────────────────────────
    const groq = requests.filter((u) => /groq\.com/i.test(u));
    check('Browser never called groq.com directly', groq.length === 0, groq.slice(0, 2).join(' | '));
    check('Browser used localhost:8000 for API calls', requests.some((u) => u.startsWith(`${BASE}/api/`)), '');
    check('Vite dev server (5173) not involved', !requests.some((u) => /:5173/.test(u)), '');
  } catch (e) {
    console.error('HARNESS FAILURE:', e.message);
    exitCode = 1;
  } finally {
    try { chrome.kill(); } catch {}
    await sleep(500);
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch {}
  }

  const failed = CHECKS.filter(([, ok]) => !ok);
  console.log(`\n${'='.repeat(60)}\nPHASE 2a BROWSER TEST: ${CHECKS.length - failed.length}/${CHECKS.length} checks passed`);
  if (failed.length || exitCode) {
    failed.forEach(([n, , d]) => console.log('  FAILED:', n, d ? `(${d})` : ''));
    process.exit(1);
  }
  console.log('All Phase 2a browser checks passed.');
}

main();
