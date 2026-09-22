#!/usr/bin/env node
/**
 * UI walkthrough for the MailBuddy redesign (dev mode).
 * Drives a real Chrome window over CDP: visits every screen, captures
 * screenshots, records console/page errors, exercises the assistant panel.
 *
 * Usage: node scripts/ui_walkthrough.mjs [chromePath] [outDir]
 * Env:   MB_CHROME (chrome path override)
 */
import http from 'http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import os from 'node:os';

const BASE = process.argv[2] || 'http://localhost:5173';
const OUT_DIR = process.argv[3] || 'reports/ui_redesign';
const CDP_PORT = 9223;
fs.mkdirSync(OUT_DIR, { recursive: true });

const errors = [];
const shots = [];

function httpJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => resolve(JSON.parse(d))); }).on('error', reject);
  });
}

function connect(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    ws.onopen = () => resolve(ws);
    ws.onerror = reject;
  });
}

let msgId = 0;
function send(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++msgId;
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function evalJs(ws, expression) {
  const r = await send(ws, 'Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error('page eval failed: ' + JSON.stringify(r.exceptionDetails).slice(0, 300));
  return r.result?.value;
}

async function shot(ws, name) {
  const r = await send(ws, 'Page.captureScreenshot', { format: 'png' });
  const file = path.join(OUT_DIR, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(r.data, 'base64'));
  shots.push(file);
  console.log(`[shot] ${name}`);
}

// --- Launch a dedicated Chrome instance with CDP -------------------------
const chromeCandidates = process.env.MB_CHROME ? [process.env.MB_CHROME] : [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  process.env.LOCALAPPDATA + '/Google/Chrome/Application/chrome.exe',
].filter(Boolean);
const chromePath = chromeCandidates.find((p) => fs.existsSync(p));
if (!chromePath) { console.error('chrome not found'); process.exit(1); }

const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mb-ui-'));
const chrome = spawn(chromePath, [
  `--remote-debugging-port=${CDP_PORT}`,
  `--user-data-dir=${profileDir}`,
  '--window-size=1440,900',
  '--no-first-run', '--no-default-browser-check',
  'about:blank',
], { stdio: 'ignore', detached: false });

try {
  // wait for CDP
  let targets = null;
  for (let i = 0; i < 40; i++) {
    try { targets = await httpJson(`http://127.0.0.1:${CDP_PORT}/json/list`); break; } catch { await sleep(500); }
  }
  if (!targets) throw new Error('CDP did not come up');
  const page = targets.find((t) => t.type === 'page');
  const ws = await connect(page.webSocketDebuggerUrl);
  await send(ws, 'Page.enable');
  await send(ws, 'Runtime.enable');
  ws.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    if (data.method === 'Runtime.exceptionThrown') errors.push('page exception: ' + JSON.stringify(data.params?.exceptionDetails?.exception?.description || data.params).slice(0, 200));
    if (data.method === 'Runtime.consoleAPICalled' && data.params.type === 'error') errors.push('console.error: ' + JSON.stringify(data.params.args?.map((a) => a.value || a.description) || []).slice(0, 200));
    if (data.method === 'Log.entryAdded' && data.params.entry.level === 'error') errors.push('log: ' + (data.params.entry.text || '').slice(0, 200));
  });
  await send(ws, 'Log.enable');

  const goto = async (url, name, waitMs = 1800) => {
    await send(ws, 'Page.navigate', { url });
    await sleep(waitMs);
    const title = await evalJs(ws, 'document.title');
    console.log(`[nav] ${name} -> ${url} (${title})`);
    await shot(ws, name);
  };

  await goto(`${BASE}/`, '01_dashboard');
  await goto(`${BASE}/emails`, '02_inbox');

  // Inbox with assistant open (visual integration check)
  await evalJs(ws, `document.querySelector('.sidebar-assistant-btn')?.click(); 'ok'`);
  await sleep(900);
  await shot(ws, '03_inbox_assistant_open');

  // Send a real assistant question from the inbox (global chat)
  await evalJs(ws, `(function(){
    const input = document.querySelector('.mb-assistant-input input');
    if (!input) return 'no-input';
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, 'What needs my attention?');
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return 'typed';
  })()`);
  await evalJs(ws, `document.querySelector('.mb-assistant-input button[type=submit]')?.click(); 'sent'`);
  await sleep(9000); // allow Groq round-trip
  await shot(ws, '04_assistant_answer');
  const assistantHasAnswer = await evalJs(ws, `document.querySelectorAll('.mb-msg-assistant .mb-msg-bubble').length > 0`);
  console.log(`[check] assistant answered: ${assistantHasAnswer}`);

  // Close assistant, open an email detail
  await evalJs(ws, `document.querySelector('.mb-assistant-close')?.click(); 'closed'`);
  await sleep(400);
  const firstEmailHref = await evalJs(ws, `(function(){
    const row = document.querySelector('tbody tr');
    return row ? row.getAttribute('data-href') || 'click-row' : 'no-rows';
  })()`);
  // Click first row to navigate
  await evalJs(ws, `document.querySelector('tbody tr')?.click(); 'nav'`);
  await sleep(2000);
  const url1 = await evalJs(ws, 'location.pathname');
  console.log(`[nav] email detail -> ${url1}`);
  await shot(ws, '05_email_detail');

  // Ask MailBuddy about this email (context mode)
  await evalJs(ws, `document.querySelector('.ask-mailbuddy-btn-wrap button')?.click(); 'opened'`);
  await sleep(800);
  const contextChip = await evalJs(ws, `document.querySelector('.mb-context-subject')?.textContent || 'none'`);
  console.log(`[check] email context chip: ${contextChip}`);
  await evalJs(ws, `(function(){
    const chips = [...document.querySelectorAll('.mb-assistant-chip')];
    const target = chips.find(c => /flagged/i.test(c.textContent));
    target?.click();
    return target ? 'clicked' : 'no-chip';
  })()`);
  await sleep(9000);
  await shot(ws, '06_email_context_answer');

  await goto(`${BASE}/analytics`, '07_analytics');
  await goto(`${BASE}/settings`, '08_settings');

  // Small-window responsive check
  await send(ws, 'Emulation.setDeviceMetricsOverride', { width: 760, height: 900, deviceScaleFactor: 1, mobile: false });
  await sleep(700);
  await shot(ws, '09_settings_narrow');
  await goto(`${BASE}/`, '10_dashboard_narrow');
  await send(ws, 'Emulation.clearDeviceMetricsOverride');
  await sleep(500);

  console.log('\n=== WALKTHROUGH SUMMARY ===');
  console.log(`screenshots: ${shots.length}`);
  console.log(`errors: ${errors.length}`);
  errors.slice(0, 12).forEach((e) => console.log('  ! ' + e));
  fs.writeFileSync(path.join(OUT_DIR, 'walkthrough_results.json'), JSON.stringify({ shots, errors, assistantHasAnswer }, null, 2));
} finally {
  try { chrome.kill(); } catch {}
}
