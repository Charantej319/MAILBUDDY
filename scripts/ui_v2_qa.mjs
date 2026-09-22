#!/usr/bin/env node
/**
 * V2 "Calm Desktop + Functional Color" QA + screenshots (dev mode).
 * Verifies: sidebar nav, priority counts, critical/high pages, security page,
 * email opening from a priority page, dashboard chips, assistant chips.
 * Captures the 7 requested screenshots.
 * Usage: node scripts/ui_v2_qa.mjs
 */
import http from 'http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import os from 'node:os';

const BASE = 'http://localhost:5173';
const OUT_DIR = 'reports/ui_v2';
const CDP_PORT = 9226;
fs.mkdirSync(OUT_DIR, { recursive: true });
const results = [];
const consoleErrors = [];
const check = (name, ok, detail = '') => { results.push({ name, ok, detail }); console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? ' — ' + detail : ''}`); };

const httpJson = (url) => new Promise((resolve, reject) => { http.get(url, (r) => { let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => resolve(JSON.parse(d))); }).on('error', reject); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let msgId = 0;
function send(ws, method, params = {}) { return new Promise((resolve, reject) => { const id = ++msgId; const on = (e) => { const d = JSON.parse(e.data); if (d.id === id) { ws.removeEventListener('message', on); d.error ? reject(new Error(JSON.stringify(d.error))) : resolve(d.result); } }; ws.addEventListener('message', on); ws.send(JSON.stringify({ id, method, params })); }); }
async function evalJs(ws, expression) { const r = await send(ws, 'Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }); if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails).slice(0, 300)); return r.result?.value; }
async function shot(ws, name) { const r = await send(ws, 'Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(path.join(OUT_DIR, `${name}.png`), Buffer.from(r.data, 'base64')); console.log(`[shot] ${name}`); }

const chromePath = ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe', process.env.LOCALAPPDATA + '/Google/Chrome/Application/chrome.exe'].find((p) => p && fs.existsSync(p));
const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mb-v2-'));
const chrome = spawn(chromePath, [`--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${profileDir}`, '--window-size=1440,900', '--no-first-run', 'about:blank'], { stdio: 'ignore' });

try {
  let page;
  for (let i = 0; i < 40; i++) { try { page = (await httpJson(`http://127.0.0.1:${CDP_PORT}/json/list`)).find((t) => t.type === 'page'); if (page) break; } catch { await sleep(500); } }
  const ws = await connect(page.webSocketDebuggerUrl);
  function connect(wsUrl) { return new Promise((resolve, reject) => { const s = new WebSocket(wsUrl); s.onopen = () => resolve(s); s.onerror = reject; }); }
  await send(ws, 'Page.enable'); await send(ws, 'Runtime.enable'); await send(ws, 'Log.enable');
  ws.addEventListener('message', (event) => {
    const d = JSON.parse(event.data);
    if (d.method === 'Runtime.exceptionThrown') consoleErrors.push('exception: ' + JSON.stringify(d.params?.exceptionDetails?.exception?.description || d.params).slice(0, 160));
    if (d.method === 'Log.entryAdded' && d.params.entry.level === 'error') consoleErrors.push('log: ' + (d.params.entry.text || '').slice(0, 160));
  });

  const goto = async (url, wait = 1600) => { await send(ws, 'Page.navigate', { url }); await sleep(wait); };

  // ── 1. Dashboard + chips ──────────────────────────────────────────
  await goto(`${BASE}/`, 2200);
  const chips = await evalJs(ws, `[...document.querySelectorAll('.mb-stat-chip')].map(c => c.textContent.replace(/\\s+/g,' ').trim())`);
  check('dashboard stat chips render', Array.isArray(chips) && chips.length >= 4, JSON.stringify(chips));
  await shot(ws, '07_dashboard');

  // ── 2. Sidebar priority section ───────────────────────────────────
  const prioLinks = await evalJs(ws, `[...document.querySelectorAll('.sidebar-prio-link')].map(a => ({ text: a.querySelector('.sidebar-prio-label')?.textContent, count: a.querySelector('.sidebar-prio-count')?.textContent ?? null, cls: [...a.classList].find(c => c.startsWith('icon-')) }))`);
  check('sidebar priority section has 4 levels with counts', prioLinks?.length === 4 && prioLinks.every(l => l.count !== null), JSON.stringify(prioLinks));
  const iconByLevel = Object.fromEntries((prioLinks || []).map(l => [l.text, l.cls]));
  check('per-level tint classes applied', iconByLevel['Critical'] === 'icon-critical' && iconByLevel['High'] === 'icon-high' && iconByLevel['Low'] === 'icon-low');
  await shot(ws, '02_sidebar_priority');

  // ── 3. Critical page via sidebar click ────────────────────────────
  await evalJs(ws, `document.querySelector('.sidebar-prio-link.icon-critical')?.click(); 'ok'`);
  await sleep(1800);
  const critHeader = await evalJs(ws, `(function(){ const h = document.querySelector('.prio-page-header'); if (!h) return null; return { h1: h.querySelector('h1')?.textContent.trim(), sub: h.querySelector('p')?.textContent, chip: h.querySelector('.prio-level-chip')?.textContent, cls: h.className }; })()`);
  check('critical page header shows level + count', /Critical/.test(critHeader?.h1 || '') && /message/.test(critHeader?.sub || ''), JSON.stringify(critHeader));
  check('critical page carries icon-critical accent class', /icon-critical/.test(critHeader?.cls || ''));
  await shot(ws, '03_critical_page');

  // ── 4. High page ──────────────────────────────────────────────────
  await goto(`${BASE}/priority/HIGH`, 1800);
  const highCls = await evalJs(ws, `document.querySelector('.prio-page-header')?.className || ''`);
  const highChip = await evalJs(ws, `document.querySelector('.prio-level-chip')?.textContent`);
  check('high page carries icon-high accent class + HIGH chip', /icon-high/.test(highCls) && highChip === 'HIGH', highCls.slice(0, 60) + ' / ' + highChip);
  await shot(ws, '04_high_page');

  // ── 5. Email opening from priority page ───────────────────────────
  await goto(`${BASE}/priority/CRITICAL`, 1800);
  await evalJs(ws, `document.querySelector('.mb-email-row')?.click(); 'clicked'`);
  await sleep(2000);
  const detail = await evalJs(ws, `({ path: location.pathname, subject: document.querySelector('.threat-subject')?.textContent?.slice(0, 50), prioBadge: document.querySelector('.mb-detail-grid .mb-badge')?.textContent, secBadge: [...document.querySelectorAll('.intel-item')].length > 0 })`);
  check('email opens from priority page', String(detail?.path || '').startsWith('/emails/'), detail?.path);
  check('email detail shows priority + security separately', !!detail?.prioBadge && !!detail?.secBadge);
  await shot(ws, '05_email_detail');

  // ── 6. Security page ──────────────────────────────────────────────
  await goto(`${BASE}/security`, 2000);
  const buckets = await evalJs(ws, `[...document.querySelectorAll('.sec-bucket-card')].map(b => ({ label: b.querySelector('.sec-bucket-label')?.textContent, count: b.querySelector('.sec-bucket-count')?.textContent }))`);
  check('security buckets render with counts', buckets?.length === 4 && buckets.every(b => b.count !== null), JSON.stringify(buckets));
  await evalJs(ws, `[...document.querySelectorAll('.sec-bucket-card')].find(b => b.querySelector('.sec-bucket-label')?.textContent === 'Suspicious')?.click(); 'ok'`);
  await sleep(1500);
  const filterActive = await evalJs(ws, `document.querySelector('.sec-bucket-card[aria-pressed="true"] .sec-bucket-label')?.textContent`);
  check('security bucket filters list', filterActive === 'Suspicious');
  await shot(ws, '08_security_page');

  // ── 7. Inbox ──────────────────────────────────────────────────────
  await goto(`${BASE}/emails`, 2000);
  const dots = await evalJs(ws, `document.querySelectorAll('.mb-sender-cell .prio-dot').length`);
  const tableRows = await evalJs(ws, `document.querySelectorAll('tbody tr').length`);
  check('inbox rows show priority dots (neutral rows)', dots > 0 && tableRows > 0, `${dots}/${tableRows}`);
  await shot(ws, '01_inbox');

  // ── 8. Assistant with colored quick actions ───────────────────────
  await evalJs(ws, `document.querySelector('.sidebar-assistant-btn')?.click(); 'ok'`);
  await sleep(900);
  const chips2 = await evalJs(ws, `[...document.querySelectorAll('.mb-assistant-chip')].map(c => ({ text: c.textContent.trim(), cls: [...c.classList].filter(c => c.startsWith('chip-')) }))`);
  check('assistant quick actions have meaning-based chips', chips2?.length >= 4 && chips2.some(c => c.cls.includes('chip-critical')) && chips2.some(c => c.cls.includes('chip-security')), JSON.stringify(chips2));
  // real round-trip
  await evalJs(ws, `(function(){ const i = document.querySelector('.mb-assistant-input input'); if (!i) return 'no-input'; const set = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set; set.call(i, 'What needs my attention?'); i.dispatchEvent(new Event('input', { bubbles: true })); return 'typed'; })()`);
  await evalJs(ws, `document.querySelector('.mb-assistant-input button[type=submit]')?.click(); 'sent'`);
  await sleep(9000);
  const answered = await evalJs(ws, `document.querySelectorAll('.mb-msg-assistant .mb-msg-bubble').length > 0`);
  check('assistant answers in V2 UI', !!answered);
  await shot(ws, '06_assistant_open');

  // ── summary ───────────────────────────────────────────────────────
  console.log('\n=== V2 QA SUMMARY ===');
  const failed = results.filter((r) => !r.ok);
  console.log(`passed: ${results.length - failed.length}/${results.length}`);
  console.log(`console errors: ${consoleErrors.length}`);
  consoleErrors.slice(0, 8).forEach((e) => console.log('  ! ' + e));
  fs.writeFileSync(path.join(OUT_DIR, 'v2_qa_results.json'), JSON.stringify({ results, consoleErrors }, null, 2));
} finally {
  try { chrome.kill(); } catch {}
}
