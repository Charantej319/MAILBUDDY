#!/usr/bin/env node
/** Layout/contrast QA probe over CDP. Usage: node scripts/ui_inspect_layout.mjs <url> [outName] */
import http from 'http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import os from 'node:os';

const URL_TARGET = process.argv[2] || 'http://localhost:5173/';
const OUT = process.argv[3] || 'reports/ui_redesign/qa_probe.png';
const CDP_PORT = 9224;

function httpJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => resolve(JSON.parse(d))); }).on('error', reject);
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let msgId = 0;
function connect(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    ws.onopen = () => resolve(ws);
    ws.onerror = reject;
  });
}
function send(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++msgId;
    const onMessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.id === id) { ws.removeEventListener('message', onMessage); data.error ? reject(new Error(JSON.stringify(data.error))) : resolve(data.result); }
    };
    ws.addEventListener('message', onMessage);
    ws.send(JSON.stringify({ id, method, params }));
  });
}
async function evalJs(ws, expression) {
  const r = await send(ws, 'Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails).slice(0, 300));
  return r.result?.value;
}

const chromePath = ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe', process.env.LOCALAPPDATA + '/Google/Chrome/Application/chrome.exe'].find((p) => p && fs.existsSync(p));
const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mb-qa-'));
const chrome = spawn(chromePath, [`--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${profileDir}`, '--window-size=1440,900', '--no-first-run', 'about:blank'], { stdio: 'ignore' });
try {
  let page;
  for (let i = 0; i < 40; i++) {
    try { page = (await httpJson(`http://127.0.0.1:${CDP_PORT}/json/list`)).find((t) => t.type === 'page'); if (page) break; } catch { await sleep(500); }
  }
  const ws = await connect(page.webSocketDebuggerUrl);
  await send(ws, 'Page.enable');
  await send(ws, 'Page.navigate', { url: URL_TARGET });
  await sleep(2500);

  const report = await evalJs(ws, `(function(){
    const out = {};
    const sb = document.querySelector('.sidebar');
    out.sidebar = sb ? { w: sb.getBoundingClientRect().width, bg: getComputedStyle(sb).backgroundColor } : null;
    const main = document.querySelector('.main-area');
    out.mainMarginLeft = main ? getComputedStyle(main).marginLeft : null;
    const pc = document.querySelector('.page-content');
    out.pageContent = pc ? { w: pc.getBoundingClientRect().width, overflowX: document.documentElement.scrollWidth > window.innerWidth } : null;
    const topbar = document.querySelector('.topbar');
    out.topbar = topbar ? { h: topbar.getBoundingClientRect().height, bg: getComputedStyle(topbar).backgroundColor } : null;
    // horizontal overflow check
    out.horizontalOverflow = document.documentElement.scrollWidth - window.innerWidth;
    // broken text colors: count elements with color too close to their bg
    let lowContrast = 0;
    document.querySelectorAll('button, .card-title, .mb-msg-bubble, th, td, .sidebar-link').forEach((el) => {
      const cs = getComputedStyle(el);
      if (cs.visibility === 'hidden' || cs.display === 'none') return;
      const fg = cs.color.match(/\\d+/g)?.slice(0,3).map(Number) || [0,0,0];
      let bg = cs.backgroundColor;
      let node = el;
      while ((bg === 'rgba(0, 0, 0, 0)' || bg === 'transparent') && node.parentElement) { node = node.parentElement; bg = getComputedStyle(node).backgroundColor; }
      const bgc = bg.match(/\\d+/g)?.slice(0,3).map(Number);
      if (!bgc) return;
      const lum = (c) => { const a = c.map(v => { v/=255; return v<=0.03928? v/12.92 : Math.pow((v+0.055)/1.055, 2.4); }); return 0.2126*a[0]+0.7152*a[1]+0.0722*a[2]; };
      const ratio = (Math.max(lum(fg),lum(bgc))+0.05)/(Math.min(lum(fg),lum(bgc))+0.05);
      if (ratio < 3 && el.textContent.trim()) lowContrast++;
    });
    out.lowContrastElements = lowContrast;
    // key visible components on this page
    out.assistantOpen = !!document.querySelector('.mb-assistant-panel');
    out.tables = document.querySelectorAll('table').length;
    out.cards = document.querySelectorAll('.card').length;
    out.buttons = document.querySelectorAll('.btn').length;
    out.vh = window.innerHeight; out.vw = window.innerWidth;
    return out;
  })()`);
  console.log(JSON.stringify(report, null, 2));

  const r = await send(ws, 'Page.captureScreenshot', { format: 'png' });
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, Buffer.from(r.data, 'base64'));
  console.log('shot -> ' + OUT);
} finally {
  try { chrome.kill(); } catch {}
}
