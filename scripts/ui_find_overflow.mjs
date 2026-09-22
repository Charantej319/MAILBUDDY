#!/usr/bin/env node
/** Find elements wider than viewport. Usage: node scripts/ui_find_overflow.mjs <url> */
import http from 'http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import os from 'node:os';
const URL_TARGET = process.argv[2] || 'http://localhost:5173/emails';
const CDP_PORT = 9225;
function httpJson(url) { return new Promise((res, rej) => { http.get(url, (r) => { let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => res(JSON.parse(d))); }).on('error', rej); }); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let msgId = 0;
function connect(wsUrl) { return new Promise((res, rej) => { const ws = new WebSocket(wsUrl); ws.onopen = () => res(ws); ws.onerror = rej; }); }
function send(ws, method, params = {}) { return new Promise((res, rej) => { const id = ++msgId; const on = (e) => { const d = JSON.parse(e.data); if (d.id === id) { ws.removeEventListener('message', on); d.error ? rej(new Error(JSON.stringify(d.error))) : res(d.result); } }; ws.addEventListener('message', on); ws.send(JSON.stringify({ id, method, params })); }); }
async function evalJs(ws, expression) { const r = await send(ws, 'Runtime.evaluate', { expression, returnByValue: true }); if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails).slice(0, 300)); return r.result?.value; }
const chromePath = ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe', process.env.LOCALAPPDATA + '/Google/Chrome/Application/chrome.exe'].find((p) => p && fs.existsSync(p));
const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mb-of-'));
const chrome = spawn(chromePath, [`--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${profileDir}`, '--window-size=1440,900', '--no-first-run', 'about:blank'], { stdio: 'ignore' });
try {
  let page; for (let i = 0; i < 40; i++) { try { page = (await httpJson(`http://127.0.0.1:${CDP_PORT}/json/list`)).find((t) => t.type === 'page'); if (page) break; } catch { await sleep(500); } }
  const ws = await connect(page.webSocketDebuggerUrl);
  await send(ws, 'Page.enable');
  await send(ws, 'Page.navigate', { url: URL_TARGET });
  await sleep(2500);
  const out = await evalJs(ws, `(function(){
    const vw = document.documentElement.clientWidth;
    const bad = [];
    document.querySelectorAll('*').forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.right > vw + 1 && r.width > 8) {
        bad.push({ tag: el.tagName, cls: (el.className || '').toString().slice(0, 60), right: Math.round(r.right), w: Math.round(r.width) });
      }
    });
    return { vw, count: bad.length, list: bad.slice(0, 15) };
  })()`);
  console.log(JSON.stringify(out, null, 2));
} finally { try { chrome.kill(); } catch {} }
