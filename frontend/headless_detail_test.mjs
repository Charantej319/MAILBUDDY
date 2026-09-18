#!/usr/bin/env node
/**
 * Headless Chrome test for /emails/:id rendering.
 * Usage: node headless_detail_test.mjs <emailId>
 * Connects to the page target BEFORE navigating so early runtime errors are captured.
 */
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const EMAIL_ID = process.argv[2] || '4e9d0220-c600-43e4-b2ec-2c19302e99d3';
const URL_TO_TEST = `http://localhost:5173/emails/${EMAIL_ID}`;
const DEBUG_PORT = 9333;

const consoleMsgs = [];
const pageErrors = [];
const failedRequests = [];

async function getChromePath() {
  const candidates = [
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    (process.env.LOCALAPPDATA || '') + '/Google/Chrome/Application/chrome.exe',
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  throw new Error('Chrome not found');
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function getPageTargetWs() {
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/list`);
      const targets = await res.json();
      const page = targets.find(t => t.type === 'page');
      if (page?.webSocketDebuggerUrl) return page.webSocketDebuggerUrl;
    } catch {}
    await sleep(400);
  }
  throw new Error('No page target found');
}

// Minimal CDP websocket client (no deps)
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
        this.handlers.get(msg.method).forEach(h => h(msg.params));
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

async function main() {
  const chromePath = await getChromePath();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome-cdp-'));
  const chrome = spawn(chromePath, [
    `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${userDataDir}`,
    '--headless=new',
    '--no-first-run', '--no-default-browser-check', '--disable-extensions',
    '--disable-gpu', '--window-size=1400,900',
    'about:blank',
  ], { stdio: 'ignore' });

  try {
    const wsUrl = await getPageTargetWs();
    const ws = await connectWs(wsUrl.replace('localhost', '127.0.0.1'));
    const cdp = new CDP(ws);

    cdp.on('Runtime.consoleAPICalled', (p) => {
      const text = (p.args || []).map(a => a.value !== undefined ? String(a.value) : (a.description || a.type)).join(' ');
      consoleMsgs.push(`[${p.type}] ${text.slice(0, 500)}`);
    });
    cdp.on('Runtime.exceptionThrown', (p) => {
      const d = p.exceptionDetails;
      pageErrors.push(`${d.text} ${d.exception?.description || ''}`.slice(0, 1200));
    });
    cdp.on('Network.loadingFailed', (p) => failedRequests.push(`${p.errorText}`));
    cdp.on('Network.responseReceived', (p) => {
      if (p.response.url.includes('/api/')) consoleMsgs.push(`[net] ${p.response.status} ${p.response.url}`);
    });

    await cdp.send('Runtime.enable');
    await cdp.send('Page.enable');
    await cdp.send('Network.enable');
    if (process.env.BLOCK) {
      await cdp.send('Network.setBlockedURLs', { urls: [process.env.BLOCK] });
    }
    await cdp.send('Page.navigate', { url: URL_TO_TEST });
    await sleep(7000); // let React mount, fetch, render (incl. lazy body re-fetch)

    const evalJs = async (expr) => {
      const r = await cdp.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) return 'EVAL-ERROR: ' + JSON.stringify(r.exceptionDetails).slice(0, 300);
      return r.result?.value;
    };

    const rootHtmlLen = await evalJs(`document.getElementById('root') ? document.getElementById('root').innerHTML.length : -1`);
    const rootSample = await evalJs(`document.getElementById('root') ? document.getElementById('root').innerHTML.slice(0, 500) : 'NO #root'`);
    const bodyText = await evalJs(`document.body ? document.body.innerText.slice(0, ${process.env.SLICE || 900}) : 'NO BODY'`);

    console.log('=== URL:', URL_TO_TEST);
    console.log('=== #root innerHTML length:', rootHtmlLen);
    console.log('=== #root HTML sample:', rootSample);
    console.log('=== body text:', JSON.stringify(bodyText));
    console.log('=== page errors (' + pageErrors.length + '):');
    pageErrors.forEach(e => console.log('   ', e));
    console.log('=== failed requests (' + failedRequests.length + '):', failedRequests.slice(0, 10));
    console.log('=== console/net messages (' + consoleMsgs.length + '):');
    consoleMsgs.slice(0, 30).forEach(m => console.log('   ', m));
  } finally {
    try { chrome.kill(); } catch {}
    await sleep(500);
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch {}
  }
}

main().catch(e => { console.error('TEST FAILURE:', e.message); process.exit(1); });
