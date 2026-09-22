#!/usr/bin/env node
/**
 * Bridge diagnostics — read-only probing of the live renderer.
 * Usage: node probe_bridge.mjs <cdpPort>
 */
import http from 'http';

const PORT = process.argv[2] || '9348';
const BASE = `http://127.0.0.1:${PORT}`;

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
  if (r.exceptionDetails) return { __exception: JSON.stringify(r.exceptionDetails).slice(0, 300) };
  return r.result?.value;
};

// 1. Install an error collector NOW (misses past errors, catches future ones)
await evalJs(`(() => {
  window.__mbErrs = [];
  window.addEventListener('error', e => window.__mbErrs.push(String(e.message).slice(0, 200)));
  window.addEventListener('unhandledrejection', e => window.__mbErrs.push('REJ: ' + String(e.reason && e.reason.message || e.reason).slice(0, 200)));
  return true;
})()`);

// 2. Does the window itself see the pending endpoint?
const direct = await evalJs(`fetch('/api/mailbuddy/notifications/pending', { credentials: 'include' }).then(r => r.text()).catch(e => 'ERR ' + e.message)`);
console.log('direct pending fetch  :', String(direct).slice(0, 300));

// 3. Spy wiring test: call the wrapped API manually (this DOES raise a real toast)
const spyBefore = await evalJs(`(window.__mbIpcSpy && window.__mbIpcSpy.calls.length) || 'NO SPY'`);
console.log('spy calls before      :', spyBefore);
const manual = await evalJs(`window.electronAPI && window.electronAPI.showNotification({ title: 'MailBuddy', body: 'IPC-WIRE-TEST: if you see this toast, the Electron IPC path works' })`);
console.log('manual IPC call       :', manual === undefined ? 'dispatched (no return value, as expected)' : JSON.stringify(manual));
const spyAfter = await evalJs(`(window.__mbIpcSpy && JSON.stringify(window.__mbIpcSpy.calls)) || 'NO SPY'`);
console.log('spy calls after       :', spyAfter);

// 4. Does the SERVED bundle contain the notification bridge code?
const bundleProbe = await evalJs(`performance.getEntriesByType('resource').filter(r => r.name.endsWith('.js')).map(r => r.name)`);
console.log('loaded js bundles     :', JSON.stringify(bundleProbe));
if (Array.isArray(bundleProbe) && bundleProbe.length) {
  const probe = await evalJs(`Promise.all(${JSON.stringify(bundleProbe)}.map(u => fetch(u).then(r => r.text()))).then(txts => {
    const all = txts.join('');
    return JSON.stringify({
      bundles: txts.length,
      bytes: all.length,
      hasPendingEndpoint: all.includes('notifications/pending'),
      hasAckEndpoint: all.includes('notifications/ack'),
      hasElectronApiCall: all.includes('electronAPI'),
      hasShowNotification: all.includes('showNotification'),
      hasBridgeTitle: all.includes('New important email received'),
    });
  })`);
  console.log('bundle content probe  :', probe);
}

// 5. Wait briefly and report any captured errors
await new Promise((r) => setTimeout(r, 3000));
const errs = await evalJs('JSON.stringify(window.__mbErrs)');
console.log('window errors (3s)    :', errs);

process.exit(0);
