import http from 'http';

const PORT = process.argv[2] || '9348';
const BASE = `http://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function send(ws, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1e9);
    const onMessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.id === id) { ws.removeEventListener('message', onMessage); data.error ? reject(new Error(JSON.stringify(data.error))) : resolve(data.result); }
    };
    ws.addEventListener('message', onMessage);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

const pages = await new Promise((resolve, reject) => {
  http.get(`${BASE}/json/list`, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => resolve(JSON.parse(d))); }).on('error', reject);
});
console.log('page targets:', pages.filter(t => t.type === 'page').map(t => t.url));

const target = pages.filter(t => t.type === 'page')[0];
const ws = await new Promise((resolve, reject) => {
  const s = new WebSocket(`ws://127.0.0.1:${PORT}/devtools/page/${target.id}`);
  s.onopen = () => resolve(s); s.onerror = reject;
});

const evalJs = async (expr) => {
  const r = await send(ws, 'Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) return 'EXC: ' + JSON.stringify(r.exceptionDetails).slice(0, 300);
  return r.result?.value;
};

console.log('location.href  :', await evalJs('location.href'));
console.log('sw controller  :', await evalJs('!!navigator.serviceWorker && !!navigator.serviceWorker.controller'));
const diag = await evalJs(`fetch('/api/gmail/status', { credentials: 'include' })
  .then(async r => JSON.stringify({ status: r.status, url: r.url, ct: r.headers.get('content-type'), head: (await r.text()).slice(0, 120) }))
  .catch(e => 'FETCH_ERR: ' + e.message)`);
console.log('fetch diag     :', diag);
const cookies = await send(ws, 'Network.getCookies', { urls: ['http://localhost:8000'] });
console.log('cookies localhost:', cookies.cookies.map(c => `${c.name}@${c.domain}`).join(', ') || 'NONE');
process.exit(0);
