/**
 * Phase 2b unit tests for the desktop shell lifecycle module (desktop/backend.js).
 * No Electron, no Groq key, no network beyond localhost ephemeral servers.
 * Run:  cd desktop && npm test
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const fs = require('fs');

const backend = require('../backend');

// ── 1. Package configuration ─────────────────────────────────────────
test('desktop package manifest points at main.js and electron is installed', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.equal(pkg.main, 'main.js');
  assert.equal(pkg.productName, 'MailBuddy');
  const electronPkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'node_modules', 'electron', 'package.json'), 'utf8'));
  assert.ok(electronPkg.version, 'electron version present');
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'node_modules', 'electron', 'dist', 'electron.exe')), 'electron binary present');
});

// ── 2. Backend startup command (dev + Phase 2c swap point) ──────────
test('resolveBackendCommand dev mode targets uvicorn on port 8000', () => {
  const { command, args, cwd, kind } = backend.resolveBackendCommand({ projectRoot: 'C:/proj' });
  assert.equal(kind, 'dev');
  assert.equal(command, 'python');
  assert.ok(args.includes('-m') && args.includes('uvicorn'));
  assert.ok(args.includes('8000'));
  assert.ok(cwd.endsWith('backend'));
});

test('resolveBackendCommand packaged mode resolves the PyInstaller exe (Phase 2c)', () => {
  const projectRoot = path.join(__dirname, '..', '..');
  const { command, args, cwd, kind } = backend.resolveBackendCommand({ projectRoot, packaged: true });
  assert.equal(kind, 'packaged');
  assert.ok(command.endsWith('phishguard-backend.exe'), command);
  assert.deepEqual(args, []);
  assert.equal(cwd, path.dirname(command));
  assert.ok(fs.existsSync(command), 'built exe exists in the source tree');
});

test('PHISHGUARD_BACKEND_EXE overrides the packaged exe path (testing hook)', () => {
  process.env.PHISHGUARD_BACKEND_EXE = 'C:/custom/phishguard-backend.exe';
  try {
    const { command, kind } = backend.resolveBackendCommand({ projectRoot: 'C:/proj', packaged: false });
    assert.equal(kind, 'packaged');
    assert.equal(command, 'C:/custom/phishguard-backend.exe');
  } finally {
    delete process.env.PHISHGUARD_BACKEND_EXE;
  }
});

// ── 3. PHISHGUARD_DATA_DIR propagation ───────────────────────────────
test('backendEnv sets PHISHGUARD_DATA_DIR in desktop mode', () => {
  const env = backend.backendEnv({ dataDir: 'C:/Users/x/AppData/Roaming/PhishGuard' });
  assert.equal(env.PHISHGUARD_DATA_DIR, 'C:/Users/x/AppData/Roaming/PhishGuard');
});

test('backendEnv preserves the rest of the environment and extra overrides', () => {
  const env = backend.backendEnv({ dataDir: 'D:/dd', extra: { AI_ENABLED: 'true' } });
  assert.equal(env.AI_ENABLED, 'true');
  assert.equal(env.PATH, process.env.PATH);
});

test('defaultDataDir is %APPDATA%/PhishGuard', () => {
  assert.ok(backend.defaultDataDir({ appData: 'C:/Users/x/AppData/Roaming' }).endsWith('PhishGuard'));
});

// ── 3b. Window-origin guarantee (cookie-host match with OAuth callback) ──
// The Google-registered redirect URI is http://localhost:8000/auth/google/callback,
// which sets the phishguard_session cookie on host "localhost". The BrowserWindow
// MUST load http://localhost:<port> (not 127.0.0.1) or the Gmail session silently
// disappears after an app restart.
test('main.js loads the app window on the localhost origin, not 127.0.0.1', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  assert.match(src, /APP_ORIGIN = `http:\/\/localhost:\$\{BACKEND_PORT\}`/,
               'APP_ORIGIN must be http://localhost:<port>');
  assert.match(src, /win\.loadURL\(APP_ORIGIN\)/, 'window must load APP_ORIGIN');
  assert.doesNotMatch(src, /win\.loadURL\(BACKEND_URL\)/,
                      'window must not load the 127.0.0.1 BACKEND_URL');
});

test('desktop declares the AppUserModelID so Windows notifications display', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  assert.match(src, /setAppUserModelId\(['"]com\.phishguard\.desktop['"]\)/);
  const preload = fs.readFileSync(path.join(__dirname, '..', 'preload.js'), 'utf8');
  assert.match(preload, /contextBridge\.exposeInMainWorld\(['"]electronAPI['"]/);
  assert.match(preload, /mailbuddy:notification/);
});

// ── 4. Health-check behavior ─────────────────────────────────────────
function makeServer(payload, statusCode = 200) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      res.writeHead(statusCode, { 'Content-Type': 'application/json' });
      res.end(payload);
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

test('isBackendHealthy true for the real health payload', async () => {
  const { srv, port } = await makeServer('{"status":"healthy","service":"PhishGuard API"}');
  try {
    assert.equal(await backend.isBackendHealthy(`http://127.0.0.1:${port}/api/health`), true);
  } finally { srv.close(); }
});

test('isBackendHealthy false for non-PhishGuard or error responses', async () => {
  const { srv, port } = await makeServer('{"status":"ok"}'); // wrong payload
  const { srv: s2, port: p2 } = await makeServer('{"detail":"Not Found"}', 404);
  try {
    assert.equal(await backend.isBackendHealthy(`http://127.0.0.1:${port}/api/health`), false);
    assert.equal(await backend.isBackendHealthy(`http://127.0.0.1:${p2}/api/health`), false);
  } finally { srv.close(); s2.close(); }
});

test('isBackendHealthy false when nothing listens', async () => {
  assert.equal(await backend.isBackendHealthy('http://127.0.0.1:9/api/health', 300), false);
});

// ── 5. waitForBackend success + timeout ──────────────────────────────
test('waitForBackend succeeds once the health endpoint responds', async () => {
  const { srv, port } = await makeServer('{"status":"healthy"}');
  try {
    const r = await backend.waitForBackend({ timeoutMs: 3000, intervalMs: 100, url: `http://127.0.0.1:${port}/api/health` });
    assert.equal(r.ok, true);
  } finally { srv.close(); }
});

test('waitForBackend times out when the endpoint never appears', async () => {
  const r = await backend.waitForBackend({ timeoutMs: 700, intervalMs: 120, url: 'http://127.0.0.1:9/api/health' });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'timeout');
});

test('waitForBackend reports not-phishguard when a foreign server holds the port', async () => {
  const { srv, port } = await makeServer('{"hello":"world"}'); // wrong service on the port
  try {
    const r = await backend.waitForBackend({ timeoutMs: 4000, intervalMs: 100, url: `http://127.0.0.1:${port}/api/health` });
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'not-phishguard');
  } finally { srv.close(); }
});

// ── 6. Port-conflict detection (informational, never kills) ─────────
test('isPortInUse detects a listener and reports a pid', async () => {
  const server = net.createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    const { inUse } = await backend.isPortInUse(port);
    assert.equal(inUse, true); // pid is best-effort; not asserted
  } finally { server.close(); }
});

test('isPortInUse false on a free port', async () => {
  const server = net.createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const freePort = server.address().port;
  await new Promise((r) => server.close(r));
  const { inUse } = await backend.isPortInUse(freePort);
  assert.equal(inUse, false);
});

// ── 7. Shutdown behavior ─────────────────────────────────────────────
test('stopBackend gracefully stops a long-running child we started', async () => {
  const { spawn } = require('child_process');
  const child = spawn('python', ['-c', 'import time\nwhile True: time.sleep(0.1)'], { windowsHide: true });
  assert.equal(child.exitCode, null);
  await backend.stopBackend(child, { graceMs: 3000 });
  assert.ok(child.exitCode !== null || child.signalCode !== null, 'child exited');
});

test('stopBackend is a no-op for an already-exited child', async () => {
  const { spawn } = require('child_process');
  const child = spawn('python', ['-c', 'pass']);
  await new Promise((r) => child.on('exit', r));
  await backend.stopBackend(child); // must not hang or throw
});

test('stopBackend with null child resolves without action', async () => {
  await backend.stopBackend(null); // adopt-mode path in main.js
});
