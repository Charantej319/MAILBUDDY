/**
 * PhishGuard desktop shell — backend process lifecycle.
 *
 * Deliberately Electron-free and side-effect-light so every function is
 * unit-testable with node:test. main.js wires these into the Electron app.
 *
 * Phase 2c swap point: resolveBackendCommand({ packaged: true }) returns the
 * packaged phishguard-backend.exe command; replacing the dev uvicorn command
 * later requires no redesign here.
 */
'use strict';

const { spawn } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');

const BACKEND_PORT = 8000;
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;

/**
 * Resolve how to start the backend.
 *  - dev:      system python + uvicorn (existing development workflow)
 *  - packaged: phishguard-backend.exe (PyInstaller one-dir bundle, Phase 2c)
 *
 * Packaged exe location: <resources>/backend/phishguard-backend/phishguard-backend.exe
 * inside an installed Electron app, or packaging/dist/... in the source tree.
 * PHISHGUARD_BACKEND_EXE overrides for testing without electron-builder.
 */
function resolveBackendCommand({ projectRoot, packaged = false } = {}) {
  const exeOverride = process.env.PHISHGUARD_BACKEND_EXE;
  if (packaged || exeOverride) {
    const exePath = exeOverride
      ? exeOverride
      : (process.resourcesPath
          ? path.join(process.resourcesPath, 'backend', 'phishguard-backend', 'phishguard-backend.exe')
          : path.join(projectRoot || '.', 'packaging', 'dist', 'phishguard-backend', 'phishguard-backend.exe'));
    return { command: exePath, args: [], cwd: path.dirname(exePath), kind: 'packaged' };
  }
  // Development: run the existing FastAPI app with the system Python.
  const backendDir = projectRoot ? `${projectRoot}/backend` : 'backend';
  return {
    command: 'python',
    args: ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(BACKEND_PORT), '--log-level', 'warning'],
    cwd: backendDir,
    kind: 'dev',
  };
}

/** Environment handed to the backend child. Desktop mode always sets the data dir. */
function backendEnv({ dataDir, extra = {} } = {}) {
  return {
    ...process.env,
    ...(dataDir ? { PHISHGUARD_DATA_DIR: dataDir } : {}),
    ...extra,
  };
}

/** Default per-user data directory: %APPDATA%\PhishGuard. */
function defaultDataDir({ appData = process.env.APPDATA || process.env.HOME || '.' } = {}) {
  return `${appData}/PhishGuard`.replace(/\\/g, '/');
}

/**
 * True when something is LISTENING on the port. Never kills anything.
 * Returns { inUse, pid | null } — pid from netstat, best effort.
 */
function isPortInUse(port = BACKEND_PORT) {
  return new Promise((resolve) => {
    const probe = net.createConnection({ port, host: '127.0.0.1' });
    probe.once('connect', () => {
      probe.destroy();
      // Identify the owner (best effort, Windows netstat) — informational only.
      const { execFile } = require('child_process');
      execFile('netstat', ['-ano'], { windowsHide: true }, (err, stdout) => {
        let pid = null;
        if (!err) {
          const line = stdout.split('\n').find((l) => l.includes(`:${port}`) && /LISTENING/i.test(l));
          if (line) pid = Number(line.trim().split(/\s+/).pop()) || null;
        }
        resolve({ inUse: true, pid });
      });
    });
    probe.once('error', () => resolve({ inUse: false, pid: null }));
  });
}

/** True when a healthy PhishGuard backend already answers /api/health. */
function isBackendHealthy(url = `${BACKEND_URL}/api/health`, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; if (body.length > 4096) req.destroy(); });
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          resolve(res.statusCode === 200 && data && data.status === 'healthy');
        } catch {
          resolve(false);
        }
      });
    });
    req.once('timeout', () => { req.destroy(); resolve(false); });
    req.once('error', () => resolve(false));
  });
}

/**
 * Poll the health endpoint until healthy or timeout. No fixed sleeps.
 * Returns { ok: true } or { ok: false, reason: 'timeout' | 'not-phishguard' }.
 */
async function waitForBackend({ timeoutMs = 45000, intervalMs = 400, url = `${BACKEND_URL}/api/health` } = {}) {
  const deadline = Date.now() + timeoutMs;
  let sawListening = false;
  const targetPort = Number(new URL(url).port) || (new URL(url).protocol === 'https:' ? 443 : 80);
  while (Date.now() < deadline) {
    if (await isBackendHealthy(url)) return { ok: true };
    // Distinguish "nothing there yet" from "something else took the port".
    const { inUse } = await isPortInUse(targetPort);
    if (inUse) {
      if (!sawListening) {
        sawListening = true;
        // Give a freshly started server a moment to answer before declaring
        // the port occupied by an impostor.
        await new Promise((r) => setTimeout(r, intervalMs));
        continue;
      }
      if (await isBackendHealthy(url)) return { ok: true };
      return { ok: false, reason: 'not-phishguard' };
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return { ok: false, reason: 'timeout' };
}

/**
 * Spawn the backend child. Returns the ChildProcess.
 * stdout/stderr are piped so the caller can route them into a log.
 */
function startBackend({ projectRoot, packaged = false, dataDir, env = {} } = {}) {
  const { command, args, cwd } = resolveBackendCommand({ projectRoot, packaged });
  const child = spawn(command, args, {
    cwd,
    env: backendEnv({ dataDir, extra: env }),
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  child.__phishguardBackend = true;
  return child;
}

/**
 * Gracefully stop the backend WE started. Never touches other processes.
 * 1) kill() (SIGTERM-equivalent) -> 2) grace wait -> 3) force kill.
 */
async function stopBackend(child, { graceMs = 6000 } = {}) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  return new Promise((resolve) => {
    let done = false;
    const finish = () => { if (!done) { done = true; clearInterval(poll); resolve(); } };
    child.once('exit', finish);
    try { child.kill(); } catch { /* already gone */ }
    const poll = setInterval(() => {
      if (child.exitCode !== null || child.signalCode !== null) finish();
    }, 100);
    setTimeout(() => {
      if (!done) {
        try { child.kill('SIGKILL'); } catch { /* best effort */ }
        setTimeout(finish, 250);
      }
    }, graceMs);
  });
}

module.exports = {
  BACKEND_PORT,
  BACKEND_URL,
  resolveBackendCommand,
  backendEnv,
  defaultDataDir,
  isPortInUse,
  isBackendHealthy,
  waitForBackend,
  startBackend,
  stopBackend,
};
