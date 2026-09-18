/**
 * MailBuddy desktop shell (formerly PhishGuard) — Electron main process.
 *
 * Responsibilities (Phase 2b):
 *   1. Single-instance lock
 *   2. Resolve the per-user data dir (%APPDATA%\PhishGuard) and export it to
 *      the backend as PHISHGUARD_DATA_DIR
 *   3. Preflight port 8000 (never kills foreign processes)
 *   4. Spawn the FastAPI backend, capture its output into a controlled log
 *   5. Poll /api/health (no fixed sleeps), then open the window
 *   6. Graceful backend shutdown on quit (no orphans)
 *
 * Phase 2c swap point: startBackend({ packaged }) already understands the
 * packaged command; no redesign will be needed.
 */
'use strict';

const path = require('path');
const fs = require('fs');
const { app, BrowserWindow, dialog, shell } = require('electron');
const backend = require('./backend');

const APP_TITLE = 'MailBuddy';
const BACKEND_URL = backend.BACKEND_URL; // http://127.0.0.1:8000
const shouldQuit = process.argv.includes('--e2e-quit-after');
const lockAcquired = app.requestSingleInstanceLock();

// ── Single instance ──────────────────────────────────────────────────
if (!lockAcquired) {
  app.quit();
} else {
  app.on('second-instance', () => {
    const [win] = BrowserWindow.getAllWindows();
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });
}

let backendProc = null;
let backendLogPath = null;

/** Route backend stdout/stderr into %APPDATA%/PhishGuard/logs/backend.log. */
function attachBackendLogging(child, dataDir) {
  try {
    const logsDir = path.join(dataDir, 'logs');
    fs.mkdirSync(logsDir, { recursive: true });
    backendLogPath = path.join(logsDir, 'backend.log');
    const stream = fs.createWriteStream(backendLogPath, { flags: 'a' });
    const stamp = () => new Date().toISOString();
    child.stdout.on('data', (d) => stream.write(`[${stamp()}] [stdout] ${d}`));
    child.stderr.on('data', (d) => stream.write(`[${stamp()}] [stderr] ${d}`));
    child.on('exit', (code, signal) => {
      stream.write(`[${stamp()}] [exit] code=${code} signal=${signal}\n`);
      stream.end();
    });
  } catch (err) {
    // Logging is best-effort; never block startup on it.
    console.error('backend log setup failed:', err.message);
  }
}

/** Native error dialog with the log location for diagnosis. */
function showFatalError(title, message) {
  const logHint = backendLogPath ? `\n\nBackend log:\n${backendLogPath}` : '';
  dialog.showErrorBox(title, `${message}${logHint}`);
}

async function startBackendOrDie() {
  const dataDir = backend.defaultDataDir();
  fs.mkdirSync(dataDir, { recursive: true });

  // 1. Is a healthy PhishGuard backend already running? Adopt it instead of
  //    spawning a duplicate (e.g. dev uvicorn or a previous instance).
  if (await backend.isBackendHealthy()) {
    console.log('[phishguard] healthy backend already running on :8000 — adopting it');
    return null; // null = nothing to shut down later; do NOT kill foreign process
  }

  // 2. Port occupied by something else? Refuse with a clear error, never kill.
  const { inUse, pid } = await backend.isPortInUse();
  if (inUse) {
    const who = pid ? ` (PID ${pid})` : '';
    showFatalError(
      'MailBuddy — port already in use',
      `Port 8000 is already in use by another program${who}.\n\n` +
      'MailBuddy needs port 8000 for its local backend and Gmail sign-in.\n' +
      'Close the other program and start MailBuddy again.\n\n' +
      'MailBuddy did NOT terminate that process.',
    );
    throw new Error(`port 8000 in use by PID ${pid ?? 'unknown'}`);
  }

  // 3. Start the backend with the per-user data dir.
  // Packaged mode (PyInstaller exe) is selected when running from an installed
  // app OR when PHISHGUARD_BACKEND_EXE overrides the path for local testing.
  const packagedMode = app.isPackaged || !!process.env.PHISHGUARD_BACKEND_EXE;
  backendProc = backend.startBackend({
    projectRoot: path.resolve(__dirname, '..'),
    packaged: packagedMode,
    dataDir,
  });
  attachBackendLogging(backendProc, dataDir);
  console.log(`[phishguard] backend spawned (pid ${backendProc.pid}), data dir: ${dataDir}`);

  backendProc.on('exit', (code, signal) => {
    if (!app.isQuitting && !shouldQuit) {
      // Backend died unexpectedly — tell the user instead of a blank window.
      showFatalError(
        'PhishGuard backend stopped unexpectedly',
        `The PhishGuard backend exited (code ${code ?? '-'} signal ${signal ?? '-'}).`,
      );
    }
  });

  // 4. Poll health — no fixed sleeps.
  const waited = await backend.waitForBackend({ timeoutMs: 45000 });
  if (!waited.ok) {
    const reason = waited.reason === 'not-phishguard'
      ? 'Port 8000 was taken over by another program while PhishGuard was starting.'
      : 'The PhishGuard backend did not become healthy within 45 seconds.';
    showFatalError('PhishGuard failed to start', reason);
    throw new Error(`backend startup failed: ${waited.reason}`);
  }
  return backendProc;
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1360,
    height: 880,
    minWidth: 1024,
    minHeight: 640,
    title: APP_TITLE,
    icon: path.join(__dirname, 'icon.ico'),
    show: false,
    backgroundColor: '#0f1115',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,   // renderer isolated from Node
      nodeIntegration: false,   // no Node in the renderer
      sandbox: true,            // renderer sandboxed
      webviewTag: false,
      // Nothing custom is exposed; the app is plain same-origin web content.
    },
  });

  // The existing React app handles all navigation internally (BrowserRouter).
  // The Google OAuth consent screen is allowed to navigate IN the app window so
  // the existing callback (http://localhost:8000/auth/google/callback) returns
  // into this same window — no OAuth code changes, cookie lands on the app
  // origin. Any other external target opens in the default browser; email
  // links remain non-clickable sanitized text per the existing security model
  // (we never auto-open them).
  const GOOGLE_AUTH_HOSTS = /^https:\/\/(accounts\.google\.com|www\.googleusercontent\.com|ssl\.gstatic\.com|www\.google\.com)\//i;
  win.webContents.setWindowOpenHandler(({ url }) => {
    // Consent flows that insist on popups go to the default browser instead.
    if (GOOGLE_AUTH_HOSTS.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (event, url) => {
    const local = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//i.test(url + '/');
    if (local || GOOGLE_AUTH_HOSTS.test(url) || url.startsWith('data:')) return; // allowed in-app
    event.preventDefault();
    if (/^https:\/\//i.test(url)) shell.openExternal(url); // explicit https only
  });

  win.once('ready-to-show', () => win.show());
  win.loadURL(BACKEND_URL); // http://127.0.0.1:8000 — the React SPA + API origin
  return win;
}

app.isQuitting = false;
app.on('before-quit', () => { app.isQuitting = true; });

app.whenReady().then(async () => {
  try {
    await startBackendOrDie();
    createWindow();
    if (shouldQuit) {
      // E2E mode: verify the window loaded real content + security posture,
      // then quit cleanly (before-quit stops the backend).
      const [win] = BrowserWindow.getAllWindows();
      win.webContents.once('did-finish-load', async () => {
        setTimeout(async () => {
          const title = win.webContents.getTitle();
          const text = await win.webContents.executeJavaScript('document.body.innerText.slice(0, 400)').catch(() => '');
          const probe = await win.webContents.executeJavaScript(`JSON.stringify({
            hasRequire: typeof require !== 'undefined',
            hasProcess: typeof process !== 'undefined',
            sandboxed: typeof process !== 'undefined' ? !!process.sandboxed : null,
            nodeIntegrationGlobal: typeof global !== 'undefined' && global !== window,
            exposedKeys: Object.keys(window).filter(k => /phishguard|backend|electron/i.test(k)),
            groqKeyInStorage: ['localStorage', 'sessionStorage'].some(s => {
              try { return Object.values(window[s]).some(v => /gsk_[A-Za-z0-9]{10,}/.test(String(v))); } catch { return false; }
            }),
            groqKeyInCookie: /gsk_[A-Za-z0-9]{10,}/.test(document.cookie),
          })`).catch(() => '{}');
          console.log('E2E_WINDOW_TITLE=' + title);
          console.log('E2E_BODY_HEAD=' + JSON.stringify(text));
          console.log('E2E_SECURITY=' + probe);
          app.quit();
        }, 5000);
      });
    }
  } catch (err) {
    console.error('[phishguard] startup failed:', err.message);
    app.exit(1);
  }
});

app.on('window-all-closed', () => {
  app.quit(); // standard Windows behavior: closing the window quits the app
});

app.on('before-quit', async (event) => {
  if (!backendProc || app.__backendStopped) return;
  // Hold the quit until OUR backend child is stopped (no orphans).
  event.preventDefault();
  app.__backendStopping = true;
  try {
    await backend.stopBackend(backendProc, { graceMs: 6000 });
  } finally {
    backendProc = null;
    app.__backendStopped = true;
    app.quit(); // resume the quit
  }
});

// Last-resort safety net: if the quit path above somehow skipped the stop.
process.on('exit', () => {
  if (backendProc && backendProc.exitCode === null && !app.__backendStopped) {
    try { backendProc.kill(); } catch { /* best effort */ }
  }
});
