/**
 * PhishGuard desktop shell — preload.
 *
 * Phase 2b: the renderer is plain same-origin web content served by the local
 * FastAPI backend and needs NO Node access and NO custom IPC, so nothing is
 * exposed. This file exists so the secure pipeline is wired and future,
 * explicitly-scoped bridges (e.g. "open external link" with an allowlist) can
 * be added deliberately — never by loosening contextIsolation.
 */
'use strict';

// Intentionally empty: no contextBridge exposure. GROQ_API_KEY, Gmail tokens,
// the filesystem and shell access are never reachable from the renderer.
