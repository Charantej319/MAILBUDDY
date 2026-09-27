/**
 * PhishGuard desktop shell — preload.
 *
 * The renderer is plain same-origin web content served by the local FastAPI
 * backend. Exposed surface is intentionally minimal:
 *
 *   1. showNotification  — one-way native toast bridge (NotificationBridge.jsx).
 *   2. getApiToken       — pulls the local API bearer token from the main
 *      process ONCE via IPC. The token is then kept only in renderer memory
 *      (services/api.js) and sent as `Authorization: Bearer` on /api calls.
 *      It is never written to localStorage, never placed in a URL, never
 *      logged. GROQ_API_KEY, Gmail tokens and the filesystem stay unreachable.
 */
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  showNotification: ({ title, body } = {}) => {
    if (typeof title !== 'string' || typeof body !== 'string') return;
    ipcRenderer.send('mailbuddy:notification', {
      title: title.slice(0, 140),
      body: body.slice(0, 300),
    });
  },

  getApiToken: () => ipcRenderer.invoke('mailbuddy:get-api-token'),
});
