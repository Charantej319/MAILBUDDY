/**
 * PhishGuard desktop shell — preload.
 *
 * The renderer is plain same-origin web content served by the local FastAPI
 * backend and needs NO Node access and NO general-purpose IPC. The ONLY
 * exposed surface is a one-way native-notification call used by
 * NotificationBridge.jsx: it forwards two bounded strings to the main process,
 * which delivers the Windows toast (and owns the AppUserModelID needed for it
 * to display). No file paths, no shell, no tokens, no arbitrary channels —
 * GROQ_API_KEY, Gmail tokens and the filesystem are never reachable from the
 * renderer.
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
});
