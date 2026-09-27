import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.jsx'
import { setApiToken } from './services/api.js'
import './index.css'
import './mailbuddy.css'

// Pull the local API bearer token from the Electron main process (IPC) once
// at startup and keep it in memory only (see services/api.js). Never stored
// in localStorage/sessionStorage/cookies, never placed in URLs. In browser
// dev mode there is no electronAPI and requests go out without the header
// until a token is provided via setApiToken() from the dev console.
async function bootstrapApiToken() {
  try {
    if (window.electronAPI?.getApiToken) {
      const token = await window.electronAPI.getApiToken()
      if (typeof token === 'string' && token.length > 0) {
        setApiToken(token)
      }
    }
  } catch {
    // Token delivery is best-effort at startup; cookie-only surfaces
    // (/auth, /api/gmail with a session) keep working without it.
  }
}

const apiTokenReady = bootstrapApiToken()

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)

// Hold a reference so bundlers/linters cannot flag the promise; first /api
// calls wait for the token to be available before the first paint completes.
export { apiTokenReady }
