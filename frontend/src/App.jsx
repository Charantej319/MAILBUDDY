import React, { useState, useEffect } from 'react'
import { Routes, Route, Link, useLocation, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import EmailList from './pages/EmailList'
import EmailAnalysis from './pages/EmailAnalysis'
import Analytics from './pages/Analytics'
import Settings from './pages/Settings'
import AssistantPanel from './components/AssistantPanel'
import NotificationBridge from './components/NotificationBridge'
import MailBuddyBrand from './components/MailBuddyBrand'
import { api } from './services/api'

const Icons = {
  shield: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  dashboard: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>
    </svg>
  ),
  mail: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>
    </svg>
  ),
  chart: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>
    </svg>
  ),
  settings: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  ),
  alertTriangle: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  ),
}

function App() {
  const location = useLocation()
  const [gmailStatus, setGmailStatus] = useState({ connected: false, email: null, last_sync: null })
  const [assistantOpen, setAssistantOpen] = useState(false)

  useEffect(() => {
    api.getGmailStatus().then(setGmailStatus).catch(() => {})
  }, [location.pathname])

  const navItems = [
    { path: '/', label: 'Dashboard', icon: Icons.dashboard },
    { path: '/emails', label: 'Emails', icon: Icons.mail },
    { path: '/analytics', label: 'Analytics', icon: Icons.chart },
    { path: '/settings', label: 'Settings', icon: Icons.settings },
  ]

  const isActive = (path) => {
    if (path === '/') return location.pathname === '/'
    return location.pathname.startsWith(path)
  }

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <MailBuddyBrand size={24} />
        </div>

        <nav className="sidebar-nav">
          <div className="sidebar-section-label">Navigation</div>
          {navItems.map(item => (
            <Link
              key={item.path}
              to={item.path}
              className={`sidebar-link ${isActive(item.path) ? 'active' : ''}`}
            >
              {item.icon}
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="sidebar-footer">
          <Link to="/settings" className="sidebar-link gmail-footer-link">
            <span className={`gmail-status-dot ${gmailStatus.connected ? 'connected' : ''}`}></span>
            {gmailStatus.connected ? 'Gmail Connected' : 'Gmail Not Connected'}
          </Link>
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <span className="topbar-title">
            {navItems.find(i => isActive(i.path))?.label || 'MailBuddy'}
          </span>
          <div className="topbar-actions">
            <button
              className="topbar-assistant-btn"
              onClick={() => setAssistantOpen((o) => !o)}
              aria-label="Open MailBuddy Assistant"
              title="MailBuddy Assistant"
            >
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
              </svg>
              <span className="topbar-assistant-label">Assistant</span>
            </button>
            <div className="gmail-status-indicator">
              <span className={`gmail-status-dot ${gmailStatus.connected ? 'connected' : ''}`}></span>
              <span className="gmail-status-text">
                {gmailStatus.connected ? gmailStatus.email : 'Not Connected'}
              </span>
            </div>
            <Link to="/settings" className="topbar-settings-btn">
              {Icons.settings}
            </Link>
          </div>
        </header>

        <div className="page-content">
          <Routes>
            <Route path="/" element={<Dashboard gmailStatus={gmailStatus} />} />
            <Route path="/emails" element={<EmailList gmailStatus={gmailStatus} />} />
            <Route path="/emails/:id" element={<EmailAnalysis />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/settings" element={<Settings gmailStatus={gmailStatus} setGmailStatus={setGmailStatus} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>

        <AssistantPanel open={assistantOpen} onClose={() => setAssistantOpen(false)} />
        <NotificationBridge />
      </div>
    </div>
  )
}

export default App
