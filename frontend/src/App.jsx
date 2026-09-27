import React, { useState, useEffect } from 'react'
import { Routes, Route, Link, useLocation, useNavigate, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import EmailList from './pages/EmailList'
import EmailAnalysis from './pages/EmailAnalysis'
import Analytics from './pages/Analytics'
import Settings from './pages/Settings'
import PriorityPage from './pages/PriorityPage'
import SecurityPage from './pages/SecurityPage'
import AssistantPanel from './components/AssistantPanel'
import NotificationBridge from './components/NotificationBridge'
import MailBuddyBrand from './components/MailBuddyBrand'
import { api } from './services/api'
import { LEVEL_META } from './utils/priority'

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
  flag: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/>
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
  // Email context for the assistant: { id, subject } when opened from an email,
  // null for global mailbox chat.
  const [assistantEmail, setAssistantEmail] = useState(null)

  useEffect(() => {
    api.getGmailStatus().then(setGmailStatus).catch(() => {})
  }, [location.pathname])

  // F-23: background polling is enabled by default — auto-start it once per
  // app load when an authenticated Gmail account exists. The backend is the
  // authority: it requires a session cookie + a connected token row, and is
  // idempotent ('already_polling' instead of a duplicate poller).
  useEffect(() => {
    let cancelled = false
    const ensurePolling = async () => {
      try {
        const status = await api.getGmailStatus()
        if (cancelled || !status?.connected) return
        const res = await api.startGmailPolling()
        if (!cancelled && res?.status) {
          // 'started' | 'already_polling' — both are success; no UI action needed.
        }
      } catch {
        // Polling is best-effort: sync still works manually from Settings.
      }
    }
    ensurePolling()
    return () => { cancelled = true }
  }, [])

  const openGlobalAssistant = () => {
    setAssistantEmail(null)
    setAssistantOpen(true)
  }

  const openEmailAssistant = (email, question = null) => {
    if (email?.id) {
      setAssistantEmail({ id: email.id, subject: email.subject, prefill: question || undefined })
      setAssistantOpen(true)
    }
  }

  const clearAssistantPrefill = () => {
    setAssistantEmail((prev) => (prev ? { id: prev.id, subject: prev.subject } : prev))
  }

  const navItems = [
    { path: '/', label: 'Dashboard', icon: Icons.dashboard },
    { path: '/emails', label: 'Inbox', icon: Icons.mail },
    { path: '/priority', label: 'Priority', icon: Icons.flag },
    { path: '/security', label: 'Security', icon: Icons.shield },
    { path: '/analytics', label: 'Analytics', icon: Icons.chart },
    { path: '/settings', label: 'Settings', icon: Icons.settings },
  ]

  const isActive = (path) => {
    if (path === '/') return location.pathname === '/'
    if (path === '/priority') return location.pathname.startsWith('/priority')
    if (path === '/security') return location.pathname.startsWith('/security')
    return location.pathname.startsWith(path)
  }

  // Priority summary for the sidebar counts (dashboard already fetches this;
  // the sidebar keeps its own lightweight copy so it works on every screen).
  const [priorityCounts, setPriorityCounts] = useState(null)
  useEffect(() => {
    let cancelled = false
    const load = () => api.getPrioritySummary().then((s) => { if (!cancelled) setPriorityCounts(s?.counts || {}) }).catch(() => {})
    load()
    const t = setInterval(load, 60000)
    return () => { cancelled = true; clearInterval(t) }
  }, [])
  useEffect(() => {
    // refresh counts right after navigating (uploads/syncs change them)
    api.getPrioritySummary().then((s) => setPriorityCounts(s?.counts || {})).catch(() => {})
  }, [location.pathname])

  const sidebarPriorities = ['CRITICAL', 'HIGH', 'NORMAL', 'LOW']

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <MailBuddyBrand size={24} />
        </div>

        <nav className="sidebar-nav">
          <div className="sidebar-section-label">Mailbox</div>
          {navItems.map(item => (
            <Link
              key={item.path}
              to={item.path}
              className={`sidebar-link ${isActive(item.path) ? 'active' : ''}`}
              aria-current={isActive(item.path) ? 'page' : undefined}
            >
              {item.icon}
              {item.label}
            </Link>
          ))}

          <div className="sidebar-section-label" style={{ marginTop: 10 }}>Priority</div>
          {sidebarPriorities.map((level) => {
            const meta = LEVEL_META[level]
            const active = location.pathname === `/priority/${level}`
            const count = priorityCounts?.[level]
            return (
              <Link
                key={level}
                to={`/priority/${level}`}
                className={`sidebar-link sidebar-prio-link ${meta.icon} ${active ? 'active' : ''}`}
                aria-current={active ? 'page' : undefined}
              >
                <span className={`prio-dot ${meta.dot}`} aria-hidden="true"></span>
                <span className="sidebar-prio-label">{meta.label}</span>
                {count !== undefined && count !== null && (
                  <span className="sidebar-prio-count" aria-label={`${count} ${meta.label.toLowerCase()} emails`}>{count}</span>
                )}
              </Link>
            )
          })}
        </nav>

        <div className="sidebar-footer">
          <button
            className={`sidebar-link sidebar-assistant-btn ${assistantOpen ? 'active' : ''}`}
            onClick={openGlobalAssistant}
            aria-label="Ask MailBuddy"
            title="Ask MailBuddy"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
            </svg>
            Ask MailBuddy
          </button>
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
              onClick={() => (assistantOpen ? setAssistantOpen(false) : openGlobalAssistant())}
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
            <Route path="/emails/:id" element={<EmailAnalysis onAskAssistant={openEmailAssistant} />} />
            <Route path="/priority" element={<PriorityPage />} />
            <Route path="/priority/:level" element={<PriorityPage />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/settings" element={<Settings gmailStatus={gmailStatus} setGmailStatus={setGmailStatus} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>

        <AssistantPanel
          open={assistantOpen}
          onClose={() => setAssistantOpen(false)}
          emailContext={assistantEmail}
          onClearContext={() => setAssistantEmail(null)}
          onPrefillDone={clearAssistantPrefill}
        />
        <NotificationBridge />
      </div>
    </div>
  )
}

export default App
