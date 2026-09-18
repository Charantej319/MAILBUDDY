import React, { useState, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../services/api'
import { formatRelativeTime } from '../utils/time'

function Settings({ gmailStatus, setGmailStatus }) {
  const [searchParams, setSearchParams] = useSearchParams()
  const [disconnecting, setDisconnecting] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [syncResult, setSyncResult] = useState(null)
  const [error, setError] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const verifiedRef = useRef(false)
  const [mbSettings, setMbSettings] = useState(null)
  const [mbSaving, setMbSaving] = useState(false)

  useEffect(() => {
    api.getMailBuddySettings().then((d) => setMbSettings(d.settings)).catch(() => setMbSettings(null))
  }, [])

  const toggleMbSetting = async (key) => {
    if (mbSaving || !mbSettings) return
    setMbSaving(true)
    const next = { ...mbSettings, [key]: !mbSettings[key] }
    setMbSettings(next) // optimistic
    try {
      const data = await api.updateMailBuddySettings({ [key]: next[key] })
      setMbSettings(data.settings)
    } catch {
      setMbSettings(mbSettings) // revert on failure
    } finally {
      setMbSaving(false)
    }
  }

  const connected = gmailStatus?.connected || false

  useEffect(() => {
    if (searchParams.get('connected') === 'true') {
      // Verify the connection with the backend instead of trusting the URL,
      // and surface an explicit error if the session did not stick.
      if (!verifiedRef.current) {
        verifiedRef.current = true
        setVerifying(true)
        api.getGmailStatus()
          .then((status) => {
            setGmailStatus(status)
            if (!status.connected) {
              setError('Gmail sign-in completed but the session could not be established. Please reconnect.')
            }
          })
          .catch(() => setError('Could not verify Gmail connection. Is the backend running?'))
          .finally(() => setVerifying(false))
      }
      setSearchParams({})
    }
    if (searchParams.get('error')) {
      setError(api.explainOAuthError(searchParams.get('error')))
      setSearchParams({})
    }
  }, [])

  const handleConnect = () => {
    api.connectGmail()
  }

  const handleDisconnect = async () => {
    setDisconnecting(true)
    try {
      await api.disconnectGmail()
      setGmailStatus({ connected: false, email: null, last_sync: null })
    } catch (err) {
      setError(err.message)
    } finally {
      setDisconnecting(false)
    }
  }

  const handleSync = async () => {
    setSyncing(true)
    setSyncResult(null)
    setError(null)
    try {
      const result = await api.syncGmail(50)
      setSyncResult(result)
      const status = await api.getGmailStatus()
      setGmailStatus(status)
    } catch (err) {
      setError(err.message)
    } finally {
      setSyncing(false)
    }
  }

  return (
    <div>
      <div className="page-header">
        <div className="page-header-left">
          <h1>Settings</h1>
          <p>Manage Gmail connection, threat intelligence, and application settings</p>
        </div>
      </div>

      {error && (
        <div className="alert alert-error" style={{ marginBottom: 'var(--space-4)' }}>
          <span>{error}</span>
          <button className="btn btn-ghost btn-sm" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      {syncResult && (
        <div className="alert alert-success" style={{ marginBottom: 'var(--space-4)' }}>
          <span>Sync complete: {syncResult.synced} new emails analyzed, {syncResult.skipped} already processed.</span>
        </div>
      )}

      {/* Gmail Connection */}
      <div className="settings-section">
        <div className="settings-section-header">
          <div className="settings-section-title">Gmail Connection</div>
          <div className="settings-section-desc">Connect your Gmail account for real-time email threat analysis</div>
        </div>
        <div className="settings-section-body">
          <div className="gmail-connection-status">
            <div className="gmail-status-info">
              <div className="gmail-status-row">
                <span className={`gmail-status-dot ${connected ? 'connected' : ''}`}></span>
                <span className="gmail-status-state">
                  {connected ? 'Connected' : 'Not Connected'}
                </span>
              </div>
              {connected && (
                <div className="gmail-status-details">
                  <span className="gmail-email">{gmailStatus.email}</span>
                  {gmailStatus.last_sync && (
                    <span className="gmail-sync-time">
                      Last sync: {formatRelativeTime(gmailStatus.last_sync)}
                    </span>
                  )}
                  {gmailStatus.synced_emails > 0 && (
                    <span className="gmail-sync-count">
                      {gmailStatus.synced_emails} emails analyzed
                    </span>
                  )}
                </div>
              )}
            </div>
            <div className="gmail-actions">
              {connected ? (
                <>
                  <button className="btn btn-primary" onClick={handleSync} disabled={syncing}>
                    {syncing ? (
                      <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }}></span> Syncing...</>
                    ) : 'Sync Now'}
                  </button>
                  <button className="btn btn-secondary" onClick={handleDisconnect} disabled={disconnecting}>
                    {disconnecting ? 'Disconnecting...' : 'Disconnect'}
                  </button>
                </>
              ) : (
                <button className="btn btn-primary" onClick={handleConnect} disabled={verifying}>
                  {verifying ? (
                    <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }}></span> Verifying connection...</>
                  ) : 'Connect Gmail'}
                </button>
              )}
            </div>
          </div>

          {connected && gmailStatus.last_sync && (
            <div className="settings-note">
              Background polling checks for new emails every 60 seconds when the application is running.
            </div>
          )}
        </div>
      </div>

      {/* MailBuddy Assistant & Priority */}
      <div className="settings-section">
        <div className="settings-section-header">
          <div className="settings-section-title">MailBuddy</div>
          <div className="settings-section-desc">Assistant, smart priority and notifications. Disabling AI never disables the security engine.</div>
        </div>
        <div className="settings-section-body">
          {mbSettings ? (
            <div className="mb-settings-grid">
              {[
                { key: 'assistant_enabled', label: 'AI Assistant', desc: 'Read-only inbox assistant in the top bar' },
                { key: 'smart_priority_enabled', label: 'Smart Priority', desc: 'AI-assisted importance classification' },
                { key: 'important_notifications_enabled', label: 'Important Email Notifications', desc: 'For CRITICAL and HIGH priority email' },
                { key: 'desktop_notifications_enabled', label: 'Desktop Notifications', desc: 'Native notifications in the desktop app' },
              ].map((item) => (
                <div key={item.key} className="mb-setting-row">
                  <div className="mb-setting-text">
                    <span className="mb-setting-label">{item.label}</span>
                    <span className="mb-setting-desc">{item.desc}</span>
                  </div>
                  <button
                    className={`mb-toggle ${mbSettings[item.key] ? 'on' : ''}`}
                    onClick={() => toggleMbSetting(item.key)}
                    disabled={mbSaving}
                    role="switch"
                    aria-checked={mbSettings[item.key]}
                    aria-label={item.label}
                  >
                    <span className="mb-toggle-knob"></span>
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state-inline"><span className="empty-state-text">Settings unavailable.</span></div>
          )}
        </div>
      </div>

      {/* Polling Configuration */}
      <div className="settings-section">
        <div className="settings-section-header">
          <div className="settings-section-title">Polling Configuration</div>
          <div className="settings-section-desc">Configure how often MailBuddy checks for new emails</div>
        </div>
        <div className="settings-section-body">
          <div className="app-info-grid">
            <div className="app-info-item">
              <span className="app-info-label">Poll Interval</span>
              <span className="app-info-value">60 seconds</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">Initial Sync Count</span>
              <span className="app-info-value">50 emails</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">Max Emails per Sync</span>
              <span className="app-info-value">100 emails</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">Background Polling</span>
              <span className="app-info-value">{connected ? 'Active' : 'Inactive'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Intelligence */}
      <div className="settings-section">
        <div className="settings-section-header">
          <div className="settings-section-title">Threat Intelligence</div>
          <div className="settings-section-desc">Optional external threat intelligence providers (API keys via environment variables)</div>
        </div>
        <div className="settings-section-body">
          <div className="provider-grid">
            <div className="provider-item">
              <span className="provider-name">Local DNS Analysis</span>
              <span className="provider-status configured">Active</span>
            </div>
            <div className="provider-item">
              <span className="provider-name">Local Domain Intelligence</span>
              <span className="provider-status configured">Active</span>
            </div>
            <div className="provider-item">
              <span className="provider-name">Google Safe Browsing</span>
              <span className="provider-status unavailable">Not Configured</span>
            </div>
            <div className="provider-item">
              <span className="provider-name">VirusTotal</span>
              <span className="provider-status unavailable">Not Configured</span>
            </div>
            <div className="provider-item">
              <span className="provider-name">URLhaus</span>
              <span className="provider-status unavailable">Not Configured</span>
            </div>
            <div className="provider-item">
              <span className="provider-name">Intelligence Caching</span>
              <span className="provider-status configured">Active (1h TTL)</span>
            </div>
          </div>
          <div className="settings-note" style={{ marginTop: 'var(--space-4)' }}>
            External threat intelligence providers are optional. MailBuddy's local detection engine remains fully functional without API keys.
            Configure via environment variables: GOOGLE_SAFE_BROWSING_KEY, VIRUSTOTAL_KEY, URLHAUS_KEY
          </div>
        </div>
      </div>

      {/* Security & Privacy */}
      <div className="settings-section">
        <div className="settings-section-header">
          <div className="settings-section-title">Security & Privacy</div>
        </div>
        <div className="settings-section-body">
          <div className="security-info">
            <p>
              MailBuddy requests <strong>read-only</strong> Gmail access for email threat analysis.
              It does not send, delete, modify, or reply to emails.
            </p>
            <p>
              OAuth tokens are stored server-side in an encrypted database and are never exposed to the frontend.
              The application uses static URL analysis only and never visits links contained in emails.
            </p>
            <p>
              Attachments are never opened or executed. Only metadata (filename, extension, MIME type) is analyzed.
            </p>
            <p>
              External API keys are stored in environment variables and never sent to the frontend.
              Threat intelligence results are cached locally with a 1-hour TTL to reduce API usage.
            </p>
          </div>
        </div>
      </div>

      {/* Data Retention */}
      <div className="settings-section">
        <div className="settings-section-header">
          <div className="settings-section-title">Data Retention</div>
        </div>
        <div className="settings-section-body">
          <div className="app-info-grid">
            <div className="app-info-item">
              <span className="app-info-label">Analysis Results</span>
              <span className="app-info-value">Retained indefinitely</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">Email Content</span>
              <span className="app-info-value">Not stored (metadata only)</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">OAuth Tokens</span>
              <span className="app-info-value">Stored until disconnected</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">Intelligence Cache</span>
              <span className="app-info-value">1 hour TTL (in-memory)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Application Info */}
      <div className="settings-section">
        <div className="settings-section-header">
          <div className="settings-section-title">Application</div>
        </div>
        <div className="settings-section-body">
          <div className="app-info-grid">
            <div className="app-info-item">
              <span className="app-info-label">Version</span>
              <span className="app-info-value">2.0.0</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">Detection Engine</span>
              <span className="app-info-value">Evidence-weighted (explainable)</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">Database</span>
              <span className="app-info-value">SQLite (local)</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">Email Access</span>
              <span className="app-info-value">Read-only via Gmail API</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">Domain Intelligence</span>
              <span className="app-info-value">Local DNS, MX, SPF/DMARC</span>
            </div>
            <div className="app-info-item">
              <span className="app-info-label">Correlation Engine</span>
              <span className="app-info-value">Cross-signal analysis</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Settings
