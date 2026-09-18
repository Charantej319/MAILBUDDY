import React, { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import { formatRelativeTime } from '../utils/time'

function Dashboard({ gmailStatus }) {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    loadStats()
  }, [])

  const loadStats = async () => {
    try {
      const data = await api.getStatistics()
      setStats(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="loading-state">
        <div className="spinner"></div>
        <span>Loading dashboard...</span>
      </div>
    )
  }

  const total = stats?.total_emails || 0
  const high = stats?.high_risk_count || 0
  const suspicious = stats?.suspicious_count || 0
  const safe = stats?.safe_count || 0
  const low = stats?.low_risk_count || 0
  const threats = high + suspicious
  const recentThreats = stats?.recent_threats || []

  return (
    <div>
      {/* Gmail Connection Prompt */}
      {total === 0 && !gmailStatus?.connected && (
        <div className="onboarding-card">
          <div className="onboarding-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ width: 32, height: 32 }}>
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div className="onboarding-content">
            <h3>Connect your Gmail account</h3>
            <p>Analyze incoming emails for phishing, suspicious links, social engineering and authentication anomalies.</p>
            <div className="onboarding-actions">
              <button className="btn btn-primary" onClick={() => navigate('/settings')}>Connect Gmail</button>
              <span className="onboarding-separator">or</span>
              <Link to="/emails?upload=true" className="btn btn-secondary">Upload .eml file</Link>
            </div>
          </div>
        </div>
      )}

      {/* Operational Overview */}
      <div className="page-header">
        <div className="page-header-left">
          <h1>Dashboard</h1>
          <p>Operational overview — what needs your attention</p>
        </div>
        <div className="page-header-actions">
          {gmailStatus?.connected && (
            <Link to="/emails" className="btn btn-primary">View Emails</Link>
          )}
          {!gmailStatus?.connected && total === 0 && (
            <button className="btn btn-secondary" onClick={() => navigate('/settings')}>Connect Gmail</button>
          )}
        </div>
      </div>

      {/* Compact Metrics */}
      <div className="metrics-row">
        <div className="metric-card">
          <div className="metric-label">Emails Analyzed</div>
          <div className="metric-value">{total}</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Threats Detected</div>
          <div className="metric-value" style={{ color: threats > 0 ? 'var(--high-risk)' : 'var(--safe)' }}>{threats}</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Gmail Status</div>
          <div className="metric-value" style={{ fontSize: 'var(--text-md)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span className={`gmail-status-dot ${gmailStatus?.connected ? 'connected' : ''}`}></span>
            {gmailStatus?.connected ? 'Connected' : 'Not Connected'}
          </div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Last Sync</div>
          <div className="metric-value" style={{ fontSize: 'var(--text-sm)', fontWeight: 500 }}>
            {gmailStatus?.last_sync ? formatRelativeTime(gmailStatus.last_sync) : 'Never'}
          </div>
        </div>
      </div>

      {/* Threats Requiring Attention */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">Threats Requiring Attention</span>
          {threats > 0 && <Link to="/emails" className="btn btn-ghost btn-sm">View all</Link>}
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {recentThreats.length > 0 ? (
            <div className="threat-list">
              {recentThreats.map(email => (
                <div key={email.id} className="threat-list-item" onClick={() => navigate(`/emails/${email.id}`)}>
                  <div className="threat-list-score" style={{ color: getScoreColor(email.risk_score) }}>
                    {email.risk_score.toFixed(0)}
                  </div>
                  <div className="threat-list-content">
                    <div className="threat-list-subject">{email.subject || '(no subject)'}</div>
                    <div className="threat-list-sender">{email.sender_email || email.sender}</div>
                  </div>
                  <div className="threat-list-meta">
                    <span className={`badge ${getBadgeClass(email.classification)}`}>
                      {getShortClassification(email.classification)}
                    </span>
                    <span className="threat-list-time">{formatRelativeTime(email.analyzed_at || email.date)}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state-inline">
              <span className="empty-state-text">
                {total === 0
                  ? 'No emails analyzed yet. Connect Gmail or upload .eml files.'
                  : 'No threats detected. Your inbox appears clean.'}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Risk Distribution + Top Domains */}
      <div className="grid-2">
        {/* Risk Distribution */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Risk Distribution</span>
          </div>
          <div className="card-body">
            {total > 0 ? (
              <div className="risk-distribution">
                {[
                  { label: 'Safe', count: safe, cls: 'safe', color: 'var(--safe)' },
                  { label: 'Low Risk', count: low, cls: 'low', color: 'var(--low-risk)' },
                  { label: 'Suspicious', count: suspicious, cls: 'suspicious', color: 'var(--suspicious)' },
                  { label: 'High Risk', count: high, cls: 'high', color: 'var(--high-risk)' },
                ].map(item => (
                  <div key={item.label} className="risk-dist-row">
                    <div className="risk-dist-label">
                      <span className="risk-dist-dot" style={{ background: item.color }}></span>
                      <span>{item.label}</span>
                    </div>
                    <div className="risk-dist-bar-wrap">
                      <div className="risk-dist-bar">
                        <div className={`risk-bar-fill ${item.cls}`} style={{ width: `${(item.count / total) * 100}%` }}></div>
                      </div>
                      <span className="risk-dist-count">{item.count}</span>
                      <span className="risk-dist-pct">({total > 0 ? ((item.count / total) * 100).toFixed(0) : 0}%)</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state-inline">
                <span className="empty-state-text">No data yet.</span>
              </div>
            )}
          </div>
        </div>

        {/* Top Sender Domains */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Top Sender Domains</span>
          </div>
          <div className="card-body">
            {stats?.top_sender_domains?.length > 0 ? (
              <div className="domain-list">
                {stats.top_sender_domains.slice(0, 8).map((item, idx) => (
                  <div key={idx} className="domain-row">
                    <span className="domain-name">{item.domain}</span>
                    <span className="domain-count">{item.count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state-inline">
                <span className="empty-state-text">No data yet.</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function getScoreColor(score) {
  if (score < 25) return 'var(--safe)'
  if (score < 50) return 'var(--low-risk)'
  if (score < 75) return 'var(--suspicious)'
  return 'var(--high-risk)'
}

function getBadgeClass(classification) {
  if (classification === 'SAFE') return 'badge-safe'
  if (classification === 'LOW RISK') return 'badge-low'
  if (classification === 'SUSPICIOUS') return 'badge-suspicious'
  return 'badge-high'
}

function getShortClassification(classification) {
  if (classification === 'LOW RISK') return 'LOW'
  if (classification === 'HIGH RISK') return 'HIGH'
  return classification
}

export default Dashboard
