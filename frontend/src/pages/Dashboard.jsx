import React, { useState, useEffect, useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import { formatRelativeTime } from '../utils/time'
import { LEVEL_META, priorityStyle, categoryLabel, formatDeadline } from '../utils/priority'
import { MailBuddyLogo } from '../components/MailBuddyBrand'

function Dashboard({ gmailStatus }) {
  const [summary, setSummary] = useState(null)
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeLevel, setActiveLevel] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    load()
  }, [])

  const load = async () => {
    try {
      const [priority, statistics] = await Promise.all([
        api.getPrioritySummary().catch(() => null),
        api.getStatistics().catch(() => null),
      ])
      setSummary(priority)
      setStats(statistics)
      // Fire a bounded AI refinement pass for pending emails (never blocks UI).
      if (priority?.pending > 0) {
        api.analyzeBatchPriorities(6).catch(() => {})
      }
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }



  const attention = summary?.attention || []
  const counts = summary?.counts || {}
  const pending = summary?.pending || 0
  const threats = (stats?.high_risk_count || 0) + (stats?.suspicious_count || 0)

  // Greeting
  const greeting = useMemo(() => {
    const h = new Date().getHours()
    if (h < 12) return 'Good morning'
    if (h < 18) return 'Good afternoon'
    return 'Good evening'
  }, [])

  if (loading) {
    return (
      <div className="loading-state">
        <div className="spinner"></div>
        <span>Loading dashboard...</span>
      </div>
    )
  }

  const total = stats?.total_emails || 0

  return (
    <div>
      {/* Gmail onboarding (unchanged behavior) */}
      {total === 0 && !gmailStatus?.connected && (
        <div className="onboarding-card">
          <div className="onboarding-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ width: 32, height: 32 }}>
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div className="onboarding-content">
            <h3>Connect your Gmail account</h3>
            <p>MailBuddy analyzes incoming email for phishing, suspicious links and social engineering — and surfaces what actually needs your attention.</p>
            <div className="onboarding-actions">
              <button className="btn btn-primary" onClick={() => navigate('/settings')}>Connect Gmail</button>
              <span className="onboarding-separator">or</span>
              <Link to="/emails?upload=true" className="btn btn-secondary">Upload .eml file</Link>
            </div>
          </div>
        </div>
      )}

      {/* MailBuddy header */}
      <div className="mb-hero">
        <div className="mb-hero-greeting">
          <div className="mb-hero-brand">
            <MailBuddyLogo size={26} />
            <span>MailBuddy</span>
          </div>
          <h1>{greeting}</h1>
          <p>Here's what needs your attention.</p>
        </div>
        {threats > 0 && (
          <div className="mb-hero-security" title="From the security engine — separate from priority">
            <span className="mb-hero-security-count">{threats}</span>
            <span className="mb-hero-security-label">security flag{threats === 1 ? '' : 's'} detected</span>
          </div>
        )}
      </div>

      {/* Compact color-coded stat chips (V2) — click a priority to open its page */}
      <div className="mb-stat-chips" role="navigation" aria-label="Priority and security overview">
        <button className="mb-stat-chip chip-critical" onClick={() => navigate('/priority/CRITICAL')}>
          <span className={`prio-dot prio-dot-critical`} aria-hidden="true"></span>
          Critical <b>{counts.CRITICAL || 0}</b>
        </button>
        <button className="mb-stat-chip chip-high" onClick={() => navigate('/priority/HIGH')}>
          <span className="prio-dot prio-dot-high" aria-hidden="true"></span>
          High <b>{counts.HIGH || 0}</b>
        </button>
        <button className="mb-stat-chip chip-normal" onClick={() => navigate('/priority/NORMAL')}>
          <span className="prio-dot prio-dot-normal" aria-hidden="true"></span>
          Normal <b>{counts.NORMAL || 0}</b>
        </button>
        <button className="mb-stat-chip chip-low" onClick={() => navigate('/priority/LOW')}>
          <span className="prio-dot prio-dot-low" aria-hidden="true"></span>
          Low <b>{counts.LOW || 0}</b>
        </button>
        {threats > 0 && (
          <button className="mb-stat-chip chip-security" onClick={() => navigate('/security')}>
            <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Security concerns <b>{threats}</b>
          </button>
        )}
      </div>

      {/* Level drill-down — now lives on the dedicated Priority pages */}

      {/* Attention required */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">Attention required</span>
          {pending > 0 && (
            <span className="mb-pending-note" title="AI refinement runs in the background">
              {pending} awaiting deeper analysis
            </span>
          )}
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {attention.length > 0 ? (
            <div className="mb-attention-list">
              {attention.map((email) => (
                <div key={email.id} className="mb-attention-item" onClick={() => navigate(`/emails/${email.id}`)}>
                  <div className="mb-attention-main">
                    <div className="mb-attention-sender">{email.sender || email.sender_email}</div>
                    <div className="mb-attention-subject">{email.subject || '(no subject)'}</div>
                    {email.reasons?.length > 0 && (
                      <div className="mb-attention-reason">{email.reasons[0]}</div>
                    )}
                  </div>
                  <div className="mb-attention-meta">
                    <div className="mb-attention-badges">
                      <PriorityBadge level={email.priority} />
                      <CategoryBadge category={email.category} />
                      <SecurityBadge classification={email.security} riskScore={email.risk_score} />
                    </div>
                    <div className="mb-attention-extras">
                      {email.deadline && <span className="mb-deadline">Deadline: {formatDeadline(email.deadline)}</span>}
                      <span className="mb-attention-time">{formatRelativeTime(email.date)}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state-inline">
              <span className="empty-state-text">
                {total === 0
                  ? 'No emails yet. Connect Gmail or upload .eml files to get started.'
                  : 'Nothing urgent right now. Your important mail will appear here.'}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Security section — separate axis, never merged with priority */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Security overview</span>
            <Link to="/analytics" className="btn btn-ghost btn-sm">Analytics</Link>
          </div>
          <div className="card-body">
            {total > 0 ? (
              <div className="risk-distribution">
                {[
                  { label: 'Safe', count: stats?.safe_count || 0, cls: 'safe', color: 'var(--safe)' },
                  { label: 'Suspicious', count: stats?.suspicious_count || 0, cls: 'suspicious', color: 'var(--suspicious)' },
                  { label: 'High Risk', count: stats?.high_risk_count || 0, cls: 'high', color: 'var(--high-risk)' },
                ].map(item => (
                  <div key={item.label} className="risk-dist-row">
                    <div className="risk-dist-label">
                      <span className="risk-dist-dot" style={{ background: item.color }}></span>
                      <span>{item.label}</span>
                    </div>
                    <div className="risk-dist-bar-wrap">
                      <div className="risk-dist-bar">
                        <div className={`risk-bar-fill ${item.cls}`} style={{ width: `${total ? (item.count / total) * 100 : 0}%` }}></div>
                      </div>
                      <span className="risk-dist-count">{item.count}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state-inline"><span className="empty-state-text">No data yet.</span></div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Mailbox</span>
          </div>
          <div className="card-body">
            <div className="mb-mailbox-facts">
              <div className="mb-fact">
                <span className="mb-fact-label">Emails analyzed</span>
                <span className="mb-fact-value">{total}</span>
              </div>
              <div className="mb-fact">
                <span className="mb-fact-label">Gmail</span>
                <span className="mb-fact-value" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-sm)' }}>
                  <span className={`gmail-status-dot ${gmailStatus?.connected ? 'connected' : ''}`}></span>
                  {gmailStatus?.connected ? 'Connected' : 'Not connected'}
                </span>
              </div>
              <div className="mb-fact">
                <span className="mb-fact-label">Last sync</span>
                <span className="mb-fact-value" style={{ fontSize: 'var(--text-sm)' }}>
                  {gmailStatus?.last_sync ? formatRelativeTime(gmailStatus.last_sync) : 'Never'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function PriorityBadge({ level }) {
  if (!level) return <span className="mb-badge prio-pending">PENDING</span>
  const s = priorityStyle(level)
  return <span className={`mb-badge ${s.cls}`}>{s.label}</span>
}

function CategoryBadge({ category }) {
  return <span className="mb-badge mb-badge-category">{categoryLabel(category)}</span>
}

function SecurityBadge({ classification, riskScore }) {
  const cls =
    classification === 'SAFE' ? 'sec-safe' :
    classification === 'SUSPICIOUS' ? 'sec-suspicious' :
    classification === 'HIGH RISK' || classification === 'HIGH_RISK' ? 'sec-high' : 'sec-low'
  const label = (classification || 'SAFE').replace('_', ' ')
  return (
    <span
      className={`mb-badge ${cls}`}
      title={`Security verdict from the detection engine${riskScore != null ? ` (score ${Number(riskScore).toFixed(0)}/100)` : ''}`}
    >
      {label}
    </span>
  )
}

export default Dashboard
