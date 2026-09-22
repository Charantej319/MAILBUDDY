import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import { formatRelativeTime } from '../utils/time'
import { LEVEL_META, securityStyle, categoryLabel, formatDeadline, PRIORITY_LEVELS } from '../utils/priority'

/**
 * Priority — page-per-level navigation target for the colored sidebar section.
 * /priority        → overview of all levels (compact)
 * /priority/:level → colored page header + filtered list for that level
 *
 * Data comes from the existing mailbuddy priority endpoints; this page is
 * presentation + navigation only.
 */

function PriorityEmailRows({ emails, onOpen }) {
  if (!emails) {
    return <div className="empty-state-inline"><span className="empty-state-text">Loading…</span></div>
  }
  if (emails.length === 0) {
    return <div className="empty-state-inline"><span className="empty-state-text">No emails at this priority level.</span></div>
  }
  return (
    <div className="mb-email-rows">
      {emails.map((email) => {
        const sec = securityStyle(email.security)
        return (
          <div key={email.id} className="mb-email-row" onClick={() => onOpen(email)}>
            <div className="mb-email-row-main">
              <div className="mb-email-row-sender">{email.sender || email.sender_email}</div>
              <div className="mb-email-row-subject">{email.subject || '(no subject)'}</div>
              {email.deadline && <div className="mb-deadline" style={{ fontSize: 'var(--text-xs)' }}>Deadline: {formatDeadline(email.deadline)}</div>}
            </div>
            <div className="mb-email-row-side">
              <span className="mb-badge mb-badge-category">{categoryLabel(email.category)}</span>
              <span className={`mb-badge ${sec.cls}`} title="Security verdict — independent of priority">{sec.label}</span>
              <span className="mb-attention-time">{formatRelativeTime(email.date)}</span>
            </div>
          </div>
        )
      })}
    </div>
  )
}

export default function PriorityPage() {
  const { level } = useParams()
  const navigate = useNavigate()
  const [summary, setSummary] = useState(null)
  const [emails, setEmails] = useState(null)
  const [loading, setLoading] = useState(true)

  const up = (level || '').toUpperCase()
  const valid = PRIORITY_LEVELS.includes(up)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api.getPrioritySummary().then((s) => { if (!cancelled) setSummary(s) }).catch(() => setSummary(null))
    if (valid) {
      api.getPriorityEmails(up).then((d) => { if (!cancelled) setEmails(d.emails || []) }).catch(() => setEmails([]))
    } else {
      setEmails(null)
    }
    setLoading(false)
    return () => { cancelled = true }
  }, [up, valid])

  const counts = summary?.counts || {}
  const attention = summary?.attention || []

  // Level page
  if (valid) {
    const meta = LEVEL_META[up]
    const count = counts[up] ?? 0
    return (
      <div>
        <div className={`page-header prio-page-header ${meta.icon}`}>
          <div className="page-header-left">
            <h1>
              <span className={`prio-dot ${meta.dot}`} aria-hidden="true"></span>
              {meta.label}
            </h1>
            <p>{count} {meta.plural}</p>
          </div>
          <span className={`prio-level-chip ${meta.cls}`}>{up}</span>
        </div>

        <div className="card">
          <div className={`card-header prio-accent-top ${meta.icon}`}>
            <span className="card-title">Filtered emails</span>
            <span className="detail-panel-count">Security verdicts shown separately — priority ≠ security</span>
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            <PriorityEmailRows emails={emails} onOpen={(e) => navigate(`/emails/${e.id}`)} />
          </div>
        </div>
      </div>
    )
  }

  // Overview page
  return (
    <div>
      <div className="page-header">
        <div className="page-header-left">
          <h1>Priority</h1>
          <p>What matters now — importance is independent of the security verdict</p>
        </div>
      </div>

      <div className="prio-overview-grid">
        {PRIORITY_LEVELS.map((lvl) => {
          const meta = LEVEL_META[lvl]
          return (
            <button
              key={lvl}
              className={`prio-overview-card ${meta.icon}`}
              onClick={() => navigate(`/priority/${lvl}`)}
            >
              <span className={`prio-dot ${meta.dot}`} aria-hidden="true"></span>
              <span className="prio-overview-label">{meta.label}</span>
              <span className="prio-overview-count">{counts[lvl] ?? 0}</span>
            </button>
          )
        })}
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">Attention required</span>
          {summary?.pending > 0 && (
            <span className="mb-pending-note">{summary.pending} awaiting deeper analysis</span>
          )}
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {attention.length > 0 ? (
            <div className="mb-attention-list">
              {attention.map((email) => {
                const meta = LEVEL_META[email.priority] || {}
                const sec = securityStyle(email.security)
                return (
                  <div key={email.id} className="mb-attention-item" onClick={() => navigate(`/emails/${email.id}`)}>
                    <div className="mb-attention-main">
                      <div className="mb-attention-sender">{email.sender || email.sender_email}</div>
                      <div className="mb-attention-subject">{email.subject || '(no subject)'}</div>
                      {email.reasons?.length > 0 && <div className="mb-attention-reason">{email.reasons[0]}</div>}
                    </div>
                    <div className="mb-attention-meta">
                      <div className="mb-attention-badges">
                        <span className={`mb-badge ${meta.cls || 'prio-pending'}`}>{meta.label || 'PENDING'}</span>
                        <span className="mb-badge mb-badge-category">{categoryLabel(email.category)}</span>
                        <span className={`mb-badge ${sec.cls}`}>{sec.label}</span>
                      </div>
                      <div className="mb-attention-extras">
                        {email.deadline && <span className="mb-deadline">Deadline: {formatDeadline(email.deadline)}</span>}
                        <span>{formatRelativeTime(email.date)}</span>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="empty-state-inline">
              <span className="empty-state-text">Nothing urgent right now.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
