import React, { useState, useEffect } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import { formatRelativeTime } from '../utils/time'
import { securityStyle, priorityStyle, categoryLabel } from '../utils/priority'

/**
 * Security — the risk axis on its own page (independent of priority).
 * /security            → summary with Safe / Review / Suspicious / Threat buckets
 * /security?filter=... → filtered list for one bucket
 *
 * Buckets map to the deterministic engine's classification values:
 *   Safe = SAFE + LOW RISK, Review = (none yet — reserved), Suspicious, Threat = HIGH RISK.
 * Colors come exclusively from the --security-* tokens.
 */

const BUCKETS = [
  { key: 'safe', label: 'Safe', cls: 'sec-safe', desc: 'No meaningful risk indicators' },
  { key: 'review', label: 'Review', cls: 'sec-medium', desc: 'Minor indicators worth a look' },
  { key: 'suspicious', label: 'Suspicious', cls: 'sec-suspicious', desc: 'Multiple phishing indicators' },
  { key: 'threat', label: 'Threat', cls: 'sec-high', desc: 'Strong phishing indicators — do not interact' },
]

function bucketFor(classification) {
  const c = String(classification || '').toUpperCase()
  if (c === 'SAFE' || c === 'LOW RISK' || c === 'LOW_RISK') return 'safe'
  if (c === 'SUSPICIOUS') return 'suspicious'
  if (c === 'HIGH RISK' || c === 'HIGH_RISK') return 'threat'
  return 'safe'
}

export default function SecurityPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const filter = searchParams.get('filter')

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    api.getEmails()
      .then((d) => { if (!cancelled) setEmails(d.emails || []) })
      .catch((e) => { if (!cancelled) setError(e.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  const counts = { safe: 0, review: 0, suspicious: 0, threat: 0 }
  emails.forEach((e) => { counts[bucketFor(e.classification)] += 1 })

  const shown = filter
    ? emails.filter((e) => bucketFor(e.classification) === filter)
    : emails.filter((e) => e.classification === 'SUSPICIOUS' || e.classification === 'HIGH RISK' || e.classification === 'HIGH_RISK')

  const activeBucket = BUCKETS.find((b) => b.key === filter)

  return (
    <div>
      <div className="page-header">
        <div className="page-header-left">
          <h1>
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="var(--security-safe)" strokeWidth="1.8" style={{ verticalAlign: '-3px', marginRight: 8 }}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Security
          </h1>
          <p>Risk verdicts from the detection engine — independent of priority</p>
        </div>
      </div>

      <div className="sec-bucket-grid">
        {BUCKETS.map((b) => (
          <button
            key={b.key}
            className={`sec-bucket-card ${b.cls}`}
            aria-pressed={filter === b.key}
            onClick={() => setSearchParams(filter === b.key ? {} : { filter: b.key })}
          >
            <span className="sec-bucket-top">
              <span className={`prio-dot sec-dot-${b.key}`} aria-hidden="true"></span>
              <span className="sec-bucket-label">{b.label}</span>
              <span className="sec-bucket-count">{counts[b.key]}</span>
            </span>
            <span className="sec-bucket-desc">{b.desc}</span>
          </button>
        ))}
      </div>

      <div className="card">
        <div className={`card-header ${activeBucket ? `prio-accent-top sec-top-${activeBucket.key}` : ''}`}>
          <span className="card-title">{activeBucket ? `${activeBucket.label} emails` : 'Emails needing security review'}</span>
          <span className="detail-panel-count">{loading ? 'Loading…' : `${shown.length} shown`}</span>
        </div>
        <div className="card-body" style={{ padding: 0 }}>
          {error && (
            <div className="empty-state-inline"><span className="empty-state-text">{error}</span></div>
          )}
          {!error && !loading && shown.length === 0 && (
            <div className="empty-state-inline"><span className="empty-state-text">No emails in this bucket.</span></div>
          )}
          {!loading && shown.length > 0 && (
            <div className="mb-email-rows">
              {shown.map((email) => {
                const sec = securityStyle(email.classification)
                const prio = priorityStyle(email.priority?.level)
                return (
                  <div key={email.id} className="mb-email-row" onClick={() => navigate(`/emails/${email.id}`)}>
                    <div className="mb-email-row-main">
                      <div className="mb-email-row-sender">{email.sender_email || email.sender}</div>
                      <div className="mb-email-row-subject">{email.subject || '(no subject)'}</div>
                    </div>
                    <div className="mb-email-row-side">
                      <span className={`mb-badge ${prio.cls}`} title="Priority — independent of security">{prio.label}</span>
                      <span className="mb-badge mb-badge-category">{categoryLabel(email.priority?.category)}</span>
                      <span className={`mb-badge ${sec.cls}`}>{sec.label} · {Number(email.risk_score).toFixed(0)}</span>
                      <span className="mb-attention-time">{formatRelativeTime(email.date)}</span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
