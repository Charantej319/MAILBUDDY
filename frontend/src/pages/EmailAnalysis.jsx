import React, { useState, useEffect, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import { api } from '../services/api'
import { formatDateTime } from '../utils/time'
import { priorityStyle, categoryLabel, formatDeadline } from '../utils/priority'
import { sanitizeEmailHtml, defangUrl, containsUnsafeContent } from '../utils/sanitizeHtml'
import { getAuthStatus, authStatusMeta } from '../utils/authStatus'
import { DetailErrorBoundary } from '../components/ErrorBoundary'

/**
 * Email detail / investigation view.
 *
 * Rendering safety:
 * - Body HTML from the backend is sanitized (backend sanitizer + a second
 *   frontend pass). It is injected via dangerouslySetInnerHTML ONLY after
 *   sanitization, and a dev-mode assertion guards against regressions.
 * - URLs are displayed defanged and are never clickable.
 * - The page is additionally protected by a strict CSP (index.html).
 */

function EmailAnalysis({ onAskAssistant }) {
  const { id } = useParams()
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState(null)
  const [aiConfigured, setAiConfigured] = useState(false)
  const requestedRef = useRef(false)
  // Body content state (old Gmail analyses may not have stored bodies)
  const [bodyState, setBodyState] = useState('loading') // loading | ready | fetching | unavailable
  const [bodyUnavailableMsg, setBodyUnavailableMsg] = useState(null)

  useEffect(() => {
    loadAnalysis()
  }, [id])

  const loadAnalysis = async () => {
    try {
      setLoading(true)
      setError(null)
      setBodyUnavailableMsg(null)
      const data = await api.getEmailAnalysis(id)
      setAnalysis(data)
      // Old Gmail analyses may have no stored body — fetch it on demand.
      if (data.body_text || data.body_html || data.source !== 'gmail') {
        setBodyState(data.body_text || data.body_html ? 'ready' : 'unavailable')
      } else {
        setBodyState('fetching')
        fetchBodyContent()
      }
      // Auto-run AI verification once per load if configured and not yet done.
      api.getAIStatus()
        .then((s) => {
          setAiConfigured(!!s.configured)
          if (s.configured && !requestedRef.current && data.ai?.status === 'NOT_REQUESTED') {
            requestedRef.current = true
            runAiVerification(false)
          }
        })
        .catch(() => setAiConfigured(false))
    } catch (err) {
      setError(err.message)
      setBodyState('unavailable')
    } finally {
      setLoading(false)
    }
  }

  const fetchBodyContent = async () => {
    try {
      const result = await api.getGmailMessageContent(id)
      if (result.available) {
        setAnalysis((prev) => prev ? {
          ...prev,
          body_text: result.body_text || prev.body_text,
          body_html: result.body_html || prev.body_html,
        } : prev)
        setBodyState('ready')
      } else {
        setBodyUnavailableMsg(result.message || 'Email content is currently unavailable. The stored security analysis is still available.')
        setBodyState('unavailable')
      }
    } catch (err) {
      setBodyUnavailableMsg(err.message || 'Email content is currently unavailable. The stored security analysis is still available.')
      setBodyState('unavailable')
    }
  }

  const runAiVerification = async (manual = true) => {
    setAiLoading(true)
    setAiError(null)
    try {
      const result = await api.verifyWithAI(id)
      setAnalysis((prev) => prev ? { ...prev, ai: { ...result.ai } } : prev)
    } catch (err) {
      setAiError(err.message)
    } finally {
      setAiLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="loading-state">
        <div className="spinner"></div>
        <span>Loading analysis...</span>
      </div>
    )
  }

  if (error || !analysis) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">{error || 'Unable to load email.'}</div>
        <Link to="/emails" className="btn btn-secondary" style={{ marginTop: 12 }}>Back to Emails</Link>
      </div>
    )
  }

  const findings = analysis.detection_findings || []
  const urls = (analysis.extracted_urls || []).map(url => defangUrl(url))
  const attachments = analysis.attachment_info || []
  const scoreColor = getScoreColor(analysis.risk_score)
  const barClass = getBarClass(analysis.classification)
  // F-21: canonical ('HIGH_RISK') and legacy ('HIGH RISK') both mean threat.
  const isThreat = analysis.classification === 'SUSPICIOUS' || analysis.classification === 'HIGH RISK' || analysis.classification === 'HIGH_RISK'

  const senderFindings = findings.filter(f => f.category === 'SENDER')
  const urlFindings = findings.filter(f => f.category === 'URL')
  const contentFindings = findings.filter(f => f.category === 'CONTENT')
  const headerFindings = findings.filter(f => f.category === 'HEADER')
  const attachmentFindings = findings.filter(f => f.category === 'ATTACHMENT')
  const intelFindings = findings.filter(f => f.category === 'INTEL')
  const correlationFindings = findings.filter(f => f.category === 'CORRELATION')

  const topFindings = analysis.top_findings || getTopFindings(findings)

  const spfStatus = getAuthStatus(findings, 'spf')
  const dkimStatus = getAuthStatus(findings, 'dkim')
  const dmarcStatus = getAuthStatus(findings, 'dmarc')

  // Sanitized email body: HTML part if present (sanitized twice), else plain text.
  const bodyHtmlRaw = analysis.body_html || ''
  const bodyPlain = analysis.body_text || ''
  const hasBody = !!(bodyHtmlRaw || bodyPlain) && bodyState === 'ready'
  const safeBody = bodyHtmlRaw
    ? sanitizeEmailHtml(bodyHtmlRaw)
    : null

  // Dev-mode regression guard: sanitized output must contain no executable markup.
  if (safeBody && containsUnsafeContent(safeBody)) {
    console.error('PhishGuard: sanitized email body still contains unsafe content — sanitizeEmailHtml() regressed')
  }

  const ai = analysis.ai || {}
  const aiUnavailable = ai.status === 'UNAVAILABLE'
  const aiDisagreement = ai.status === 'DISAGREEMENT'
  const aiPending = !ai.status || ai.status === 'NOT_REQUESTED'

  const canAsk = typeof onAskAssistant === 'function'
  const askAbout = (question) => {
    if (canAsk) onAskAssistant({ id: analysis.id, subject: analysis.subject }, question)
  }

  return (
    <div className="threat-analysis-page">
      {/* Breadcrumb */}
      <div className="breadcrumb">
        <Link to="/emails" className="breadcrumb-link">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 14, height: 14 }}>
            <line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>
          </svg>
          Emails
        </Link>
        <span className="breadcrumb-separator">/</span>
        <span className="breadcrumb-current">Threat Analysis</span>
      </div>

      {/* Security Warning */}
      {isThreat && (
        <div className="alert alert-error security-warning" style={{ marginBottom: 'var(--space-4)' }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 20, height: 20, flexShrink: 0, marginTop: 2 }}>
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <div>
              <div style={{ fontWeight: 700, marginBottom: 4 }}>⚠ Security Warning</div>
              <div>This message contains indicators commonly associated with phishing or social engineering.</div>
              {topFindings.length > 0 && (
                <ul style={{ margin: '8px 0 0 18px', padding: 0 }}>
                  {topFindings.slice(0, 3).map((f, i) => (
                    <li key={i} style={{ marginBottom: 2 }}>{f.message}</li>
                  ))}
                </ul>
              )}
              <div style={{ marginTop: 8, fontStyle: 'italic' }}>
                Recommended action: Do not click links or provide credentials until the message is independently verified.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Header Row */}
      <div className="threat-header">
        <div className="threat-header-left">
          <div className="threat-header-badges">
            <span className={`badge badge-lg ${getBadgeClass(analysis.classification)}`}>
              {analysis.classification}
            </span>
            <span className={`confidence-indicator confidence-${getConfidenceClass(analysis.confidence_level)}`}>
              Confidence: {analysis.confidence_level || 'LOW'}
              {analysis.confidence_numeric ? ` (${Math.round(analysis.confidence_numeric * 100)}%)` : ''}
            </span>
          </div>
          <h1 className="threat-subject">{analysis.subject || '(no subject)'}</h1>
        </div>
        <div className="threat-header-right">
          {canAsk && (
            <div className="ask-mailbuddy-btn-wrap">
              <button className="btn btn-secondary btn-sm" onClick={() => askAbout()} disabled={!canAsk}>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: 6 }}><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                Ask MailBuddy about this email
              </button>
            </div>
          )}
          <div className="threat-score-large">
            <div className="threat-score-number" style={{ color: scoreColor }}>
              {analysis.risk_score.toFixed(0)}
            </div>
            <div className="threat-score-meta">
              <span className="threat-score-max">/ 100</span>
              <span className="threat-score-label" style={{ color: scoreColor }}>{analysis.classification}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Score Bar */}
      <div className="threat-score-bar-container">
        <div className="risk-bar" style={{ height: 6 }}>
          <div className={`risk-bar-fill ${barClass}`} style={{ width: `${analysis.risk_score}%` }}></div>
        </div>
      </div>

      {/* Email Information */}
      <div className="summary-card">
        <div className="section-title" style={{ border: 'none', marginBottom: 'var(--space-2)' }}>Email Information</div>
        <div className="detail-grid">
          <div className="detail-row">
            <span className="detail-label">From</span>
            <span className="detail-value">{analysis.sender_email || analysis.sender}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">To</span>
            <span className="detail-value">{analysis.recipient || '-'}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Subject</span>
            <span className="detail-value">{analysis.subject || '(no subject)'}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Date / Time</span>
            <span className="detail-value">{formatDateTime(analysis.date)}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Source</span>
            <span className="detail-value">{analysis.source === 'gmail' ? 'Gmail' : analysis.source === 'eml' ? '.eml Upload' : 'Raw analysis'}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Domain</span>
            <span className="detail-value mono">{analysis.sender_domain}</span>
          </div>
          {analysis.message_id_header && (
            <div className="detail-row">
              <span className="detail-label">Message ID</span>
              <span className="detail-value mono">{analysis.message_id_header}</span>
            </div>
          )}
        </div>
      </div>

      {/* MailBuddy Priority (importance — separate from security) */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">MailBuddy Priority</span>
          <span className="detail-panel-count">Importance — separate from the security verdict</span>
        </div>
        <div className="card-body">
          {analysis.priority?.level ? (
            <div>
              <div className="mb-detail-grid">
                <div>
                  <div className="intel-label">Priority</div>
                  <span className={`mb-badge ${priorityStyle(analysis.priority.level).cls}`} style={{ fontSize: 'var(--text-sm)' }}>
                    {priorityStyle(analysis.priority.level).label}
                  </span>
                </div>
                <div>
                  <div className="intel-label">Category</div>
                  <span className="mb-badge mb-badge-category" style={{ fontSize: 'var(--text-sm)' }}>{categoryLabel(analysis.priority.category)}</span>
                </div>
                {analysis.priority.deadline && (
                  <div>
                    <div className="intel-label">Deadline</div>
                    <span className="intel-value">{formatDeadline(analysis.priority.deadline)}</span>
                  </div>
                )}
              </div>
              {analysis.priority.reasons?.length > 0 && (
                <div style={{ marginTop: 'var(--space-3)' }}>
                  <div className="intel-label">Why?</div>
                  <ul className="mb-reason-list">
                    {analysis.priority.reasons.map((r, i) => <li key={i}>{r}</li>)}
                  </ul>
                </div>
              )}
              {analysis.priority.summary && (
                <p style={{ marginTop: 'var(--space-3)', color: 'var(--text-secondary)' }}>{analysis.priority.summary}</p>
              )}
            </div>
          ) : (
            <div className="empty-state-inline">
              <span className="empty-state-text">Priority analysis pending — the deterministic security analysis below is fully available.</span>
            </div>
          )}
        </div>
      </div>

      {/* Security Analysis Summary */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">Security Analysis</span>
          <span className="detail-panel-count">Deterministic engine</span>
        </div>
        <div className="card-body">
          <div className="intel-grid">
            <div className="intel-item">
              <span className="intel-label">Risk</span>
              <span className={`intel-value ${analysis.classification === 'SAFE' || analysis.classification === 'LOW RISK' ? 'pass' : 'fail'}`}>
                {analysis.classification}
              </span>
            </div>
            <div className="intel-item">
              <span className="intel-label">Score</span>
              <span className="intel-value" style={{ color: scoreColor }}>{analysis.risk_score.toFixed(0)} / 100</span>
            </div>
            <div className="intel-item">
              <span className="intel-label">Confidence</span>
              <span className="intel-value">
                {analysis.confidence_level || 'LOW'}{analysis.confidence_numeric ? ` — ${Math.round(analysis.confidence_numeric * 100)}%` : ''}
              </span>
            </div>
            <div className="intel-item">
              <span className="intel-label">Primary Indicator</span>
              <span className="intel-value">{getPrimaryIndicator(findings)}</span>
            </div>
          </div>
          {analysis.analysis_summary && (
            <p style={{ marginTop: 'var(--space-3)', color: 'var(--text-secondary)' }}>{analysis.analysis_summary}</p>
          )}
        </div>
      </div>

      {/* AI Verification (second opinion) */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">AI Verification</span>
          <span className="detail-panel-count">Optional second opinion — never overrides the rule engine</span>
        </div>
        <div className="card-body">
          {aiDisagreement && (
            <div className="alert alert-error" style={{ marginBottom: 'var(--space-3)' }}>
              <span><strong>Analysis disagreement:</strong> the AI verdict differs from the deterministic engine. Both results are shown below. Strong deterministic indicators are not overridden by the AI.</span>
            </div>
          )}
          {ai.status === 'VERIFIED' && !aiDisagreement && (
            <div className="intel-grid" style={{ marginBottom: 'var(--space-3)' }}>
              <div className="intel-item">
                <span className="intel-label">AI Verdict</span>
                <span className={`intel-value ${ai.verdict === 'SAFE' || ai.verdict === 'LOW_RISK' ? 'pass' : 'fail'}`}>{ai.verdict}</span>
              </div>
              <div className="intel-item">
                <span className="intel-label">AI Confidence</span>
                <span className="intel-value">{Math.round((ai.confidence || 0) * 100)}%</span>
              </div>
              <div className="intel-item">
                <span className="intel-label">Recommended Action</span>
                <span className="intel-value">{ai.recommended_action || '-'}</span>
              </div>
              <div className="intel-item">
                <span className="intel-label">Model</span>
                <span className="intel-value mono">{ai.model || '-'}</span>
              </div>
            </div>
          )}
          {aiDisagreement && (
            <div className="intel-grid" style={{ marginBottom: 'var(--space-3)' }}>
              <div className="intel-item">
                <span className="intel-label">Rule Engine</span>
                <span className="intel-value fail">{analysis.classification} — {analysis.risk_score.toFixed(0)}/100</span>
              </div>
              <div className="intel-item">
                <span className="intel-label">AI Verdict</span>
                <span className={`intel-value ${ai.verdict === 'SAFE' || ai.verdict === 'LOW_RISK' ? 'pass' : 'fail'}`}>{ai.verdict} — {Math.round((ai.confidence || 0) * 100)}%</span>
              </div>
              <div className="intel-item">
                <span className="intel-label">Recommended Action</span>
                <span className="intel-value">{ai.recommended_action || '-'}</span>
              </div>
              <div className="intel-item">
                <span className="intel-label">Model</span>
                <span className="intel-value mono">{ai.model || '-'}</span>
              </div>
            </div>
          )}
          {ai.reasons?.length > 0 && (
            <div style={{ marginBottom: 'var(--space-3)' }}>
              <div className="intel-label" style={{ marginBottom: 4 }}>AI Reasons</div>
              <ul style={{ margin: '0 0 0 18px', padding: 0, color: 'var(--text-secondary)' }}>
                {ai.reasons.map((r, i) => <li key={i} style={{ marginBottom: 2 }}>{r}</li>)}
              </ul>
            </div>
          )}
          {ai.summary && (
            <div style={{ marginBottom: 'var(--space-3)', color: 'var(--text-secondary)' }}>
              <span style={{ fontWeight: 600 }}>AI Summary: </span>{ai.summary}
            </div>
          )}
          {aiUnavailable && (
            <div className="alert alert-warning" style={{ marginBottom: aiError ? 'var(--space-3)' : 0 }}>
              <span>AI verification unavailable{ai.error ? ` — ${ai.error}` : ''}. Deterministic analysis is still available and authoritative.</span>
            </div>
          )}
          {aiPending && !aiLoading && aiConfigured && (
            <button className="btn btn-secondary btn-sm" onClick={() => runAiVerification(true)}>
              Run AI verification
            </button>
          )}
          {aiPending && !aiLoading && !aiConfigured && (
            <div className="empty-state-inline">
              <span className="empty-state-text">
                AI verification not configured (optional). Set AI_PROVIDER=groq and GROQ_API_KEY in the backend environment to enable it. The deterministic analysis above is complete.
              </span>
            </div>
          )}
          {aiLoading && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }}></span>
              <span>Running AI verification…</span>
            </div>
          )}
          {aiError && (
            <div className="alert alert-error" style={{ marginTop: 'var(--space-3)' }}>
              <span>{aiError}</span>
            </div>
          )}
        </div>
      </div>

      {/* Why Flagged (deterministic detection evidence) */}
      {topFindings.length > 0 && (
        <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
          <div className="card-header">
            <span className="card-title">Why Flagged — Detection Evidence</span>
            <span className="detail-panel-count">{topFindings.length} top indicators</span>
          </div>
          <div className="card-body">
            <div className="top-findings-section">
              {topFindings.map((finding, idx) => (
                <div key={idx} className="top-finding-item">
                  <div className={`top-finding-points ${finding.points >= 0 ? 'positive' : 'negative'}`}>
                    {finding.points >= 0 ? '+' : ''}{finding.points}
                  </div>
                  <div className="top-finding-content">
                    <div className="top-finding-title">{finding.message}</div>
                    {finding.explanation && (
                      <div className="top-finding-explanation">{finding.explanation}</div>
                    )}
                    {finding.evidence && (
                      <div className="top-finding-evidence">{finding.evidence}</div>
                    )}
                    <div className="finding-meta" style={{ marginTop: 'var(--space-1)' }}>
                      <span className={`finding-severity ${finding.severity}`}>{finding.severity}</span>
                      <span className="finding-category">{finding.category}</span>
                      <span className="finding-source">{finding.source || 'Local analysis'}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Email Content */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">Email Content</span>
          <span className="detail-panel-count">Sanitized — links are not clickable</span>
        </div>
        <div className="card-body">
          {bodyState === 'fetching' && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }}></span>
              <span>Fetching email content from Gmail…</span>
            </div>
          )}
          {bodyState === 'unavailable' && (
            <div className="empty-state-inline">
              <span className="empty-state-text">
                {bodyUnavailableMsg || 'Email content is currently unavailable. The stored security analysis is still available.'}
              </span>
              {analysis.source === 'gmail' && (
                <button className="btn btn-ghost btn-sm" style={{ marginLeft: 12 }} onClick={fetchBodyContent}>
                  Retry
                </button>
              )}
            </div>
          )}
          {hasBody && bodyHtmlRaw && (
            <div className="email-body-view email-body-html"
                 dangerouslySetInnerHTML={{ __html: safeBody }} />
          )}
          {hasBody && !bodyHtmlRaw && (
            <pre className="email-body-view email-body-text" style={{ whiteSpace: 'pre-wrap', fontFamily: 'inherit', margin: 0 }}>
              {bodyPlain}
            </pre>
          )}
        </div>
      </div>

      {/* Sender & Domain Intelligence */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">Sender & Domain Intelligence</span>
          <span className="detail-panel-count">{senderFindings.length + intelFindings.length} findings</span>
        </div>
        <div className="card-body">
          <div className="intel-grid">
            <div className="intel-item">
              <span className="intel-label">Sender</span>
              <span className="intel-value" style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{analysis.sender_email || analysis.sender}</span>
            </div>
            <div className="intel-item">
              <span className="intel-label">Domain</span>
              <span className="intel-value" style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{analysis.sender_domain}</span>
            </div>
          </div>
          {(senderFindings.length > 0 || intelFindings.length > 0) ? (
            <div style={{ marginTop: 'var(--space-3)' }}>
              {[...senderFindings, ...intelFindings].map((f, i) => (
                <FindingItem key={i} finding={f} />
              ))}
            </div>
          ) : (
            <div className="empty-state-inline" style={{ marginTop: 'var(--space-3)' }}>
              <span className="empty-state-text">No sender or domain findings.</span>
            </div>
          )}
        </div>
      </div>

      {/* URL Intelligence */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">URL Intelligence</span>
          <span className="detail-panel-count">{urls.length} URL(s), {urlFindings.length} findings</span>
        </div>
        <div className="card-body">
          {urls.length > 0 && (
            <div className="url-list" style={{ marginBottom: 'var(--space-3)' }}>
              {urls.map((url, i) => (
                // URLs are rendered as defanged plain text, never as clickable <a>.
                <div key={i} className="url-item url-item-defanged" title="Defanged — not clickable">{url}</div>
              ))}
            </div>
          )}
          {urlFindings.map((f, i) => (
            <FindingItem key={i} finding={f} />
          ))}
          {urls.length === 0 && urlFindings.length === 0 && (
            <div className="empty-state-inline">
              <span className="empty-state-text">No URLs found in this email.</span>
            </div>
          )}
        </div>
      </div>

      {/* Email Authentication */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">Email Authentication</span>
          <span className="detail-panel-count">{headerFindings.length} findings</span>
        </div>
        <div className="card-body">
          <div className="intel-grid" style={{ marginBottom: 'var(--space-3)' }}>
            {/* F-24: distinct verdict states — softfail is NOT a hard failure */}
            <div className="intel-item">
              <span className="intel-label">SPF</span>
              <span className={`intel-value ${authStatusMeta(spfStatus).cls}`}>{authStatusMeta(spfStatus).label}</span>
            </div>
            <div className="intel-item">
              <span className="intel-label">DKIM</span>
              <span className={`intel-value ${authStatusMeta(dkimStatus).cls}`}>{authStatusMeta(dkimStatus).label}</span>
            </div>
            <div className="intel-item">
              <span className="intel-label">DMARC</span>
              <span className={`intel-value ${authStatusMeta(dmarcStatus).cls}`}>{authStatusMeta(dmarcStatus).label}</span>
            </div>
          </div>
          {headerFindings.map((f, i) => (
            <FindingItem key={i} finding={f} />
          ))}
          {headerFindings.length === 0 && (
            <div className="empty-state-inline">
              <span className="empty-state-text">No authentication findings (headers may not have been captured for this email).</span>
            </div>
          )}
        </div>
      </div>

      {/* Content Analysis */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">Content Analysis</span>
          <span className="detail-panel-count">{contentFindings.length} findings</span>
        </div>
        <div className="card-body">
          {contentFindings.map((f, i) => (
            <FindingItem key={i} finding={f} />
          ))}
          {contentFindings.length === 0 && (
            <div className="empty-state-inline">
              <span className="empty-state-text">No content-based findings.</span>
            </div>
          )}
        </div>
      </div>

      {/* Attachments */}
      <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">Attachments</span>
          <span className="detail-panel-count">{attachments.length} attachment(s), {attachmentFindings.length} findings</span>
        </div>
        <div className="card-body">
          {attachments.length > 0 && (
            <div className="attachment-list" style={{ marginBottom: 'var(--space-3)' }}>
              {attachments.map((att, i) => (
                <div key={i} className="attachment-item">
                  <div className="attachment-name">{att.filename}</div>
                  <div className="attachment-meta">{att.content_type} · {formatSize(att.size)}</div>
                </div>
              ))}
            </div>
          )}
          {attachmentFindings.map((f, i) => (
            <FindingItem key={i} finding={f} />
          ))}
          {attachments.length === 0 && attachmentFindings.length === 0 && (
            <div className="empty-state-inline">
              <span className="empty-state-text">No attachments found.</span>
            </div>
          )}
        </div>
      </div>

      {/* Correlation Findings */}
      {correlationFindings.length > 0 && (
        <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
          <div className="card-header">
            <span className="card-title">Cross-Signal Correlation</span>
            <span className="detail-panel-count">{correlationFindings.length} finding(s)</span>
          </div>
          <div className="card-body">
            {correlationFindings.map((f, i) => (
              <FindingItem key={i} finding={f} />
            ))}
          </div>
        </div>
      )}

      {/* Recommended Actions */}
      {analysis.recommended_actions?.length > 0 && (
        <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
          <div className="card-header">
            <span className="card-title">Recommended Actions</span>
          </div>
          <div className="card-body">
            <ul className="action-list">
              {analysis.recommended_actions.map((action, idx) => (
                <li key={idx} className="action-item">
                  <span className="action-icon">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                  </span>
                  {action}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}

function FindingItem({ finding }) {
  return (
    <div className="finding-item">
      <span className={`finding-severity ${finding.severity}`}>{finding.severity}</span>
      <div className="finding-content">
        <div className="finding-message">{finding.message}</div>
        <div className="finding-meta">
          <span className="finding-category">{finding.category}</span>
          <span className="finding-points">{finding.points >= 0 ? '+' : ''}{finding.points} pts</span>
          <span className="finding-rule">{finding.rule_id}</span>
          {finding.source && <span style={{ fontStyle: 'italic' }}>{finding.source}</span>}
        </div>
        {finding.explanation && (
          <div className="finding-explanation">{finding.explanation}</div>
        )}
        {finding.evidence && (
          <div className="finding-evidence">{finding.evidence}</div>
        )}
      </div>
    </div>
  )
}

function getTopFindings(findings) {
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
  const sorted = [...findings].sort((a, b) => {
    const sevA = severityOrder[a.severity] ?? 4
    const sevB = severityOrder[b.severity] ?? 4
    if (sevA !== sevB) return sevA - sevB
    return Math.abs(b.points) - Math.abs(a.points)
  })
  return sorted.slice(0, 5)
}

// getAuthStatus moved to src/utils/authStatus.js (F-24) so the SPF/DKIM/DMARC
// verdict derivation is unit-testable and softfail is no longer conflated with
// hard failure.

function getPrimaryIndicator(findings) {
  if (!findings || findings.length === 0) return 'None'
  const high = findings.find(f => f.severity === 'HIGH' || f.severity === 'CRITICAL')
  if (high) return `${high.category}: ${high.message}`
  const med = findings.find(f => f.severity === 'MEDIUM')
  if (med) return `${med.category}: ${med.message}`
  return `${findings[0].category}: ${findings[0].message}`
}

function getScoreColor(score) {
  if (score < 25) return 'var(--safe)'
  if (score < 50) return 'var(--low-risk)'
  if (score < 75) return 'var(--suspicious)'
  return 'var(--high-risk)'
}

function getBarClass(classification) {
  if (classification === 'SAFE') return 'safe'
  // F-21: canonical underscore form recognized alongside the spaced form.
  if (classification === 'LOW RISK' || classification === 'LOW_RISK') return 'low'
  if (classification === 'SUSPICIOUS') return 'suspicious'
  return 'high'
}

function getBadgeClass(classification) {
  if (classification === 'SAFE') return 'badge-safe'
  if (classification === 'LOW RISK') return 'badge-low'
  if (classification === 'SUSPICIOUS') return 'badge-suspicious'
  return 'badge-high'
}

function getConfidenceClass(level) {
  if (!level) return 'low'
  const l = level.toLowerCase()
  if (l.includes('very high')) return 'very-high'
  if (l.includes('high')) return 'high'
  if (l.includes('medium')) return 'medium'
  return 'low'
}

function stripHtmlToText(html) {
  if (!html) return ''
  return String(html)
    .replace(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi, '')
    .replace(/<style\b[^>]*>([\s\S]*?)<\/style\s*>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

export default function EmailAnalysisWithBoundary(props) {
  return (
    <DetailErrorBoundary contextName="email investigation">
      <EmailAnalysis {...props} />
    </DetailErrorBoundary>
  )
}

