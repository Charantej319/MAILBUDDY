import React, { useState, useEffect, useRef } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../services/api'
import { formatDateTime } from '../utils/time'

function EmailList({ gmailStatus }) {
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [syncing, setSyncing] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadResult, setUploadResult] = useState(null)
  const [showUpload, setShowUpload] = useState(false)
  const [dragging, setDragging] = useState(false)
  const fileInputRef = useRef(null)
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  useEffect(() => {
    if (searchParams.get('upload') === 'true') {
      setShowUpload(true)
    }
    loadEmails()
  }, [])

  const loadEmails = async () => {
    try {
      setLoading(true)
      const data = await api.getEmails()
      setEmails(data.emails || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleSync = async () => {
    setSyncing(true)
    setError(null)
    try {
      await api.syncGmail(50)
      await loadEmails()
    } catch (err) {
      setError(err.message)
    } finally {
      setSyncing(false)
    }
  }

  const handleFileDrop = async (file) => {
    if (!file || !file.name.endsWith('.eml')) {
      setError('Please upload a .eml file')
      return
    }
    setUploading(true)
    setUploadResult(null)
    setError(null)
    try {
      const result = await api.analyzeEml(file)
      setUploadResult(result)
      await loadEmails()
    } catch (err) {
      setError(err.message)
    } finally {
      setUploading(false)
    }
  }

  const handleFileSelect = (e) => {
    const file = e.target.files[0]
    if (file) handleFileDrop(file)
  }

  const handleDragOver = (e) => { e.preventDefault(); setDragging(true) }
  const handleDragLeave = () => setDragging(false)
  const handleDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    if (e.dataTransfer.files[0]) handleFileDrop(e.dataTransfer.files[0])
  }

  const filteredEmails = emails.filter(email => {
    if (filter === 'threats') {
      if (email.classification !== 'HIGH RISK' && email.classification !== 'SUSPICIOUS') return false
    } else if (filter !== 'all') {
      const map = { safe: 'SAFE', low: 'LOW RISK', suspicious: 'SUSPICIOUS', high: 'HIGH RISK' }
      if (email.classification !== map[filter]) return false
    }
    if (search) {
      const q = search.toLowerCase()
      return (
        (email.sender || '').toLowerCase().includes(q) ||
        (email.sender_email || '').toLowerCase().includes(q) ||
        (email.subject || '').toLowerCase().includes(q) ||
        (email.sender_domain || '').toLowerCase().includes(q)
      )
    }
    return true
  })

  const filterCounts = {
    all: emails.length,
    threats: emails.filter(e => e.classification === 'HIGH RISK' || e.classification === 'SUSPICIOUS').length,
    high: emails.filter(e => e.classification === 'HIGH RISK').length,
    suspicious: emails.filter(e => e.classification === 'SUSPICIOUS').length,
    low: emails.filter(e => e.classification === 'LOW RISK').length,
    safe: emails.filter(e => e.classification === 'SAFE').length,
  }

  return (
    <div>
      {/* Page Header */}
      <div className="page-header">
        <div className="page-header-left">
          <h1>Emails</h1>
          <p>{emails.length} emails analyzed</p>
        </div>
        <div className="page-header-actions">
          {gmailStatus?.connected && (
            <button className="btn btn-primary" onClick={handleSync} disabled={syncing}>
              {syncing ? (
                <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }}></span> Syncing...</>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 14, height: 14 }}>
                    <polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/>
                    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                  </svg>
                  Sync Gmail
                </>
              )}
            </button>
          )}
          {!gmailStatus?.connected && (
            <button className="btn btn-secondary" onClick={() => navigate('/settings')}>
              Connect Gmail
            </button>
          )}
          <button className="btn btn-secondary" onClick={() => setShowUpload(!showUpload)}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 14, height: 14 }}>
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            Analyze .eml
          </button>
        </div>
      </div>

      {/* Upload Panel */}
      {showUpload && (
        <div className="card" style={{ marginBottom: 'var(--space-4)' }}>
          <div className="card-header">
            <span className="card-title">Upload Email File</span>
            <button className="btn btn-ghost btn-sm" onClick={() => { setShowUpload(false); setUploadResult(null) }}>Close</button>
          </div>
          <div className="card-body">
            <div
              className={`upload-zone ${dragging ? 'dragging' : ''}`}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input ref={fileInputRef} type="file" accept=".eml" onChange={handleFileSelect} style={{ display: 'none' }} />
              <div className="upload-zone-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ width: 32, height: 32 }}>
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" />
                </svg>
              </div>
              <div className="upload-zone-text">
                {uploading ? 'Analyzing email...' : 'Drag & drop an .eml file, or click to browse'}
              </div>
              <div className="upload-zone-hint">Supports .eml format, max 10MB</div>
            </div>

            {uploadResult && (
              <div className="alert alert-success" style={{ marginTop: 'var(--space-3)' }}>
                <span>Analysis complete.</span>
                <button className="btn btn-ghost btn-sm" onClick={() => navigate(`/emails/${uploadResult.id}`)}>View details</button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="alert alert-error" style={{ marginBottom: 'var(--space-4)' }}>
          <span>{error}</span>
          <button className="btn btn-ghost btn-sm" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      {/* Filters and Search */}
      <div className="email-toolbar">
        <div className="filter-tabs">
          {[
            { key: 'all', label: 'All' },
            { key: 'threats', label: 'Threats' },
            { key: 'high', label: 'High Risk' },
            { key: 'suspicious', label: 'Suspicious' },
            { key: 'low', label: 'Low Risk' },
            { key: 'safe', label: 'Safe' },
          ].map(f => (
            <button
              key={f.key}
              className={`filter-tab ${filter === f.key ? 'active' : ''}`}
              onClick={() => setFilter(f.key)}
            >
              {f.label}
              <span className="filter-count">{filterCounts[f.key]}</span>
            </button>
          ))}
        </div>
        <div className="toolbar-search">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="search-icon">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input
            type="text"
            className="input search-input"
            placeholder="Search emails..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="loading-state">
          <div className="spinner"></div>
          <span>Loading emails...</span>
        </div>
      ) : filteredEmails.length > 0 ? (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 60 }}>Risk</th>
                  <th>Sender</th>
                  <th>Subject</th>
                  <th style={{ width: 50 }}>Score</th>
                  <th style={{ width: 80 }}>Confidence</th>
                  <th style={{ width: 120 }}>Primary Indicator</th>
                  <th style={{ width: 100 }}>Date</th>
                  <th style={{ width: 60 }}>Source</th>
                </tr>
              </thead>
              <tbody>
                {filteredEmails.map(email => (
                  <tr key={email.id} onClick={() => navigate(`/emails/${email.id}`)}>
                    <td>
                      <span className={`badge ${getBadgeClass(email.classification)}`}>
                        {getShortClassification(email.classification)}
                      </span>
                    </td>
                    <td className="cell-ellipsis">
                      {email.sender_email || email.sender}
                    </td>
                    <td className="cell-ellipsis cell-secondary">
                      {email.subject || '(no subject)'}
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, color: getScoreColor(email.risk_score) }}>
                        {email.risk_score.toFixed(0)}
                      </span>
                    </td>
                    <td>
                      <span className={`confidence-indicator confidence-${getConfidenceClass(email.confidence_level)}`}>
                        {getShortConfidence(email.confidence_level)}
                      </span>
                    </td>
                    <td className="cell-ellipsis cell-xs">
                      {getPrimaryIndicator(email)}
                    </td>
                    <td className="cell-muted">
                      {formatDateTime(email.date)}
                    </td>
                    <td>
                      <span className="badge badge-source">{email.source === 'gmail' ? 'Gmail' : '.eml'}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ width: 40, height: 40 }}>
                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>
              </svg>
            </div>
            <div className="empty-state-title">
              {emails.length === 0 ? 'No emails analyzed yet' : 'No emails match the filter'}
            </div>
            <div className="empty-state-desc">
              {emails.length === 0
                ? 'Upload an .eml file or connect Gmail to get started.'
                : 'Try a different filter or search term.'}
            </div>
            {emails.length === 0 && (
              <button className="btn btn-primary" onClick={() => setShowUpload(true)}>Upload .eml File</button>
            )}
          </div>
        </div>
      )}
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

function getConfidenceClass(level) {
  if (!level) return 'low'
  const l = level.toLowerCase()
  if (l.includes('very high') || l.includes('very')) return 'very-high'
  if (l.includes('high')) return 'high'
  if (l.includes('medium')) return 'medium'
  return 'low'
}

function getShortConfidence(level) {
  if (!level) return 'LOW'
  if (level.length > 12) return level.substring(0, 12)
  return level
}

function getPrimaryIndicator(email) {
  const findings = email.detection_findings
  if (!findings || findings.length === 0) return '-'
  const high = findings.find(f => f.severity === 'HIGH' || f.severity === 'CRITICAL')
  if (high) return high.category
  const med = findings.find(f => f.severity === 'MEDIUM')
  if (med) return med.category
  return findings[0].category || '-'
}

export default EmailList
