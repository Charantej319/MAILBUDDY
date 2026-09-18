import React, { useState, useEffect } from 'react'
import { api } from '../services/api'

function Analytics() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    loadStats()
  }, [])

  const loadStats = async () => {
    try {
      const data = await api.getStatistics()
      setStats(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="loading-state">
        <div className="spinner"></div>
        <span>Loading analytics...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="alert alert-error">
        <span>{error}</span>
        <button className="btn btn-ghost btn-sm" onClick={loadStats}>Retry</button>
      </div>
    )
  }

  const total = stats?.total_emails || 0
  const high = stats?.high_risk_count || 0
  const suspicious = stats?.suspicious_count || 0
  const low = stats?.low_risk_count || 0
  const safe = stats?.safe_count || 0
  const threats = high + suspicious

  // Calculate aggregate metrics from recent analyses
  const recent = stats?.recent_analyses || []
  const avgScore = total > 0 && recent.length > 0
    ? recent.reduce((sum, e) => sum + e.risk_score, 0) / recent.length
    : 0

  // Rule frequency analysis
  const ruleFrequency = {}
  recent.forEach(email => {
    const findings = email.detection_findings || []
    findings.forEach(f => {
      if (!ruleFrequency[f.rule_id]) {
        ruleFrequency[f.rule_id] = { count: 0, category: f.category, severity: f.severity }
      }
      ruleFrequency[f.rule_id].count++
    })
  })

  const topRules = Object.entries(ruleFrequency)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 10)

  return (
    <div>
      <div className="page-header">
        <div className="page-header-left">
          <h1>Analytics</h1>
          <p>Historical investigation and detection patterns</p>
        </div>
      </div>

      {/* Overview Metrics */}
      <div className="metrics-row">
        <div className="metric-card">
          <div className="metric-label">Total Analyzed</div>
          <div className="metric-value">{total}</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Threats Detected</div>
          <div className="metric-value" style={{ color: threats > 0 ? 'var(--high-risk)' : 'var(--safe)' }}>
            {threats}
          </div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Detection Rate</div>
          <div className="metric-value">{total > 0 ? ((threats / total) * 100).toFixed(0) : 0}%</div>
        </div>
        <div className="metric-card">
          <div className="metric-label">Avg Risk Score</div>
          <div className="metric-value" style={{ color: getScoreColor(avgScore) }}>{avgScore.toFixed(0)}</div>
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
                  { label: 'Safe', count: safe, color: 'var(--safe)', cls: 'safe' },
                  { label: 'Low Risk', count: low, color: 'var(--low-risk)', cls: 'low' },
                  { label: 'Suspicious', count: suspicious, color: 'var(--suspicious)', cls: 'suspicious' },
                  { label: 'High Risk', count: high, color: 'var(--high-risk)', cls: 'high' },
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
              <div className="empty-state" style={{ padding: '48px 0' }}>
                <div className="empty-state-title">Not enough analyzed emails yet</div>
                <div className="empty-state-desc">Analyze more emails to see risk distribution.</div>
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
                {stats.top_sender_domains.map((item, idx) => (
                  <div key={idx} className="domain-row">
                    <span className="domain-name">{item.domain}</span>
                    <span className="domain-count">{item.count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state" style={{ padding: '48px 0' }}>
                <div className="empty-state-title">Not enough data yet</div>
                <div className="empty-state-desc">Analyze more emails to see sender domain distribution.</div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Top Detection Rules */}
      {topRules.length > 0 && (
        <div className="card" style={{ marginTop: 'var(--space-4)' }}>
          <div className="card-header">
            <span className="card-title">Most Frequent Detection Rules</span>
          </div>
          <div className="card-body">
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Rule ID</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th style={{ width: 80 }}>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {topRules.map(([ruleId, info]) => (
                    <tr key={ruleId}>
                      <td className="cell-ellipsis" style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                        {ruleId}
                      </td>
                      <td><span className="finding-category">{info.category}</span></td>
                      <td>
                        <span className={`finding-severity ${info.severity}`}>{info.severity}</span>
                      </td>
                      <td style={{ fontWeight: 600 }}>{info.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Detection Methodology */}
      <div className="card" style={{ marginTop: 'var(--space-4)' }}>
        <div className="card-header">
          <span className="card-title">Detection Methodology</span>
        </div>
        <div className="card-body">
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--space-4)' }}>
            PhishGuard uses evidence-weighted scoring with cross-signal correlation.
            Each category contributes a maximum number of points to the final risk score (0-100).
            Confidence is calculated independently based on available evidence.
          </p>
          <div className="methodology-grid">
            {[
              { label: 'Sender/Domain', weight: '20 pts', desc: 'Lookalike domains, impersonation, homoglyphs' },
              { label: 'URL Analysis', weight: '25 pts', desc: 'IP URLs, shorteners, suspicious TLDs, lookalikes' },
              { label: 'Content', weight: '20 pts', desc: 'Urgency, credential requests, social engineering' },
              { label: 'Authentication', weight: '20 pts', desc: 'SPF, DKIM, DMARC, alignment' },
              { label: 'Attachments', weight: '10 pts', desc: 'Executables, double extensions, MIME mismatches' },
              { label: 'Intelligence', weight: '5 pts', desc: 'Domain intelligence, brand impersonation' },
              { label: 'Correlation', weight: '10 pts', desc: 'Cross-signal combinations' },
            ].map(item => (
              <div key={item.label} className="methodology-item">
                <div className="methodology-label">{item.label}</div>
                <div className="methodology-weight">{item.weight}</div>
                <div className="methodology-desc">{item.desc}</div>
              </div>
            ))}
          </div>
          <div className="classification-legend" style={{ marginTop: 'var(--space-4)' }}>
            <span style={{ color: 'var(--safe)' }}>0-24 Safe</span>
            <span className="legend-sep">·</span>
            <span style={{ color: 'var(--low-risk)' }}>25-49 Low Risk</span>
            <span className="legend-sep">·</span>
            <span style={{ color: 'var(--suspicious)' }}>50-74 Suspicious</span>
            <span className="legend-sep">·</span>
            <span style={{ color: 'var(--high-risk)' }}>75-100 High Risk</span>
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

export default Analytics
