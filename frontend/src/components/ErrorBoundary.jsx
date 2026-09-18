import React from 'react'
import { Link } from 'react-router-dom'

/**
 * Route-level error boundary.
 *
 * One malformed field or unexpected render error must never produce a
 * completely blank page: the boundary keeps the app shell (sidebar/topbar,
 * which live above this component in App.jsx) and offers the user a way out.
 */
class DetailErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    // Log safely: no tokens, no stack traces exposed to the user.
    console.error('PhishGuard render error (' + (this.props.contextName || 'page') + '):', error?.message)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="threat-analysis-page">
          <div className="breadcrumb">
            <Link to="/emails" className="breadcrumb-link">← Emails</Link>
            <span className="breadcrumb-separator">/</span>
            <span className="breadcrumb-current">Threat Analysis</span>
          </div>
          <div className="alert alert-error" role="alert">
            <div style={{ fontWeight: 700, marginBottom: 4 }}>Unable to display this email</div>
            <div>Something went wrong while rendering the investigation view. The stored security analysis is safe.</div>
          </div>
          <div style={{ marginTop: 'var(--space-4)', display: 'flex', gap: 10 }}>
            <button className="btn btn-secondary" onClick={() => this.setState({ error: null })}>
              Try again
            </button>
            <Link to="/emails" className="btn btn-secondary">Back to Emails</Link>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

export { DetailErrorBoundary }
