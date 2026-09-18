import React, { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import { categoryLabel, priorityStyle, formatDeadline } from '../utils/priority'

/**
 * MailBuddy Assistant — native in-app panel (not a chatbot clone).
 * Read-only: it can look up and summarize mailbox data served by the
 * backend; it cannot send, modify, or delete email (backend enforces this).
 */

const SUGGESTED = [
  'What needs my attention?',
  'Show internship emails',
  'Find urgent emails',
  'Summarize unread emails',
]

export default function AssistantPanel({ open, onClose }) {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const listRef = useRef(null)
  const navigate = useNavigate()

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight
  }, [messages, open])

  if (!open) return null

  const send = async (question) => {
    const q = (question ?? input).trim()
    if (!q || busy) return
    setInput('')
    setError(null)
    setMessages((m) => [...m, { role: 'user', content: q }])
    setBusy(true)
    try {
      const history = messages.slice(-6).map((m) => ({ role: m.role, content: m.content }))
      const data = await api.askMailBuddy(q)
      setMessages((m) => [...m, { role: 'assistant', content: data.answer, references: data.references || [] }])
    } catch (err) {
      setError(err.message || 'The assistant is unavailable right now.')
    } finally {
      setBusy(false)
    }
  }

  const openEmail = (ref) => {
    if (ref?.url) {
      onClose()
      navigate(ref.url)
    }
  }

  return (
    <div className="mb-assistant-panel" role="dialog" aria-label="MailBuddy Assistant">
      <div className="mb-assistant-header">
        <div className="mb-assistant-title">
          <span className="mb-assistant-avatar" aria-hidden="true">
            <svg viewBox="0 0 64 64" width="18" height="18"><rect x="4" y="10" width="56" height="44" rx="8" fill="#2563eb"/><path d="M10 18 L32 36 L54 18" stroke="#fff" strokeWidth="4" fill="none" strokeLinecap="round"/></svg>
          </span>
          <div>
            <div className="mb-assistant-name">MailBuddy Assistant</div>
            <div className="mb-assistant-sub">Ask me about your inbox</div>
          </div>
        </div>
        <button className="mb-assistant-close" onClick={onClose} aria-label="Close assistant">×</button>
      </div>

      <div className="mb-assistant-messages" ref={listRef}>
        {messages.length === 0 && (
          <div className="mb-assistant-empty">
            <p>I can look up emails, summarize what needs attention, find deadlines, and explain why something was flagged.</p>
            <div className="mb-assistant-suggested">
              {SUGGESTED.map((s) => (
                <button key={s} className="mb-assistant-chip" onClick={() => send(s)}>{s}</button>
              ))}
            </div>
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`mb-msg mb-msg-${m.role}`}>
            <div className="mb-msg-bubble">{m.content.split('\n').map((line, j) => <div key={j}>{line}</div>)}</div>
            {m.role === 'assistant' && m.references?.length > 0 && (
              <div className="mb-msg-refs">
                {m.references.map((ref, j) => (
                  <button key={j} className="mb-ref-card" onClick={() => openEmail(ref)} title={`Open: ${ref.subject || ''}`}>
                    <span className="mb-ref-sender">{ref.sender}</span>
                    <span className="mb-ref-subject">{ref.subject || '(no subject)'}</span>
                    <span className="mb-ref-meta">
                      {ref.priority ? priorityStyle(ref.priority).label : 'PENDING'} · {categoryLabel(ref.category)}
                      {ref.deadline ? ` · Deadline: ${formatDeadline(ref.deadline)}` : ''}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}
        {busy && <div className="mb-msg mb-msg-assistant"><div className="mb-msg-bubble mb-msg-typing">Looking through your inbox…</div></div>}
        {error && <div className="mb-assistant-error">{error}</div>}
      </div>

      <form className="mb-assistant-input" onSubmit={(e) => { e.preventDefault(); send() }}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about your inbox…"
          aria-label="Ask MailBuddy Assistant"
          disabled={busy}
        />
        <button type="submit" className="btn btn-primary btn-sm" disabled={busy || !input.trim()}>Ask</button>
      </form>
      <div className="mb-assistant-footnote">Read-only assistant — MailBuddy never sends or modifies email.</div>
    </div>
  )
}
