import React, { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import { priorityStyle, categoryLabel, formatDeadline } from '../utils/priority'

/**
 * MailBuddy Assistant — native in-app panel (not a chatbot clone).
 * Read-only: it can look up and summarize mailbox data served by the
 * backend; it cannot send, modify, or delete email (backend enforces this).
 *
 * Two modes:
 * - Global: intent-routed mailbox questions ("Show critical emails").
 * - Email context: opened from an email; the panel sends the email's id and
 *   the backend grounds every answer in that email's stored analysis.
 */

const GLOBAL_SUGGESTIONS = [
  { text: 'What needs my attention?', cls: 'chip-critical' },
  { text: 'Show suspicious emails', cls: 'chip-security' },
  { text: "Summarize today's mail", cls: 'chip-mail' },
  { text: 'Find internship emails', cls: 'chip-job' },
]

const EMAIL_SUGGESTIONS = [
  'Summarize this email',
  'Why was this flagged?',
  'Is this email suspicious?',
  'What should I do?',
  'Are the links suspicious?',
]

const toChip = (s) => (typeof s === 'string' ? { text: s, cls: '' } : s)

export default function AssistantPanel({ open, onClose, emailContext = null, onClearContext, onPrefillDone }) {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [lastQuestion, setLastQuestion] = useState(null)
  const [expanded, setExpanded] = useState(false)
  const listRef = useRef(null)
  const inputRef = useRef(null)
  const navigate = useNavigate()

  const inEmailContext = !!(emailContext && emailContext.id)

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight
  }, [messages, open, busy, error])

  useEffect(() => {
    if (open) {
      setError(null)
      setBusy(false)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [open, emailContext?.id])

  // A question handed over from the email page (e.g. suggestion chip click)
  // is sent automatically once, with the email context attached.
  const prefillSentRef = useRef(false)
  useEffect(() => {
    if (open && emailContext?.prefill && !prefillSentRef.current) {
      prefillSentRef.current = true
      send(emailContext.prefill)
      onPrefillDone?.()
    }
    if (!open) prefillSentRef.current = false
  }, [open, emailContext?.prefill])

  const send = async (question) => {
    const q = (question ?? input).trim()
    if (!q || busy) return
    setInput('')
    setError(null)
    setLastQuestion(q)
    setMessages((m) => [...m, { role: 'user', content: q }])
    setBusy(true)
    try {
      const data = await api.askMailBuddy(q, inEmailContext ? emailContext.id : null)
      setMessages((m) => [...m, { role: 'assistant', content: data.answer, references: data.references || [] }])
    } catch (err) {
      setError(
        err?.status === 409
          ? 'MailBuddy Assistant is disabled in Settings. Enable it to continue.'
          : 'MailBuddy Assistant is temporarily unavailable. Your email and security analysis are still working normally.',
      )
    } finally {
      setBusy(false)
    }
  }

  const retry = () => {
    if (!lastQuestion) return
    setMessages((m) => (m[m.length - 1]?.role === 'user' ? m.slice(0, -1) : m))
    send(lastQuestion)
  }

  const clearChat = async () => {
    setMessages([])
    setError(null)
    setLastQuestion(null)
    try { await api.clearAssistantChat() } catch { /* in-memory history is best-effort */ }
  }

  const openEmail = (ref) => {
    if (ref?.url) {
      onClose()
      navigate(ref.url)
    }
  }

  // switchEmailContext: when the user opens another email from references
  // while in email context, follow it (keeps the assistant useful).

  const suggestions = inEmailContext ? EMAIL_SUGGESTIONS : GLOBAL_SUGGESTIONS
  const showSuggestions = messages.length === 0 && !busy

  // The panel is unobtrusive: it only exists in the DOM while open.
  if (!open) return null

  return (
    <div className={`mb-assistant-panel ${expanded ? 'expanded' : ''}`} role="dialog" aria-label="MailBuddy Assistant">
      <div className="mb-assistant-header">
        <div className="mb-assistant-title">
          <span className="mb-assistant-avatar" aria-hidden="true">
            <svg viewBox="0 0 64 64" width="18" height="18"><rect x="4" y="10" width="56" height="44" rx="8" fill="#2563eb"/><path d="M10 18 L32 36 L54 18" stroke="#fff" strokeWidth="4" fill="none" strokeLinecap="round"/></svg>
          </span>
          <div>
            <div className="mb-assistant-name">MailBuddy Assistant</div>
            <div className="mb-assistant-sub">
              {inEmailContext ? 'Answering about the email you are viewing' : 'Ask me about your inbox'}
            </div>
          </div>
        </div>
        <div className="mb-assistant-header-actions">
          <button
            className="mb-assistant-icon-btn"
            onClick={() => setExpanded((e) => !e)}
            aria-label={expanded ? 'Restore assistant size' : 'Expand assistant'}
            title={expanded ? 'Restore size' : 'Expand'}
          >
            {expanded ? (
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="14" y1="10" x2="21" y2="3"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
            ) : (
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
            )}
          </button>
          <button className="mb-assistant-icon-btn" onClick={clearChat} aria-label="Clear current chat" title="Clear chat">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          </button>
          <button className="mb-assistant-icon-btn" onClick={() => { onClose(); navigate('/settings') }} aria-label="Assistant settings" title="Settings">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
          </button>
          <button className="mb-assistant-close" onClick={onClose} aria-label="Close assistant">×</button>
        </div>
      </div>

      {inEmailContext && (
        <div className="mb-context-chip" title={emailContext.subject || ''}>
          <span className="mb-context-label">This email:</span>
          <span className="mb-context-subject">{emailContext.subject || '(no subject)'}</span>
          {onClearContext && (
            <button className="mb-context-exit" onClick={onClearContext} aria-label="Exit email context">Exit context</button>
          )}
        </div>
      )}

      <div className="mb-assistant-messages" ref={listRef}>
        {showSuggestions && (
          <div className="mb-assistant-empty">
            <p>
              {inEmailContext
                ? 'I can explain this email\'s security analysis, summarize it, and suggest what to do next.'
                : 'I can look up emails, summarize what needs attention, find deadlines, and explain why something was flagged.'}
            </p>
            <div className="mb-assistant-suggested">
              {suggestions.map((raw) => {
                const s = toChip(raw)
                return (
                  <button key={s.text} className={`mb-assistant-chip ${s.cls}`} onClick={() => send(s.text)}>{s.text}</button>
                )
              })}
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
        {busy && (
          <div className="mb-msg mb-msg-assistant">
            <div className="mb-msg-bubble mb-msg-typing">
              <span className="mb-typing-dots" aria-hidden="true"></span>
              MailBuddy is thinking…
            </div>
          </div>
        )}
        {error && (
          <div className="mb-assistant-error">
            <span>{error}</span>
            {lastQuestion && <button className="mb-assistant-chip" onClick={retry}>Try again</button>}
          </div>
        )}
      </div>

      <form className="mb-assistant-input" onSubmit={(e) => { e.preventDefault(); send() }}>
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={inEmailContext ? 'Ask about this email…' : 'Ask MailBuddy…'}
          aria-label="Ask MailBuddy Assistant"
          disabled={busy}
        />
        <button type="submit" className="btn btn-primary btn-sm" disabled={busy || !input.trim()} aria-label="Send">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        </button>
      </form>
      <div className="mb-assistant-footnote">Read-only assistant — MailBuddy never sends or modifies email.</div>
    </div>
  )
}
