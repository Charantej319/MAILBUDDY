# MailBuddy AI Assistant — Feature Report

**Date:** 2026-09-21 · Status: **implemented, tested, packaged, verified**

## What was built

The existing assistant foundation (intent-routed retrieval, Groq phrasing with reference validation, deterministic fallback, read-only enforcement) was **reused and extended** — no second AI provider, no Ollama, Groq key stays backend-side.

### Backend (`backend/app/mailbuddy/assistant.py`, `routes.py`)
- **Email-context chat**: `POST /api/mailbuddy/assistant/chat` now accepts `email_id`. The backend loads the email itself (by analysis id or Gmail message id) and grounds the answer in that email's stored analysis — sender, subject, priority + reasons, security classification, top findings, URLs, attachments, recommended actions, AI second opinion, and a bounded fenced body excerpt. The client never submits email content (spec §4, §11).
- New `EMAIL_SYSTEM_PROMPT`: explains the existing analysis without overruling it; no guarantees of safety/malice; email content is untrusted data; read-only enforced (spec §18, §19).
- **Grounded deterministic fallback** answers about the current email when Groq is unavailable (flagged-why / links / what-to-do / summary patterns) — the assistant never becomes unusable (spec §21).
- New retrieval intents: `today` (last-24h summary, priority-sorted) and `how many critical/high` counting (spec §6).
- `POST /api/mailbuddy/assistant/clear` — clears in-memory chat (spec §24).
- History is appended in both modes, so email-context and global questions share conversation memory.

### Frontend
- **Sidebar** "Ask MailBuddy" button at the bottom of navigation (spec §2); top-bar Assistant button opens global mode.
- **Right-side persistent panel** (not a floating box, not full-screen): expands on demand, full-width below 640px, always closable (spec §3, §23).
- **Email page** gained an "Ask MailBuddy about this email" button; the panel opens with a context chip ("This email: …" + Exit context) and email-specific suggestions: Summarize this / Why was this flagged? / Is this suspicious? / What should I do? / Are the links suspicious? (spec §5, §15).
- Global suggestions: attention / critical / suspicious / today's summary / internship / job (spec §15).
- Clickable reference cards navigate to `/emails/:id` (spec §16).
- Loading state "MailBuddy is thinking…" with subtle typing dots; duplicate submits disabled (spec §22).
- Error banner with the spec's wording + **Try again** (spec §21).
- Clear-chat button in the panel header and in Settings; Settings shows Assistant/AI status and a privacy note; no provider names or keys anywhere in the UI (spec §14, §24).
- Styling follows the existing MailBuddy design tokens: white surfaces, subtle borders, minimal shadows/radius, no neon (spec §25).

### Fixes required to wire the feature
- `EmailAnalysisWithBoundary` (the error-boundary default export) did not forward props, so the new `onAskAssistant` prop never reached the page component — now forwards `{...props}`.

## Test results

- **Backend:** 212/212 pytest pass, including 7 new tests: email retrieval by both id forms, grounded email-context answer (asserts the real finding text appears), unknown-email honesty, content fencing + no secrets in the prompt block, deterministic fallback with Groq unconfigured, clear-history, and route registration.
- **Dev mode:** real-Groq round-trips verified — global attention question, email-context summarize and safety explanation, honest empty state ("no emails provided"), clear endpoint.
- **Packaged app (installed `MailBuddy-Setup-1.0.0.exe`, backend 14:28):**
  - Gmail OAuth session survived reinstall; `connected=true` without re-auth (OAuth untouched — spec §27).
  - Sidebar button, panel, suggestions, global chat round-trip (grounded answer + 3 clickable refs) — all PASS in the real UI.
  - Email page button → context chip with the correct subject → "Why was this flagged?" → grounded explanation referencing the actual detection evidence — PASS.
  - Notifications regression: a new CRITICAL email was queued and delivered (`delivered=1`) through the unchanged pipeline — PASS.

## Build notes
- `packaging/build_installer.ps1` **reuses** an existing PyInstaller bundle; after backend changes it must be deleted (`packaging/dist`, `packaging/build`) to force a rebuild. This bit once and was caught by the packaged-app verification.
- One electron-builder run failed with `spawn UNKNOWN` in the NSIS uninstaller step; an immediate identical retry succeeded (environment flake, likely AV scanning fresh exes).
- A silent (`/S`) reinstall while MailBuddy was running briefly removed/rewrote app files; closing the app before reinstalling avoids this.

## Boundary compliance
Read-only everywhere: no send/reply/forward/delete/move/label code paths exist in the assistant module (guarded by an existing test that asserts no `{verb}_email` functions); retrieval is bounded (≤8 candidates, ≤6 findings, fenced snippets); the whole mailbox is never sent; no secrets reach the model or frontend (existing + new tests assert this).
