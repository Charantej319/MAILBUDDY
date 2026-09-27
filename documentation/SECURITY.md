# PhishGuard / MailBuddy Security Documentation

## Overview

PhishGuard (desktop product name: **MailBuddy**) is designed as a **defensive security analysis tool**. This document explains the security measures, design decisions, and limitations **as they actually exist in the current implementation**. Every claim here corresponds to code in the repository.

## OAuth Security

### Implementation
- Google OAuth 2.0 is used for Gmail API access (`backend/app/auth/google.py`)
- Only the `gmail.readonly` scope is requested (least privilege; see `GOOGLE_SCOPES` in `backend/app/config.py`)
- Tokens are handled server-side during the OAuth flow and are **never returned to the frontend**
- The application **never** asks for or stores Gmail passwords
- The OAuth `state` parameter is a server-side, single-use, 10-minute TTL value (CSRF protection)
- The post-OAuth redirect target is built only from a **configured origin allowlist** (`GOOGLE_REDIRECT_URI` / `LOCAL_APP_ORIGIN`). Request headers (`Host`, `X-Forwarded-Proto`) are matched against that allowlist and can never steer the redirect to a foreign origin (see `_callback_origin()` and `tests/test_oauth_callback.py`)

### Token Protection (encryption at rest)
- Gmail OAuth tokens are stored **encrypted at rest** in the local SQLite database via the canonical `TokenStorage` layer (`backend/app/auth/token_storage.py`)
- Wire format: `phishguard.v1:<base64url(ciphertext)>`
- **Windows (the desktop target):** native DPAPI (`CryptProtectData`/`CryptUnprotectData`) with additional entropy — ciphertext decrypts only for the same Windows user on the same machine
- **Other platforms (dev/CI):** Fernet (AES-CBC + HMAC) under a key persisted `0600` in the data directory
- Legacy plaintext rows are migrated to encrypted storage at startup (`TokenStorage.migrate`)
- Decryption failures **fail closed** with `TokenDecryptionError` (a corrupt token is never silently treated as an empty string; the UI asks the user to reconnect)
- Plaintext tokens never appear in logs, URLs, API responses, or the frontend
- The local API surface uses a separate bearer token: only its SHA-256 **digest** is stored in the database; the plaintext lives in process memory plus a `0600` bootstrap file (`api.token`) for the Electron shell

### Scope Limitations
The application requests only this scope:
- `https://www.googleapis.com/auth/gmail.readonly` - Read emails only

The application **cannot**:
- Send emails
- Delete emails
- Modify email labels
- Access other Google services

Disconnecting an account revokes the Google grant via Google's revoke endpoint (best-effort) and always removes the local token row.

## Account Isolation (multiple Gmail accounts)

The app supports multiple Gmail accounts per desktop profile:

- Every stored email analysis is stamped with the authenticated account that produced it (`EmailAnalysis.owner_account`), taken **only** from the server-side OAuth session — never from client input
- All read paths (list, detail, statistics, priority, assistant, notifications) are scoped through one shared filter (`backend/app/auth/account_context.py`) so callers only ever see their own rows
- Account A cannot retrieve Account B's emails, statistics, assistant context, or acknowledge Account B's notifications
- Legacy rows created before isolation (NULL owner) are visible only inside the same single-user desktop data directory

## API Security (local surface)

- Every `/api` route requires the local bearer token (`Authorization: Bearer …`); routes are registered behind a guarded router so a newly added endpoint cannot accidentally bypass authentication
- A `Host` allowlist middleware rejects requests with unexpected Host values (fail closed, 403)
- An origin/cookie middleware enforces same-origin behavior for cookie-bearing requests
- `/api/health` is the only unauthenticated API endpoint
- The backend binds to the loopback interface only (localhost, port 8000)

## Privacy Considerations

### Data Collection
- Email metadata is stored in the local SQLite database (sender, subject, date, risk score, findings, extracted URLs, attachment metadata)
- Email **bodies are stored locally** for display/investigation: `body_text` truncated to 50,000 characters and `body_html` to 100,000 characters
- List-style API responses (inbox, dashboard, priority, security pages) use a summary serializer that **excludes** body content by construction; only the authorized detail endpoint returns body content for investigation
- Gmail OAuth tokens are stored encrypted (see above), never in plaintext
- Users can delete analysis results at any time (`DELETE /api/emails/{id}`)
- No user tracking or analytics; no cloud storage is used for email content

### External Services
- **Google** (OAuth + Gmail API): only when the user connects a Gmail account
- **Optional AI provider** (see "AI / Groq second opinion" below): only if the user configures an API key; when unset, no AI traffic exists at all
- **DNS (MX lookups)**: the domain-intelligence layer performs real, bounded MX record queries via `dnspython` for the sender's domain (cache-backed, hard time budget, thread-pool isolated). It queries MX records only — it never visits URLs or fetches web content
- No other external services are used

### Why Passwords Are Never Collected
PhishGuard is a **defensive analysis tool**, not an email client. It:
- Never asks for email passwords
- Never stores credentials in plaintext
- Uses OAuth 2.0 for API access (industry standard)
- Operates with read-only permissions

## SSRF Prevention

### The Risk
Server-Side Request Forgery (SSRF) occurs when an application makes HTTP requests to user-supplied URLs. If an attacker controls the URL, they can access internal network resources, read cloud metadata endpoints, port-scan internal services, or exfiltrate data.

### Our Approach: Static URL Analysis
PhishGuard performs **static-only URL analysis of email URLs**:
- URLs are extracted and parsed without making HTTP requests to them
- **No HTTP connections are ever made to attacker-controlled URLs**
- URL analysis is based on pattern matching and string analysis
- Domain intelligence performs bounded **MX record lookups via DNS** (see External Services) — this is a DNS query about a domain, not an HTTP request to any server, and no URL is ever contacted

### Why Not Visit URLs?
- Automatically visiting URLs could trigger tracking pixels
- Could expose the server's IP to attackers
- Could be used for SSRF attacks
- Could execute server-side scripts on malicious pages
- Could leak information about the analysis environment

## Attachment Security

### Approach
PhishGuard analyzes **only attachment metadata**:
- Filename and extension
- MIME type
- File size (taken from already-available metadata; attachment payloads are not downloaded or decoded)

### What We Never Do
- Execute or open attachments
- Extract or run embedded macros
- Decompress archive files
- Download attachment content

### Limitations
- Cannot detect fileless malware
- Cannot analyze encrypted attachments
- Cannot detect steganography
- Cannot verify file integrity

## AI / Groq Second Opinion (optional)

The deterministic rule-based engine is **always** the primary analysis system. An optional AI layer (`backend/app/ai/verifier.py`, plus MailBuddy assistant/priority phrasing) can provide a second opinion when the user configures it:

- Providers: hosted **Groq** (`https://api.groq.com/openai/v1`), any OpenAI-compatible endpoint, or a local Ollama model — configured explicitly in the environment; **nothing is used when unconfigured**
- API keys (`GROQ_API_KEY`, etc.) live server-side only: never sent to the frontend, never logged, never stored in the database
- The model receives **structured security data**, never raw instructions; email-derived content is wrapped in XML-style fences (`backend/app/utils/prompt_fencing.py`) and a literal `</email_content>` sequence inside an email cannot escape the fence
- Responses are validated against a strict JSON schema; malformed output results in `UNAVAILABLE` and the deterministic result stands
- The model is stateless per request: no tools, no filesystem access, no ability to send/modify/delete email
- AI never automatically overrides the deterministic classification; disagreement is surfaced as a `DISAGREEMENT` status

## Notifications (anti-flood)

Important-email notifications (CRITICAL/HIGH priority, e.g. SECURITY/OTP class) are:
- Deduplicated per email via a unique ledger key (Gmail re-syncs never re-notify)
- **Bounded per account**: at most `NOTIFICATION_BURST_LIMIT` (5) new notifications per rolling hour, counted against the notification's server-stamped owner account — one account's malicious burst can neither flood the desktop nor consume another account's quota
- Deferred, never permanently dropped: over-quota notifications are created by a later sync/pass once the window drains
- Acknowledgement is account-scoped (F-16): an account can only acknowledge its own notifications

## Rendering & Display-Safety Hardening

### Email body HTML is sanitized before display

#### The risk
An email's raw body (`text/html` parts) can contain arbitrary HTML: `<script>` tags, inline event handlers (`onerror`, `onload`), `javascript:` URLs, and other executable markup. In an email-security tool the analyst routinely opens attacker-controlled content — a single missed sanitization path would turn the analyst workstation into the attack surface.

#### How it is implemented now
- The backend sanitizes HTML body content before storing/returning it for display
- The frontend applies a **second sanitization pass** (`frontend/src/utils/sanitizeHtml.js`) and then injects the result via `dangerouslySetInnerHTML` **only after both passes**; a dev-mode regression guard (`containsUnsafeContent`) logs an error if executable markup ever survives
- Plain-text bodies are rendered as text (no HTML path)
- The app window enforces a strict Content Security Policy; the Electron renderer is sandboxed with `contextIsolation: true`, `nodeIntegration: false`, and a single one-way IPC bridge for notifications
- Email pages are additionally wrapped in a React error boundary so a rendering fault in one message cannot take down the app

### Detected URLs are defanged and rendered as plain text, not clickable links

- Every URL shown in the analyst-facing UI is **defanged** (e.g. `hxxps://evil[.]com/path`) using a `defangUrl` helper
- Defanged URLs are rendered as **plain text**, not as `<a>` elements — they are not clickable
- The Electron shell never opens email-derived URLs automatically; only explicit https links the user invokes elsewhere go to the default browser
- Detection logic is unchanged; only display is hardened

## Why Rule-Based Detection for Primary Detection

1. **Deterministic**: Same input always produces the same output
2. **Explainable**: Every decision has a clear rule ID and evidence
3. **Auditable**: Rules can be reviewed and improved manually
4. **No training data needed**: Works immediately without labeled datasets
5. **No adversarial ML risk**: Cannot be fooled by adversarial examples
6. **Transparent**: Users can see exactly why an email was flagged

## Limitations and False Positives

### Known Limitations
1. **Heuristic scoring**: The risk score is an estimate, not a probability
2. **Limited header analysis**: Some headers may not be present in all emails
3. **Static URL analysis**: Cannot detect redirect chains or dynamic content
4. **No attachment execution**: Cannot detect malware in file content
5. **No machine learning**: May miss novel phishing patterns
6. **MX lookups reveal DNS queries** for sender domains to the configured DNS resolver (metadata only, no content)

### False Positives
- Legitimate security alerts may trigger credential request rules
- Marketing emails may trigger urgency language rules
- IT department emails may trigger sender mismatch rules
- Internal emails may lack authentication headers

### Mitigation
- Category-level score capping prevents single-rule dominance
- Multiple correlated indicators produce stronger scores
- An explicit authentication floor prevents wholly unauthenticated messages from scoring SAFE
- Users are encouraged to verify through independent channels
- The system explicitly states it provides heuristic assessments

## Data Directories & Packaging

- **Development:** mutable data lives in the backend layout (`backend/phishguard.db`, `backend/uploads/`, `backend/.env`)
- **Packaged desktop app:** the Electron shell sets `PHISHGUARD_DATA_DIR` to `%APPDATA%\PhishGuard` (`phishguard.db`, `uploads/`, `logs/`, runtime `.env`, `api.token`); no mutable data is written to the install directory and **no secrets are bundled into the installer**
- The PyInstaller bundle contains the FastAPI backend and the React build only (`packaging/phishguard_backend.spec`); `backend/.env` is never included
- Backend stdout/stderr is captured to `%APPDATA%\PhishGuard\logs\backend.log`; logs contain metadata and error types, never tokens or email content

## Recommendations for Production

If deploying beyond a single-user desktop application:
1. Replace SQLite with a production database and centralized secret management
2. Serve over HTTPS with a real reverse proxy
3. Add per-user accounts with a hardened identity provider
4. Implement audit logging and centralized monitoring
5. Regular security assessments and penetration testing
