# PhishGuard Security Documentation

## Overview

PhishGuard is designed as a **defensive security analysis tool**. This document explains the security measures, design decisions, and limitations.

## OAuth Security

### Implementation
- Google OAuth 2.0 is used for Gmail API access
- Only the `gmail.readonly` scope is requested (least privilege)
- Tokens are handled server-side during the OAuth flow
- The application **never** asks for or stores Gmail passwords

### Token Protection
- OAuth tokens are never committed to version control
- Environment variables are used for client secrets
- `.env.example` contains no real credentials
- Tokens are returned to the client for session-based use only
- In production, tokens should be encrypted and stored server-side

### Scope Limitations
The application requests only these scopes:
- `https://www.googleapis.com/auth/gmail.readonly` - Read emails only
- `https://www.googleapis.com/auth/userinfo.email` - Basic profile
- `https://www.googleapis.com/auth/userinfo.profile` - Basic profile

The application **cannot**:
- Send emails
- Delete emails
- Modify email labels
- Access other Google services

## Privacy Considerations

### Data Collection
- Only email metadata is stored (sender, subject, date, risk score)
- Email body text is **not** permanently stored in the database
- OAuth tokens are **not** stored in the database
- No user tracking or analytics

### Data Retention
- Analysis results are stored locally in SQLite
- Users can delete analysis results at any time
- No data is sent to external services
- No cloud storage is used for email content

### Why Passwords Are Never Collected
PhishGuard is a **defensive analysis tool**, not an email client. It:
- Never asks for email passwords
- Never stores credentials
- Uses OAuth 2.0 for API access (industry standard)
- Operates with read-only permissions

## SSRF Prevention

### The Risk
Server-Side Request Forgery (SSRF) occurs when an application makes HTTP requests to user-supplied URLs. If an attacker controls the URL, they can:
- Access internal network resources
- Read cloud metadata endpoints
- Port-scan internal services
- Exfiltrate data

### Our Approach: Static URL Analysis
PhishGuard performs **static-only URL analysis**. This means:
- URLs are extracted and parsed without making HTTP requests
- No DNS lookups are performed on suspicious domains
- No HTTP connections are made to attacker-controlled URLs
- URL analysis is based on pattern matching and string analysis

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
- File size
- Structural properties

### What We Never Do
- Execute or open attachments
- Extract or run embedded macros
- Decompress archive files
- Run antivirus scans (would require execution)

### Limitations
- Cannot detect fileless malware
- Cannot analyze encrypted attachments
- Cannot detect steganography
- Cannot verify file integrity

## Prompt Injection Risks

If an LLM is later added to PhishGuard, these risks must be addressed:
- Email content could contain instructions to the LLM
- Attackers could craft emails that manipulate AI analysis
- The LLM could be tricked into misclassifying phishing emails
- Output could be used to generate convincing phishing replies

**Mitigation**: Keep the deterministic rule-based engine as the primary detection method. Any LLM component should be supplementary and sandboxed.

## Why Rule-Based Detection for MVP

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

### False Positives
- Legitimate security alerts may trigger credential request rules
- Marketing emails may trigger urgency language rules
- IT department emails may trigger sender mismatch rules
- Internal emails may lack authentication headers

### Mitigation
- Category-level score capping prevents single-rule dominance
- Multiple correlated indicators produce stronger scores
- Users are encouraged to verify through independent channels
- The system explicitly states it provides heuristic assessments

## Rendering & Display-Safety Hardening

### Email body / HTML content is never rendered as HTML in the analyst UI

#### The risk
An email's raw body (especially `text/html` parts) can contain arbitrary HTML, including `<script>` tags, inline event handlers (`onerror`, `onload`), and other executable markup. If that markup is inserted into the DOM with React's `dangerouslySetInnerHTML`, an `<iframe srcdoc>`, or any DOM `innerHTML` assignment, the browser will execute any script it contains. In an email-security tool this is especially dangerous: the entire premise of the product is that users routinely open email content that an attacker fully controls. A single missed sanitization path would turn the analyst workstation into the attack surface — a phishing email could run in the analyst's browser, exfiltrate tokens, or hook the session.

#### Why it matters for an email-security tool specifically
Most web apps treat user-generated HTML as a secondary concern; an email analyzer treats it as the primary input. Every message the analyst inspects is, by definition, untrusted content from an external sender. The analyst is the high-value target, and the tool is the vector. Rendering raw HTML here is not a normal "user content" problem — it is "rendering attacker-controlled content in a privileged viewer" problem.

#### How it is mitigated now
- The frontend renders email body content as **plain text only**. There is no `dangerouslySetInnerHTML`, no `eval`, and no `<iframe srcdoc>` anywhere in the UI.
- A small `stripHtmlToText` helper collapses HTML to readable text by removing tags and decoding common HTML entities. It is intentionally naive on purpose: the goal is to guarantee plain text, not to build a sanitizer.
- The backend does not return raw email HTML to the frontend for display. Email parsing retains `body_html` internally for URL extraction only; the API layer returns only metadata, findings, extracted URLs, and attachments.

### Detected URLs are defanged and rendered as plain text, not clickable links

#### The risk
Rendering a detected URL as a clickable `<a href="...">` means every displayed indicator is also a live link. Two problems follow: (1) the analyst can accidentally click a malicious link and land on an attacker-controlled page, and (2) some browsers or extensions may prefetch, scan, or otherwise interact with a real link even without a full click, leaking information about the analysis environment. For an email-security tool, exposing live malicious URLs in the analyst UI is exactly the behavior we are trying to help analysts avoid.

#### Why it matters for an email-security tool specifically
The analyst viewing a phishing email is often the person deciding whether the URL is malicious. Showing it as a clickable link invites a click in precisely the moment of judgment. It also creates a subtle inconsistency: the tool says "this URL is suspicious" while simultaneously making it one click away from being followed. A defanged URL preserves readability for analysis without creating an activation path.

#### How it is mitigated now
- Every URL shown in the analyst-facing UI is **defanged** (e.g. `hxxps://evil[.]com/path`) using a `defangUrl` helper.
- Defanged URLs are rendered as **plain text**, not as `<a>` elements. They are not clickable.
- This applies to the URL Intelligence panel and any other place URLs appear in the UI. Detection logic itself is unchanged; only display is hardened.

## Recommendations for Production

If deploying beyond a portfolio project:
1. Add encrypted token storage
2. Implement rate limiting
3. Add input validation and sanitization
4. Use HTTPS for all API communication
5. Add authentication and authorization
6. Implement audit logging
7. Add machine learning models (supplementary to rules)
8. Deploy with a Web Application Firewall
9. Regular security assessments and penetration testing
