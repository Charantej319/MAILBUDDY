# PhishGuard Detection Methodology

## Overview

PhishGuard uses a **rule-based detection engine** with explainable weighted scoring. This approach was chosen for the MVP because:
- Deterministic results (same input → same output)
- Fully explainable decisions
- No training data required
- No risk of adversarial ML attacks
- Easy to audit and improve

## Risk Score Calculation

The final risk score (0-100) is calculated by summing category scores:

| Category           | Max Score | Analyzer           |
|--------------------|-----------|---------------------|
| Sender/Domain      | 20 pts    | sender.py           |
| URL Analysis       | 25 pts    | url_analyzer.py     |
| Content            | 20 pts    | content_analyzer.py |
| Headers            | 20 pts    | header_analyzer.py  |
| Attachments        | 10 pts    | attachment_analyzer.py |
| Domain Intel       | 5 pts     | intelligence/domain_intelligence.py |
| Correlation        | 10 pts    | engine.py (cross-signal) |
| Other              | 5 pts     | (reserved)          |
| **Total**          | **100**   |                     |

Each category is **capped** at its maximum, preventing any single category from dominating the score. Additionally, an explicit SPF fail + DKIM fail + DMARC fail combination enforces a score floor of 50 (SUSPICIOUS) — wholly unauthenticated messages can never classify SAFE or LOW RISK.

## Risk Classification

| Score Range | Classification | Description |
|-------------|---------------|-------------|
| 0-24        | SAFE          | No significant concerns |
| 25-49       | LOW RISK      | Minor concerns detected |
| 50-74       | SUSPICIOUS    | Multiple suspicious indicators |
| 75-100      | HIGH RISK     | Strong phishing indicators |

## Detection Rules

### Sender/Domain Analysis

| Rule ID | Severity | Points | Description |
|---------|----------|--------|-------------|
| SENDER_NAME_DOMAIN_MISMATCH | HIGH | 15 | Display name references a brand not in the sender domain |
| SENDER_LOOKALIKE_DOMAIN | HIGH | 15 | Domain closely resembles a known brand (similarity > 50%) |
| SENDER_BRAND_IMPERSONATION | HIGH | 15 | Domain contains a brand name but isn't official |
| SENDER_HOMOGLYPH | HIGH | 12 | Domain contains substituted characters (o→0, l→1, etc.) |
| SENDER_SUSPICIOUS_DOMAIN | MEDIUM | 8 | Domain has suspicious patterns (digits, hyphens, TLD) |
| SENDER_REPLY_TO_MISMATCH | MEDIUM | 8 | Reply-To domain differs from sender domain |
| SENDER_RETURN_PATH_MISMATCH | LOW | 4 | Return-Path domain differs from sender domain |
| SENDER_MISSING | MEDIUM | 5 | Sender email could not be parsed |

### URL Analysis

| Rule ID | Severity | Points | Description |
|---------|----------|--------|-------------|
| URL_IP_ADDRESS | HIGH | 12 | URL uses IP address instead of domain |
| URL_LOOKALIKE_DOMAIN | HIGH | 12 | URL domain resembles a known brand |
| URL_CREDENTIALS_IN_URL | HIGH | 10 | URL contains embedded username/password |
| URL_SHORTENER | MEDIUM | 7 | URL uses a shortener (bit.ly, tinyurl, etc.) |
| URL_SUSPICIOUS_TLD | MEDIUM | 6 | URL uses suspicious TLD (.xyz, .top, .tk, etc.) |
| URL_EXCESSIVE_SUBDOMAINS | MEDIUM | 6 | URL has >4 subdomain levels |
| URL_OBFUSCATED | MEDIUM | 6 | URL contains encoded/obfuscated characters |
| URL_SUSPICIOUS_PATH | MEDIUM | 5 | URL path contains login/verify/auth keywords |
| URL_EXPLICIT_PORT | MEDIUM | 5 | URL uses non-standard port |
| URL_LONG | MEDIUM | 5 | URL is >200 characters |
| URL_HTTP | LOW | 3 | URL uses HTTP instead of HTTPS |
| URL_SUSPICIOUS_PARAMS | LOW | 3 | URL contains suspicious query parameters |

### Content Analysis

| Rule ID | Severity | Points | Description |
|---------|----------|--------|-------------|
| CONTENT_CREDENTIAL_REQUEST | HIGH | up to 10 | Requests passwords, OTPs, PINs, etc. |
| CONTENT_THREAT_LANGUAGE | HIGH | up to 10 | Account suspension, legal action threats |
| CONTENT_URGENCY | MEDIUM-HIGH | up to 8 | Act now, immediate action required |
| CONTENT_SOCIAL_ENGINEERING | MEDIUM-HIGH | up to 8 | Click here, update your account |
| CONTENT_FINANCIAL_SCAM | MEDIUM-HIGH | up to 8 | Wire transfer, lottery, inheritance |
| CONTENT_URGENCY_CREDENTIAL_COMBO | HIGH | 5 | Urgency + credential request combination |
| CONTENT_THREAT_CREDENTIAL_COMBO | HIGH | 5 | Threat + credential request combination |

### Header Analysis

| Rule ID | Severity | Points | Description |
|---------|----------|--------|-------------|
| HEADER_SPF_FAIL | HIGH | 8 | SPF authentication failed |
| HEADER_DKIM_FAIL | HIGH | 7 | DKIM authentication failed |
| HEADER_DMARC_FAIL | HIGH | 8 | DMARC authentication failed |
| HEADER_MULTIPLE_AUTH_FAILURES | HIGH | 10 | 2+ authentication failures |
| HEADER_FROM_REPLYTO_MISMATCH | MEDIUM | 6 | From/Reply-To domain mismatch |
| HEADER_SPF_SOFTFAIL | MEDIUM | 5 | SPF softfail (weak signal — NOT a hard failure) |
| HEADER_DKIM_NONE | MEDIUM | 4 | No DKIM signature |
| HEADER_SPF_NONE | LOW | 3 | No SPF record |
| HEADER_DMARC_NONE | LOW | 2 | No DMARC policy |
| HEADER_SPF_ERROR / HEADER_DKIM_ERROR / HEADER_DMARC_ERROR | LOW | 2 | Evaluation error (temperror/permerror) — NOT a failure |
| HEADER_RETURN_PATH_MISMATCH | LOW | 3 | Return-Path domain mismatch |

### Attachment Analysis

| Rule ID | Severity | Points | Description |
|---------|----------|--------|-------------|
| ATTACHMENT_EXECUTABLE | HIGH | 8 | File has executable extension (.exe, .scr, etc.) |
| ATTACHMENT_DOUBLE_EXTENSION | HIGH | 8 | File has double extension (invoice.pdf.exe) |
| ATTACHMENT_SCRIPT | HIGH | 7 | File is a script (.vbs, .js, .ps1, etc.) |
| ATTACHMENT_DANGEROUS_MIME | HIGH | 7 | MIME type is dangerous |
| ATTACHMENT_MACRO | MEDIUM | 5 | Macro-enabled Office format |
| ATTACHMENT_MIME_MISMATCH | MEDIUM | 5 | MIME type doesn't match extension |
| ATTACHMENT_LARGE | LOW | 2 | Attachment is >10MB |

## Important Disclaimers

1. **Heuristic, not probabilistic**: The risk score is a heuristic assessment, NOT a mathematically proven probability of maliciousness.

2. **Indicators, not proof**: Individual findings are indicators, not definitive proof of phishing. A single suspicious indicator does not mean an email is malicious.

3. **Correlation matters**: Multiple correlated indicators produce stronger scores. An email with urgency language AND credential requests scores higher than either alone.

4. **Static analysis**: URLs are analyzed statically without visiting them. This prevents SSRF risks but means some URL-based analysis is limited.

5. **No execution**: Attachments are never opened or executed. Analysis is limited to metadata.

6. **False positives are possible**: Legitimate emails may trigger some rules (e.g., a bank legitimately asking you to verify your identity). The system is designed to err on the side of caution.
