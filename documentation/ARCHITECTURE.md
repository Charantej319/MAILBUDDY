# PhishGuard Architecture

## Overview

PhishGuard is a defensive email security analysis platform that detects phishing, spam, and suspicious emails using a modular, explainable rule-based detection engine.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (React)                       │
│  Dashboard │ Email List │ Analysis │ Upload │ Stats      │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTP API
┌─────────────────────┴───────────────────────────────────┐
│                  Backend (FastAPI)                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Auth API │  │ Analysis │  │ Gmail API │              │
│  │ (OAuth)  │  │ Endpoints│  │ Endpoints │              │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘              │
│       │              │              │                    │
│  ┌────┴──────────────┴──────────────┴─────┐             │
│  │            Email Parser                  │             │
│  │  (MIME parsing, URL extraction, etc.)   │             │
│  └────────────────┬────────────────────────┘             │
│                   │                                       │
│  ┌────────────────┴────────────────────────┐             │
│  │        Detection Engine                   │             │
│  │  ┌────────┐ ┌─────┐ ┌──────────┐        │             │
│  │  │ Sender │ │ URL │ │ Content  │        │             │
│  │  │  Ana.  │ │Ana. │ │  Ana.    │        │             │
│  │  └────────┘ └─────┘ └──────────┘        │             │
│  │  ┌────────┐ ┌──────────┐                 │             │
│  │  │ Header │ │Attachmnt │                 │             │
│  │  │  Ana.  │ │  Ana.    │                 │             │
│  │  └────────┘ └──────────┘                 │             │
│  │         ┌───────────┐                    │             │
│  │         │  Scorer   │                    │             │
│  │         └───────────┘                    │             │
│  └────────────────┬────────────────────────┘             │
│                   │                                       │
│  ┌────────────────┴────────────────────────┐             │
│  │          SQLite Database                  │             │
│  └──────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────┘
```

## Components

### 1. Email Parser (`backend/app/parser/`)
- Parses raw `.eml` files using Python's `email` library
- Extracts metadata: sender, recipient, subject, date
- Parses email headers for authentication results
- Extracts URLs from both plain-text and HTML bodies
- Handles multipart MIME messages
- Extracts attachment metadata (filename, MIME type, size)

### 2. Detection Engine (`detection/`)
A modular detection system with five specialized content analyzers plus domain intelligence and cross-signal correlation:

#### Sender Analyzer (`sender.py`)
- Display name vs domain mismatch detection
- Brand impersonation detection
- Homoglyph/character substitution detection
- Suspicious TLD detection
- From/Reply-To mismatch detection

#### URL Analyzer (`url_analyzer.py`)
- Static-only URL analysis (no HTTP requests - prevents SSRF)
- IP address URL detection
- URL shortener detection
- Suspicious TLD detection
- Lookalike domain detection
- Obfuscated URL detection
- Suspicious path/parameter detection

#### Content Analyzer (`content_analyzer.py`)
- Urgency language detection
- Credential request detection
- Threat/fear language detection
- Social engineering pattern detection
- Financial scam indicator detection
- Combination bonus scoring

#### Header Analyzer (`header_analyzer.py`)
- SPF result analysis
- DKIM result analysis
- DMARC result analysis
- From/Reply-To inconsistency detection
- Received header analysis

#### Attachment Analyzer (`attachment_analyzer.py`)
- Executable extension detection
- Double extension detection
- Script extension detection
- Macro-enabled Office format detection
- MIME type/extension mismatch detection

#### Domain Intelligence (`intelligence/domain_intelligence.py`)
- Bounded, cache-backed MX record resolution (dnspython) for the sender's domain
- Brand lookalike and suspicious-TLD intelligence

#### Cross-Signal Correlation (in `engine.py`)
- Combines related findings (e.g. credential request + suspicious login URL) into correlation findings with anti-double-counting deduplication

### 3. Scoring Engine (`scoring.py`)
- Combines findings from all analyzers
- Applies category-level score capping
- Produces 0-100 risk score
- Classifies as SAFE/LOW RISK/SUSPICIOUS/HIGH RISK

### 4. API Layer (`backend/app/api/`)
- RESTful endpoints for email analysis
- `.eml` file upload and analysis
- Email retrieval from database
- Statistics aggregation

### 5. Frontend (`frontend/`)
- React dashboard with cybersecurity theme
- Email list with filtering and search
- Detailed analysis page with explainable findings
- File upload interface
- Statistics visualization

## Data Flow

1. **Input**: User uploads `.eml` file or connects Gmail
2. **Parsing**: Email is parsed into structured `ParsedEmail` object
3. **Analysis**: Five analyzers process the email independently
4. **Scoring**: Findings are weighted and combined into a 0-100 score
5. **Classification**: Score is mapped to risk level
6. **Storage**: Results are saved to SQLite
7. **Display**: Frontend shows explainable findings with evidence

## Security Design Principles

- **Defensive only**: Never automatically deletes, replies, or forwards emails
- **Static analysis**: URLs are analyzed without visiting them (SSRF prevention)
- **No execution**: Attachments are never opened or executed
- **Token protection**: Gmail OAuth tokens are encrypted at rest (Windows DPAPI / Fernet fallback) and never exposed to the frontend
- **Least privilege**: Gmail API uses readonly scope
- **Explainable**: Every finding includes rule ID, severity, evidence, and explanation
