# 🛡️ MAILBUDDY
### AI-Assisted Email Phishing & Spam Detection Platform

**Understand suspicious emails. Detect potential threats. Stay informed.**

MAILBUDDY is a desktop-based email security application that analyzes emails for phishing, spam, impersonation, suspicious links, and social engineering indicators.

It combines a modular, explainable detection engine with domain intelligence, threat intelligence checks, cross-signal correlation, and optional AI-assisted verification to help users understand why an email might be dangerous.

Unlike a simple spam classifier, MAILBUDDY focuses on explaining its findings. Every detection provides relevant evidence, severity, and an explanation to help users make informed decisions.

<p align="center">
  <strong>Defensive Cybersecurity • Explainable Detection • Privacy-Conscious Design</strong>
</p>

---

## 📌 Project Overview

Email remains one of the most commonly exploited communication channels for cyberattacks.

Attackers use impersonation, malicious links, credential-harvesting pages, fraudulent attachments, and social engineering to manipulate users into revealing sensitive information.

MAILBUDDY addresses this problem by providing a unified platform for email threat analysis.

### What makes MAILBUDDY different?

- **Explainable detection:** Understand why an email was flagged instead of receiving only a black-box classification.
- **Multiple detection layers:** Analyze sender identity, URLs, content, headers, attachments, and domain intelligence.
- **Threat intelligence:** Incorporate domain age, Google Safe Browsing, and TLS-related intelligence.
- **Cross-signal correlation:** Identify suspicious combinations of indicators that may be less obvious when examined individually.
- **AI-assisted verification:** Use an optional AI second opinion to supplement deterministic detection.
- **Email prioritization:** Organize emails according to their importance and assessed risk.
- **Desktop experience:** Access email security analysis through a dedicated Electron application.

---

## ✨ Key Features

### 1. Email Phishing & Spam Detection

MAILBUDDY analyzes email characteristics using multiple specialized security components.

Detection capabilities include:

- Sender impersonation and lookalike domains.
- Suspicious URLs and IP-based links.
- URL obfuscation and shortened links.
- Urgency, threats, and social engineering language.
- SPF, DKIM, and DMARC authentication anomalies.
- Suspicious attachments and filename patterns.
- Domain registration age and intelligence.
- TLS-related domain intelligence.
- Known malicious URL reputation checks.
- Correlated security indicators.

### 2. Explainable Risk Assessment

Every finding is accompanied by relevant information, including:

- Detection category.
- Rule or finding identifier, where available.
- Severity.
- Supporting evidence.
- Risk contribution.
- Explanation of the detected behavior.

Risk is represented through a heuristic score rather than a mathematically established probability.

| Score | Classification | Indicator |
|---|---|---|
| 0–24 | SAFE | 🟢 |
| 25–49 | LOW RISK | 🟡 |
| 50–74 | SUSPICIOUS | 🟠 |
| 75–100 | HIGH RISK | 🔴 |

The scoring engine also considers combinations of security indicators instead of relying exclusively on isolated findings.

### 3. Domain & Threat Intelligence

MAILBUDDY extends traditional rule-based email analysis with additional intelligence layers.

| Component | Purpose |
|---|---|
| Domain Age Intelligence | Examines domain registration age and related indicators. |
| Google Safe Browsing | Checks URLs against known unsafe-resource intelligence. |
| TLS Intelligence | Examines TLS and certificate-related information. |
| Domain Intelligence | Evaluates domain characteristics and suspicious patterns. |
| Cross-Signal Correlation | Combines multiple findings to identify related threat indicators. |

These components provide additional context to the primary detection engine.

### 4. AI-Assisted Verification

MAILBUDDY includes an optional AI-assisted verification layer.

Its purpose is to provide a supplementary assessment of suspicious emails and help interpret potentially harmful content.

Key principles:

- Deterministic detection remains the primary assessment mechanism.
- AI is supplementary, not the sole source of classification.
- AI findings do not automatically override the underlying detection evidence.
- The application does not automatically reply to emails.

The current implementation uses a hosted Groq-based AI verification workflow.

### 5. Gmail Integration

- Gmail API integration.
- Google OAuth 2.0 authentication.
- Read-only email access.
- Email analysis through the connected account.
- Secure token storage.
- Account-scoped email analysis.

### 6. Email Prioritization

MAILBUDDY helps users focus on important emails through priority-based organization.

It supports prioritization of:

- Critical emails.
- High-priority emails.
- Normal emails.
- Low-priority emails.

This helps distinguish security threats from legitimate but important communications.

### 7. Desktop Application

MAILBUDDY is packaged as a Windows desktop application using Electron.

The desktop version integrates the frontend and backend into a single application experience without requiring users to manually start development servers.

---

## 🏗️ System Architecture

MAILBUDDY follows a modular architecture that separates the user interface, email processing, detection logic, intelligence services, and desktop application layer.

### High-Level Architecture

```text
                  MAILBUDDY
                       |
             Email Input / Gmail API
                       |
                       v
                Email Processing
                       |
                       v
                 Email Parser
               (MIME / Headers)
                       |
                       v
              Feature Extraction
                       |
                       v
              Detection Engine
                       |
       +---------------+----------------+
       |               |                |
       v               v                v
   Sender Analysis  URL Analysis   Content Analysis
       |               |                |
       +---------------+----------------+
                       |
       +---------------+----------------+
       |               |                |
       v               v                v
  Header Analysis  Attachment      Domain & Threat
                   Analysis        Intelligence
                       |
                       v
              Cross-Signal Correlation
                       |
                       v
               Risk Assessment
                       |
                       v
              Optional AI Verification
                       |
                       v
               Analysis Results
                       |
                       v
              MAILBUDDY Dashboard
```

### Desktop Architecture

The packaged Windows application uses Electron to launch and manage the backend.

```text
             MAILBUDDY.exe
                    |
                    v
             Electron Shell
                    |
                    v
          Python Backend Executable
                    |
                    v
              FastAPI Server
                    |
          +---------+---------+
          |                   |
          v                   v
      React SPA            REST API
          |                   |
          +---------+---------+
                    |
                    v
              SQLite Database
```

The packaged application serves the React production build through the FastAPI backend.

This allows the desktop application to use a common localhost origin for its interface, API requests, and session cookies.

---

## 🔬 Detection Methodology

MAILBUDDY uses a modular, rule-based detection approach.

Each analyzer focuses on a particular area of email security.

| Detection Layer | Analysis |
|---|---|
| Sender Analysis | Sender identity, impersonation, and domain mismatches. |
| URL Analysis | Suspicious URLs, IP addresses, obfuscation, and shortened links. |
| Content Analysis | Urgency, credential requests, threats, and social engineering. |
| Header Analysis | SPF, DKIM, DMARC, and authentication anomalies. |
| Attachment Analysis | Suspicious extensions, MIME inconsistencies, and attachment indicators. |
| Domain Intelligence | Domain characteristics, registration age, and related intelligence. |
| Threat Intelligence | Google Safe Browsing and TLS-related intelligence. |
| Cross-Signal Correlation | Relationships between multiple suspicious findings. |
| AI Verification | Optional supplementary assessment using an AI service. |

### Explainable Scoring

Findings are evaluated through a scoring mechanism that considers the severity and relevance of detected indicators.

For example:

```text
Email Analysis
      |
      +-- Suspicious Sender
      |
      +-- Recently Registered Domain
      |
      +-- Credential Request
      |
      +-- Suspicious Login URL
      |
      v
Cross-Signal Correlation
      |
      v
Risk Assessment
      |
      v
Classification + Evidence
```

The objective is not simply to identify suspicious emails but to provide understandable reasons behind the assessment.

---

## 🛠️ Technology Stack

| Component | Technologies |
|---|---|
| Backend | Python, FastAPI |
| Frontend | React, Vite, JavaScript |
| Desktop Framework | Electron |
| Database | SQLite |
| Email Processing | Python Email / MIME |
| Authentication | Google OAuth 2.0 |
| Email Integration | Gmail API |
| AI Verification | Groq API |
| Threat Intelligence | Google Safe Browsing |
| Domain Intelligence | RDAP, DNS and TLS-related analysis |
| Testing | Pytest, Node.js Test Runner |
| Packaging | PyInstaller, Electron Builder, NSIS |
| Version Control | Git, GitHub |

---

## 📁 Project Structure

```text
MAILBUDDY/
│
├── backend/
│   ├── app/
│   │   ├── ai/                 # AI verification
│   │   ├── api/                # API endpoints
│   │   ├── auth/               # OAuth and session management
│   │   ├── database/           # Database connection
│   │   ├── gmail/              # Gmail integration
│   │   ├── mailbuddy/          # Email processing and prioritization
│   │   ├── models/             # Data models
│   │   ├── parser/             # Email parsing
│   │   └── main.py             # FastAPI entry point
│   ├── requirements.txt
│   └── .env.example
│
├── desktop/
│   ├── main.js                 # Electron main process
│   ├── preload.js              # Secure IPC bridge
│   ├── backend.js              # Backend process management
│   ├── package.json
│   └── electron-builder.json
│
├── detection/
│   ├── intelligence/
│   │   └── threat_intel/       # Threat intelligence integrations
│   ├── engine.py               # Detection orchestrator
│   ├── sender.py               # Sender analysis
│   ├── url_analyzer.py         # URL analysis
│   ├── content_analyzer.py     # Content analysis
│   ├── header_analyzer.py      # Header analysis
│   ├── attachment_analyzer.py  # Attachment analysis
│   ├── scoring.py              # Risk scoring
│   └── rules.py                # Detection rules
│
├── frontend/
│   ├── public/
│   │   └── brand/              # MAILBUDDY branding
│   ├── src/
│   │   ├── components/         # Reusable UI components
│   │   ├── pages/              # Application pages
│   │   ├── services/           # API communication
│   │   └── utils/              # Utility functions and tests
│   └── package.json
│
├── datasets/                   # Email evaluation dataset
│   ├── legitimate/
│   ├── phishing/
│   ├── spam/
│   ├── labels.csv
│   └── create_dataset.py
│
├── documentation/
│   ├── ARCHITECTURE.md
│   ├── DETECTION.md
│   ├── GMAIL_SETUP.md
│   ├── SECURITY.md
│   └── TESTING.md
│
├── packaging/
│   ├── build_backend.ps1
│   ├── build_installer.ps1
│   └── backend_entry.py
│
├── reports/                    # Development and validation reports
├── screenshots/                # Application screenshots
├── scripts/                    # Testing and diagnostic scripts
├── tests/                      # Backend test suite
│
├── .gitignore
├── pytest.ini
└── README.md
```

---

## 🚀 Installation & Setup

MAILBUDDY supports both development execution and packaged Windows desktop deployment.

### Prerequisites

For development:

- Windows 10/11 or a compatible development environment.
- Python 3.10 or newer.
- Node.js 18 or newer.
- npm.
- Git.

### 1. Clone the Repository

```bash
git clone https://github.com/Charantej319/MAILBUDDY.git
```

Navigate into the project:

```bash
cd MAILBUDDY
```

### 2. Backend Setup

Navigate to the backend:

```bash
cd backend
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create your environment configuration:

```powershell
Copy-Item .env.example .env
```

Configure the required environment variables in `backend/.env`.

Start the backend:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 3. Frontend Setup

Open another terminal from the project root:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

The development application uses:

| Service | Address |
|---|---|
| React Frontend | http://localhost:5173 |
| FastAPI Backend | http://localhost:8000 |
| API Documentation | http://localhost:8000/docs |

The frontend development server proxies the relevant API and authentication requests to the backend.

---

## 🖥️ Windows Desktop Application

MAILBUDDY also provides a packaged Windows desktop application.

The Electron shell manages the backend process and launches the application interface.

### Desktop Application Architecture

```text
MailBuddy.exe
      |
      v
Electron Main Process
      |
      v
Backend Process Manager
      |
      v
Packaged Python Backend
      |
      v
FastAPI + React Production Build
      |
      v
MAILBUDDY Desktop Interface
```

The packaged version does not require a separately running Vite development server.

### Build the Windows Installer

From the project root:

**Step 1: Build the frontend**

```powershell
cd frontend
npm install
npm run build
cd ..
```

**Step 2: Package the Python backend**

```powershell
powershell -ExecutionPolicy Bypass -File packaging/build_backend.ps1
```

**Step 3: Generate the Windows installer**

```powershell
powershell -ExecutionPolicy Bypass -File packaging/build_installer.ps1
```

The installer is generated under:

```text
desktop/dist/
```

The packaged installer is distributed separately from the source repository through GitHub Releases.

---

## 📧 Gmail OAuth Configuration

Gmail integration is optional.

To connect a Gmail account:

1. Open the Google Cloud Console.
2. Create a Google Cloud project.
3. Enable the Gmail API.
4. Configure the OAuth consent screen.
5. Create OAuth 2.0 credentials.
6. Configure the appropriate authorized redirect URI:

```text
http://localhost:8000/auth/google/callback
```

7. Add your credentials to `backend/.env` using the variable names specified in `.env.example`.

The application uses Gmail read-only access.

**Important:** Never commit your actual OAuth credentials, API keys, or `.env` files to GitHub.

For additional information, see:

`documentation/GMAIL_SETUP.md`

---

## 🧪 Testing

MAILBUDDY includes automated tests covering backend functionality, detection components, frontend utilities, security behavior, and desktop application functionality.

### Run the Complete Test Workflow

From the project root:

```bash
python scripts/run_all_tests.py
```

### Backend Tests

```bash
python -m pytest tests/ -q
```

For verbose output:

```bash
python -m pytest tests/ -v
```

### Frontend Tests

```bash
cd frontend
node --test src/utils/authStatus.test.js
```

### Electron Tests

```bash
cd desktop
npm test
```

### Frontend Production Build

```bash
cd frontend
npm run build
```

### Evaluation Dataset

Generate the evaluation dataset:

```bash
python datasets/create_dataset.py
```

Run the evaluation:

```bash
python -m tests.evaluate
```

The evaluation framework calculates:

- Accuracy.
- Precision.
- Recall.
- F1 Score.
- Confusion Matrix.

These metrics help evaluate detection behavior on the included dataset. They should not be interpreted as guaranteed real-world detection performance.

---

## 🔒 Security & Privacy Considerations

Security is a central consideration in MAILBUDDY's architecture.

### Defensive-First Design

- The application does not automatically delete, forward, or reply to suspicious emails.
- Email attachments are analyzed through available metadata and indicators, not executed.
- URLs in analyzed emails are not opened as ordinary web pages.
- Optional reputation and intelligence checks may communicate with trusted external services or perform DNS/TLS-related checks.

### Gmail Security

- Gmail integration uses OAuth 2.0.
- Gmail access is read-only.
- Authentication tokens are protected using platform-appropriate encryption mechanisms.
- Analysis records are scoped to the authenticated account.

### Credential Protection

- API keys and OAuth credentials belong in local environment configuration.
- Secrets must never be hardcoded into source files.
- Credentials and runtime tokens must not be committed to GitHub.

### AI Verification

When AI verification is enabled, relevant email information may be processed by the configured external AI provider.

Users should consider the provider's data-handling policies before submitting sensitive communications for AI analysis.

### Detection Limitations

MAILBUDDY is a defensive cybersecurity prototype.

Its findings are heuristic assessments and not mathematically proven probabilities or guarantees of malicious activity.

False positives and false negatives are possible. Users should verify suspicious communications through independent, trusted channels.

For more information, read:

`documentation/SECURITY.md`

---

## 🗺️ Future Development

Potential areas for future improvements include:

- Supplementary machine-learning detection models.
- Real-time email monitoring.
- Advanced email authentication analysis.
- Enhanced threat intelligence integrations.
- Custom detection rule management.
- Additional email-provider integrations.
- Docker-based deployment.
- Multi-language support.
- More comprehensive security evaluation datasets.

---

## 🤝 Contributing

Contributions, suggestions, and security-related improvements are welcome.

Before contributing:

1. Review the existing project documentation.
2. Understand the modular detection architecture.
3. Follow secure coding practices.
4. Add tests for new functionality.
5. Never include actual credentials, tokens, or private email data in commits.

For security-sensitive issues, avoid publicly sharing exploitable details before responsible disclosure.

---

## ⚠️ Disclaimer

MAILBUDDY is an educational and defensive cybersecurity project.

It is not a replacement for enterprise email security solutions, professional incident response, or dedicated threat intelligence platforms.

Risk scores are heuristic assessments and should not be treated as definitive proof that an email is safe or malicious.

Use the application responsibly and only with email accounts and data you are authorized to analyze.

---

## 👨‍💻 Project

**MAILBUDDY — AI-Assisted Email Phishing & Spam Detection Platform**

Repository: https://github.com/Charantej319/MAILBUDDY

Built with a focus on explainable detection, defensive security, and practical cybersecurity engineering.

**Understand the threat. Examine the evidence. Make informed decisions.**
