# 🛡️ PhishGuard

**Explainable Email Phishing & Threat Detection Platform**

A defensive cybersecurity prototype that analyzes emails and detects potential phishing, spam, and social engineering attempts using a modular, rule-based detection engine with explainable scoring.

---

## ⚠️ Disclaimer

This is a **defensive security prototype** built for educational purposes. It is NOT production-ready software. Risk scores are heuristic assessments, not mathematically proven probabilities. Always verify suspicious emails through independent trusted channels.

---

## 🎯 Problem Statement

Email phishing remains one of the most common and effective cyberattack vectors. Existing solutions often provide black-box classifications without explaining *why* an email was flagged. PhishGuard addresses this by providing:

- **Explainable detection**: Every finding includes rule ID, severity, evidence, and explanation
- **Modular architecture**: Individual analyzers can be improved independently
- **Transparent scoring**: Users can see exactly how the risk score was calculated
- **Defensive focus**: Never automatically deletes, replies to, or forwards emails

## 🏗️ Architecture

```
Email Input (.eml / Gmail API)
        ↓
   Email Parser (MIME/headers)
        ↓
   Security Feature Extraction
        ↓
   ┌────────────────────────────────────┐
   │        Detection Engine             │
   │  Sender │ URL │ Content │ Headers  │
   │         │     │         │ Attachmnt│
   └────────────────────────────────────┘
        ↓
   Explainable Risk Score (0-100)
        ↓
   Classification (Safe/Low/Suspicious/High)
        ↓
   Dashboard with Findings & Recommendations
```

## ✨ Features

- **Gmail OAuth 2.0 Integration**: Connect your Gmail account securely (read-only access)
- **.eml File Upload**: Analyze email files directly
- **Modular Detection Engine**: 5 specialized analyzers with 40+ detection rules
- **Explainable Scoring**: Every detection shows rule ID, severity, points, and evidence
- **Risk Classification**: SAFE / LOW RISK / SUSPICIOUS / HIGH RISK
- **React Dashboard**: Clean cybersecurity-themed interface
- **Test Dataset**: Synthetic emails for evaluation
- **Unit Tests**: 51+ test cases covering all detection rules
- **Evaluation Metrics**: Precision, recall, F1 score calculation

## 🔬 Detection Methodology

### Risk Score Calculation

| Category           | Max Score | Description |
|--------------------|-----------|-------------|
| Sender/Domain      | 20 pts    | Lookalike domains, impersonation, mismatches |
| URL Analysis       | 30 pts    | IP URLs, shorteners, suspicious TLDs, obfuscation |
| Content            | 20 pts    | Urgency, credentials, threats, social engineering |
| Headers            | 15 pts    | SPF, DKIM, DMARC failures, authentication anomalies |
| Attachments        | 10 pts    | Executables, double extensions, MIME mismatches |
| Other              | 5 pts     | Reserved for future rules |

### Risk Classification

| Score | Classification |
|-------|---------------|
| 0-24  | 🟢 SAFE |
| 25-49 | 🟡 LOW RISK |
| 50-74 | 🟠 SUSPICIOUS |
| 75-100 | 🔴 HIGH RISK |

## 🛠️ Technologies

| Component | Technology |
|-----------|-----------|
| Backend | Python, FastAPI |
| Frontend | React, Vite |
| Database | SQLite |
| Email Parsing | Python email/MIME |
| Gmail API | Google OAuth 2.0 |
| Detection | Rule-based engine |

## 📦 Installation

### Prerequisites

- Python 3.10+
- Node.js 18+
- npm or yarn

### Backend Setup

```bash
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment variables
cp .env.example .env

# Start the backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Start the frontend
npm run dev
```

The application will be available at:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## 📧 Gmail OAuth Setup (Optional)

If you want to connect Gmail for live email analysis:

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select an existing one
3. Enable the Gmail API
4. Create OAuth 2.0 credentials (Web application type)
5. Add `http://localhost:8000/auth/google/callback` as an authorized redirect URI
6. Copy Client ID and Client Secret to your `.env` file:

```env
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
```

**Note**: The .eml upload feature works without Gmail OAuth.

## 🖥️ Desktop Application (MailBuddy.exe)

The packaged Windows app ships the same codebase with **no dev server involved**:

```
MailBuddy.exe (Electron)
        ↓ spawns
phishguard-backend.exe (PyInstaller FastAPI) bound to 127.0.0.1:8000
        ↓ health-gated startup (polls /api/health)
Electron window loads http://localhost:8000
        ↓ same origin serves the React SPA + API + session cookies
```

| | Development | Packaged |
|---|---|---|
| Frontend | Vite dev server `:5173` (proxies `/api` + `/auth`) | React build served by FastAPI itself |
| Backend | uvicorn on `127.0.0.1:8000` | PyInstaller exe on `127.0.0.1:8000` |
| App origin | `http://localhost:5173` | `http://localhost:8000` (SPA + API + cookies) |
| OAuth callback | `http://localhost:8000/auth/google/callback` (same in both) | same |
| Data directory | `backend/` (dev layout) | `%APPDATA%\PhishGuard` (`phishguard.db`, `uploads/`, `logs/`, runtime `.env`) |
| Secrets | `backend/.env` | `%APPDATA%\PhishGuard\.env` — **never bundled** into the installer |

Notes:

- The app window always uses the `localhost` origin (not `127.0.0.1`) because the Google-registered callback sets the `phishguard_session` cookie on host `localhost` — cookie hosts are per-name in Chromium, and using `localhost` in the window is what makes the Gmail connection persist across app restarts.
- The post-auth OAuth redirect is same-origin in both modes (derived from the request Host), so the packaged app never redirects to the Vite dev server.
- Backend stdout/stderr is captured to `%APPDATA%\PhishGuard\logs\backend.log` for diagnosis.

### Building the installer

```powershell
# 1. Frontend production build
cd frontend
npm run build
cd ..

# 2. PyInstaller backend bundle (packaging/dist/phishguard-backend/)
powershell -ExecutionPolicy Bypass -File packaging/build_backend.ps1

# 3. NSIS installer → desktop/dist/MailBuddy-Setup-1.0.0.exe
powershell -ExecutionPolicy Bypass -File packaging/build_installer.ps1
```

## 📤 Analyzing Emails

### Upload .eml File

1. Click "Analyze .eml" in the navigation
2. Drag and drop an .eml file or click to browse
3. Click "Analyze Email"
4. View the risk score, findings, and recommendations

### Connect Gmail

1. Click the Gmail integration button
2. Authorize the application (read-only access)
3. Select emails to analyze
4. View results in the dashboard

## 🧪 Testing

### Run Unit Tests

```bash
python -m pytest tests/ -v
```

### Run Evaluation

```bash
# Generate test dataset
python datasets/create_dataset.py

# Run evaluation
python tests/evaluate.py
```

### Test Dataset

The synthetic dataset includes:
- Legitimate emails (meeting invites, newsletters, support replies)
- Phishing emails (bank phishing, credential phishing, CEO wire transfer)
- Spam emails (lottery scams, prize notifications)
- Suspicious emails (malicious attachments, suspicious URLs)

## 📊 Evaluation Metrics

The evaluation calculates:
- **Accuracy**: Overall correctness
- **Precision**: Of flagged emails, how many are actually malicious
- **Recall**: Of malicious emails, how many were detected
- **F1 Score**: Harmonic mean of precision and recall
- **Confusion Matrix**: TP, TN, FP, FN counts

## 🔒 Security Considerations

- **Defensive only**: Never automatically deletes, replies to, or forwards emails
- **Static URL analysis**: URLs are analyzed without visiting them (SSRF prevention)
- **No execution**: Attachments are never opened or executed
- **Token protection**: OAuth tokens handled securely, never committed
- **Least privilege**: Gmail API uses readonly scope
- **Explainable**: Every finding includes evidence and explanation

See [documentation/SECURITY.md](documentation/SECURITY.md) for detailed security documentation.

## 📁 Project Structure

```
phishingdetectionapp/
├── backend/                 # FastAPI backend
│   ├── app/
│   │   ├── main.py         # Application entry point
│   │   ├── config.py       # Configuration
│   │   ├── api/            # API endpoints
│   │   ├── auth/           # OAuth authentication
│   │   ├── gmail/          # Gmail API integration
│   │   ├── parser/         # Email parsing
│   │   ├── models/         # Database models
│   │   └── database/       # SQLite connection
│   ├── requirements.txt
│   └── .env.example
├── detection/               # Detection engine
│   ├── engine.py           # Main engine orchestrator
│   ├── scoring.py          # Risk scoring
│   ├── sender.py           # Sender analysis
│   ├── url_analyzer.py     # URL analysis
│   ├── content_analyzer.py # Content analysis
│   ├── header_analyzer.py  # Header analysis
│   ├── attachment_analyzer.py # Attachment analysis
│   └── rules.py            # Rule definitions
├── frontend/                # React frontend
│   ├── src/
│   │   ├── components/     # UI components
│   │   ├── pages/          # Page components
│   │   ├── services/       # API services
│   │   └── App.jsx         # Main app
│   └── package.json
├── datasets/                # Test dataset
│   ├── legitimate/
│   ├── phishing/
│   ├── spam/
│   ├── labels.csv
│   └── create_dataset.py
├── tests/                   # Unit tests
│   ├── test_sender.py
│   ├── test_urls.py
│   ├── test_content.py
│   ├── test_headers.py
│   ├── test_attachments.py
│   ├── test_scoring.py
│   └── evaluate.py
├── documentation/           # Documentation
│   ├── ARCHITECTURE.md
│   ├── DETECTION.md
│   ├── SECURITY.md
│   └── TESTING.md
└── README.md
```

## 🚀 Future Improvements

- [ ] Machine learning model (supplementary to rules)
- [ ] Real-time email monitoring
- [ ] Browser extension for email clients
- [ ] REST API for integration with other tools
- [ ] Docker containerization
- [ ] Multi-language support
- [ ] Custom rule editor
- [ ] Email quarantine recommendations
- [ ] Integration with threat intelligence feeds
- [ ] Advanced header analysis (Received chain analysis)

## 📝 License

This project is for educational purposes. Use responsibly for defensive security analysis only.

## 🤝 Contributing

Contributions are welcome! Please read the security documentation before submitting changes.

---

**Built with ❤️ for cybersecurity education**

*PhishGuard is a defensive security analysis tool. It provides heuristic assessments, not definitive threat detection. Always verify suspicious emails through independent trusted channels.*
