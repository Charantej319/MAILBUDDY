# PhishGuard Testing Documentation

## Overview

PhishGuard includes unit tests for individual detection rules and an evaluation system that measures precision, recall, and F1 score against a synthetic test dataset.

## Running Tests

### Everything in one command

Backend pytest, the frontend production build, frontend auth unit tests and
the Electron/Node tests:
```bash
python scripts/run_all_tests.py          # add --quick to skip build + Electron
```

### Backend Unit Tests

Run the whole backend suite (450+ tests — detection rules, security
regressions, OAuth, account isolation, notifications, ingestion performance):
```bash
python -m pytest tests/ -q
```

The suite runs fully offline: no live Gmail, no live DNS lookups, no Groq API
and no Google OAuth are required. AI/Groq environment variables are stripped
before every test (see `tests/conftest.py`), and the suite fails if the
developer's real `backend/phishguard.db` is ever touched.

### Test Coverage (primary suites)

Run `python -m pytest tests/ --collect-only -q` for the live count. The main
suites beyond the original detection-rule tests:

| Suite | What It Tests |
|-------|---------------|
| test_sender.py / test_urls.py / test_content.py / test_headers.py / test_attachments.py | Detection-rule behavior per analyzer |
| test_scoring.py / test_session4_repair.py | Scoring, caps, classification, auth floor |
| test_security_repair.py / test_url_auth_repair.py / test_detection_fp_repair.py | Security and false-positive regression repairs |
| test_oauth_callback.py | OAuth flow incl. allowlisted redirect origin |
| test_mailbuddy.py | Priority, assistant, notifications, account isolation |
| test_notification_burst.py | F-28 bounded per-account notification policy |
| test_gmail_ingest_perf.py | F-30 bounded concurrent ingestion, attachment metadata |
| test_email_detail.py / test_email_content_fetch.py | Detail API body-exposure guarantees |
| test_render_safety.py | Sanitization / XSS regression guards |

### Test Cases

#### Sender Tests
- ✅ Legitimate sender produces no high-severity findings
- ✅ Display name/domain mismatch detection
- ✅ Brand impersonation detection
- ✅ Homoglyph character substitution detection
- ✅ Suspicious TLD detection
- ✅ Reply-To domain mismatch detection
- ✅ Missing sender handling

#### URL Tests
- ✅ Legitimate HTTPS URL produces no high-severity findings
- ✅ IP address URL detection
- ✅ URL shortener detection
- ✅ Suspicious TLD detection
- ✅ Excessively long URL detection
- ✅ Excessive subdomain detection
- ✅ Suspicious path detection
- ✅ Lookalike domain detection
- ✅ HTTP (non-HTTPS) detection
- ✅ Obfuscated URL detection
- ✅ Credentials in URL detection
- ✅ Explicit port detection

#### Content Tests
- ✅ Legitimate content produces no high-severity findings
- ✅ Urgency language detection
- ✅ Credential request detection
- ✅ Threat language detection
- ✅ Social engineering detection
- ✅ Financial scam detection
- ✅ Urgency + credential combination detection
- ✅ Empty content handling

#### Header Tests
- ✅ Passing authentication produces no high-severity findings
- ✅ SPF failure detection
- ✅ SPF softfail detection
- ✅ DKIM failure detection
- ✅ DMARC failure detection
- ✅ From/Reply-To mismatch detection
- ✅ Multiple authentication failure detection

#### Attachment Tests
- ✅ Safe attachment produces no high-severity findings
- ✅ Executable extension detection
- ✅ Double extension detection
- ✅ Script extension detection
- ✅ Macro-enabled Office format detection
- ✅ MIME type/extension mismatch detection
- ✅ Multiple attachment detection
- ✅ No attachment handling

#### Scoring Tests
- ✅ Score classification thresholds
- ✅ No findings produces score 0
- ✅ Single finding scoring
- ✅ Category-level capping
- ✅ Maximum score cap (100)
- ✅ Mixed severity findings

## Evaluation

### Running Evaluation

1. First, generate the test dataset:
```bash
python datasets/create_dataset.py
```

2. Then run the evaluation:
```bash
python tests/evaluate.py
```

### Evaluation Metrics

The evaluation script calculates:
- **Accuracy**: Overall correctness (TP + TN) / Total
- **Precision**: Of flagged emails, how many are actually malicious TP / (TP + FP)
- **Recall**: Of malicious emails, how many were detected TP / (TP + FN)
- **F1 Score**: Harmonic mean of precision and recall 2 × (Precision × Recall) / (Precision + Recall)
- **Confusion Matrix**: TP, TN, FP, FN counts

### Test Dataset

The synthetic test dataset includes:
- **Legitimate emails**: Meeting invites, newsletters, support replies
- **Phishing emails**: Bank phishing, credential phishing, fake delivery, CEO wire transfer, account update phishing
- **Spam emails**: Lottery scams, prize notifications
- **Suspicious emails**: Malicious attachments, suspicious URLs

Each email is labeled as:
- `legitimate` (label: 0) - Not malicious
- `phishing` (label: 1) - Malicious
- `spam` (label: 1) - Malicious

### Interpreting Results

| Metric | Good | Acceptable | Poor |
|--------|------|------------|------|
| Accuracy | >90% | >80% | <80% |
| Precision | >90% | >80% | <80% |
| Recall | >85% | >75% | <75% |
| F1 Score | >85% | >75% | <75% |

**Note**: These are targets for the synthetic dataset. Real-world performance may vary.

### Limitations of Evaluation

1. **Small dataset**: 10 synthetic emails is not representative of real-world email
2. **No diversity**: Limited variety of phishing techniques
3. **Known patterns**: Test emails follow known patterns the rules detect
4. **No adversarial examples**: Real attackers may use novel techniques

For a production system, a larger, more diverse dataset would be needed.
