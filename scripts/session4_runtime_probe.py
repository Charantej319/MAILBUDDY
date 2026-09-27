"""Session 4 runtime probe — proves findings F-8, F-9, F-10, F-12, F-21
through the REAL runtime paths (parser → engine → scorer, MailBuddy priority,
MailBuddy assistant). No network, no database.

Run from project root:
    python scripts/session4_runtime_probe.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


# ───────────────────────── F-8: authority-term parsing ─────────────────────────
from detection.sender import display_name_claims_authority, SenderAnalyzer

f8_ok = all(display_name_claims_authority(n) for n in
            ("VP", "John VP", "VP, Finance", "manager", "Operations Manager",
             "vice president", "Vice President of Sales", "CEO"))
f8_neg = not any(display_name_claims_authority(n) for n in
                 ("John Smith", "managerial economics course", ""))
bec = SenderAnalyzer().analyze(sender_email="ceo@outlook.com",
                               sender_name="Vice President",
                               sender_domain="outlook.com")
f8_bec = "SENDER_FREEMAIL_AUTHORITY" in [f.rule_id for f in bec]
check("F-8 VP / manager / vice president parsed as authority claims",
      f8_ok and f8_neg and f8_bec,
      "" if (f8_ok and f8_neg and f8_bec) else "see detection/sender.py")

# ───────────────────────── F-9: numeric severity comparison ─────────────────────────
from detection.rules import severity_rank, Finding, Category
from detection.scoring import RiskScorer

f9_order = (severity_rank("LOW") < severity_rank("MEDIUM") < severity_rank("HIGH")
            < severity_rank("CRITICAL"))


def _mismatch(sev, pts):
    return Finding(rule_id="SENDER_REPLY_TO_MISMATCH", category=Category.SENDER,
                   severity=sev, points=pts, message="mismatch", dedup_key="d")


_, _, out, _, _ = RiskScorer().calculate_score(
    [_mismatch("CRITICAL", 15), _mismatch("HIGH", 8)])
rows = [f for f in out if f["rule_id"] == "SENDER_REPLY_TO_MISMATCH"]
f9_dedup = (len(rows) == 1 and rows[0]["severity"] == "CRITICAL"
            and rows[0]["points"] == 15)
check("F-9 LOW<HIGH, HIGH<CRITICAL, LOW<CRITICAL, MEDIUM<HIGH (numeric, "
      "HIGH duplicate never replaces CRITICAL)", f9_order and f9_dedup)

# ───────────────────────── F-10: urgency+credential exactly once ─────────────────────────
from detection.content_analyzer import ContentAnalyzer
from detection.engine import DetectionEngine


def _crules(body):
    return [f.rule_id for f in ContentAnalyzer().analyze(body)]


f10_urg = ("CONTENT_URGENCY" in _crules("URGENT: act immediately!")
           and "CONTENT_CREDENTIAL_REQUEST" not in _crules("URGENT: act immediately!"))
f10_cred = ("CONTENT_CREDENTIAL_REQUEST" in _crules("Please enter your password.")
            and "CONTENT_URGENCY" not in _crules("Please enter your password."))
f10_combo = "CONTENT_URGENCY_CREDENTIAL_COMBO" in _crules(
    "URGENT: enter your password now.")
f10_benign = ("CONTENT_URGENCY_CREDENTIAL_COMBO" not in _crules(
    "Your account dashboard has new features. The account manager will "
    "present quarterly results."))


class _P:
    sender_email = "security@paypa1-secure.example"
    sender_name = "Security Team"
    sender_domain = "paypa1-secure.example"
    urls = []
    anchor_text = ""
    body_text = "URGENT: Your account will be suspended. Enter your password now."
    body_html = ""
    headers = {}
    attachments = []
    spf_result = "pass"
    dkim_result = "pass"
    dmarc_result = "pass"
    received_headers = []
    message_id = ""
    subject = "Account suspended"


engine_results = DetectionEngine().analyze(_P())
f10_once = sum(
    f["points"] for f in engine_results["findings"]
    if f["rule_id"] in ("CORR_URGENCY_CREDENTIAL",
                        "CONTENT_URGENCY_CREDENTIAL_COMBO")) == 10
check("F-10 urgency alone / credential alone / combo / benign wording / "
      "combination bonus applied exactly once (+10, never +15)",
      f10_urg and f10_cred and f10_combo and f10_benign and f10_once)

# ───────────────────────── F-12: content normalization ─────────────────────────
f12_cases = [
    "Please enter your password.",
    "Please enter your p.a.s.s.w.o.r.d.",
    "Enter your p a s s w o r d now.",
    "Submit your pa\u200bssword to verify.",
    "Your session expired — enter your passw0rd.",
    "Confirm your ｐａｓｓｗｏｒｄ.",
]
f12_detect = all("CONTENT_CREDENTIAL_REQUEST" in _crules(b) for b in f12_cases)
f12_benign = "CONTENT_CREDENTIAL_REQUEST" not in _crules(
    "The password policy was updated last week.")
check("F-12 password / p.a.s.s.w.o.r.d / 'p a s s w o r d' / zero-width / "
      "passw0rd / full-width detected; benign password discussion clean",
      f12_detect and f12_benign)

# ───────────────────────── F-21: canonical HIGH_RISK end-to-end ─────────────────────────
from backend.app.mailbuddy.priority import heuristic_classify
from backend.app.mailbuddy.assistant import _deterministic_email_answer
from detection.rules import normalize_risk_level, risk_display_label

PHISH_EML = (
    "From: PayPal Security <security@paypa1-secure.example>\r\n"
    "To: user@example.com\r\n"
    "Subject: Your account has been suspended\r\n"
    "Authentication-Results: mx.example.com; spf=fail dkim=fail dmarc=fail\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<p>URGENT: Your account has been suspended.</p>"
    "<p>Enter your password and verification code within 24 hours.</p>"
)

parsed = __import__(
    "backend.app.parser.email_parser", fromlist=["parse_eml_content"]
).parse_eml_content(PHISH_EML.encode())
engine_results = DetectionEngine().analyze(parsed)
cls = engine_results["classification"]
f21_engine = (cls == "HIGH_RISK" and engine_results["risk_score"] >= 75)

prio = heuristic_classify(
    subject=parsed.subject,
    sender=parsed.sender,
    sender_email=parsed.sender_email,
    sender_domain=parsed.sender_domain,
    body_text=parsed.body_text,
    security_classification=cls,  # canonical value received by priority
)
f21_priority = prio["priority"] == "HIGH"


class _Row:
    classification = cls
    risk_score = engine_results["risk_score"]
    detection_findings = (
        '[{"rule_id": "X", "severity": "HIGH", "message": "test indicator"}]'
    )
    ai_verdict = None
    ai_status = None


answer = _deterministic_email_answer(_Row(), "is this suspicious?")
f21_assistant = "HIGH_RISK" in answer and "test indicator" in answer
f21_compat = (normalize_risk_level("HIGH RISK") == "HIGH_RISK"
              and risk_display_label("HIGH_RISK") == "HIGH RISK"
              and risk_display_label("HIGH RISK") == "HIGH RISK")
check("F-21 engine -> HIGH_RISK (canonical); priority receives it and raises "
      "to HIGH; assistant consumes it; legacy 'HIGH RISK' stays compatible",
      f21_engine and f21_priority and f21_assistant and f21_compat,
      f"classification={cls!r}, priority={prio['priority']!r}")

# ───────────────────────── summary ─────────────────────────
print()
ok = all(good for _, good in results)
print("SESSION 4 RUNTIME PROBE:", "ALL PASS" if ok else "FAILURES PRESENT")
sys.exit(0 if ok else 1)
