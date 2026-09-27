"""
Session 4 repair — focused regression tests.

Covers the five remaining findings:
  F-8  Authority-term parsing: "VP", "manager", "vice president" (and other
       authority titles) are recognized on word boundaries regardless of
       position, case, or adjacent punctuation — no substring bugs.
  F-9  Numeric severity comparison: LOW < MEDIUM < HIGH < CRITICAL; a HIGH
       duplicate never replaces a CRITICAL finding (no alphabetical compare,
       no mixed-identity rows).
  F-10 Urgency + credential combination bonus applied EXACTLY ONCE: the
       correlation layer owns the bonus; the content-level combo is a
       zero-point marker; single signals never fire the combo.
  F-12 Content normalization: NFKC + zero-width stripping + de-obfuscation
       (p.a.s.s.w.o.r.d, p a s s w o r d, passw0rd, zero-width split) detect
       credential requests; benign password discussion stays benign.
  F-21 Canonical HIGH_RISK: engine output is machine-form ("HIGH_RISK"),
       legacy "HIGH RISK" is accepted by normalize/display helpers, and the
       full engine → priority/assistant path works with canonical values.

The detection-level tests are pure and never touch the network. The
end-to-end test class exercises the full DetectionEngine and (when run with
the API fixtures) the FastAPI pipeline with a mocked Groq verifier.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from detection.sender import (
    SenderAnalyzer,
    display_name_claims_authority,
)
from detection.content_analyzer import ContentAnalyzer, normalize_content
from detection.rules import (
    Finding,
    Category,
    Severity,
    severity_rank,
    classify_risk,
    normalize_risk_level,
    risk_display_label,
    is_risky_level,
    RiskLevel,
)
from detection.scoring import RiskScorer
from detection.engine import DetectionEngine


def _rules(findings):
    return [f.rule_id for f in findings]


# ═════════════════════════════ F-8 ═════════════════════════════

class TestF8AuthorityTermParsing:
    """Authority claims must be parsed on word boundaries."""

    @pytest.mark.parametrize("name", [
        "VP",
        "vp",                       # case-insensitive
        "John VP",                  # term at the END of the name (edge)
        "VP, Finance",              # term followed by punctuation
        "VP Finance",               # term at the START (edge)
        "manager",
        "Manager",                  # case-insensitive
        "Operations Manager",
        "Product Manager, Platform",
        "vice president",
        "Vice President",
        "Vice President of Sales",
        "Senior Vice President",    # 'vice president' inside a longer title
        "CEO",
        "Chief Executive Officer",  # 'chief' as a standalone word
        "IT Support",
        "HR Department",
    ])
    def test_authority_names_detected(self, name):
        assert display_name_claims_authority(name), name

    @pytest.mark.parametrize("name", [
        "John Smith",
        "Ann Lee",
        "managerial economics course",   # 'manager' is NOT a standalone word
        "supervising editor",            # substring but not word-boundary
        "devpper operations",            # 'vp' inside a word must not match
        "The Vaping Club",               # 'vp'? no — 'vaping' has no standalone vp
        "",
        None,
    ])
    def test_non_authority_names_not_detected(self, name):
        assert not display_name_claims_authority(name), name

    @pytest.mark.parametrize("name", ["VP", "Manager", "Vice President", "CEO"])
    def test_freemail_authority_finding_fires(self, name):
        """BEC signal: authority display name on a free mailbox."""
        findings = SenderAnalyzer().analyze(
            sender_email=f"user@outlook.com", sender_name=name,
            sender_domain="outlook.com",
        )
        assert "SENDER_FREEMAIL_AUTHORITY" in _rules(findings), name

    def test_freemail_non_authority_stays_clean(self):
        findings = SenderAnalyzer().analyze(
            sender_email="user@outlook.com", sender_name="John Smith",
            sender_domain="outlook.com",
        )
        assert "SENDER_FREEMAIL_AUTHORITY" not in _rules(findings)


# ═════════════════════════════ F-9 ═════════════════════════════

class TestF9NumericSeverityComparison:
    """Severity must compare numerically, never alphabetically."""

    def test_rank_ordering(self):
        assert severity_rank("LOW") < severity_rank("MEDIUM")
        assert severity_rank("MEDIUM") < severity_rank("HIGH")
        assert severity_rank("HIGH") < severity_rank("CRITICAL")
        # The exact alphabetical trap: "HIGH" >= "CRITICAL" as strings.
        assert not ("HIGH" < "CRITICAL")  # string compare would be False
        assert severity_rank("HIGH") < severity_rank("CRITICAL")  # numeric OK

    def test_unknown_severity_ranks_lowest(self):
        assert severity_rank("garbage") == 0
        assert severity_rank("") == 0
        assert severity_rank(None) == 0
        assert severity_rank("low") == severity_rank("LOW")  # case-insensitive

    def _mismatch(self, severity, points):
        return Finding(
            rule_id="SENDER_REPLY_TO_MISMATCH",
            category=Category.SENDER,
            severity=severity,
            points=points,
            message=f"mismatch ({severity})",
            dedup_key="test-domain",
        )

    def test_high_duplicate_does_not_replace_critical(self):
        """THE regression: alphabetical ordering would let HIGH (>= CRITICAL
        as strings) replace a CRITICAL finding."""
        score, cls, out, _, _ = RiskScorer().calculate_score(
            [self._mismatch("CRITICAL", 15), self._mismatch("HIGH", 8)]
        )
        rows = [f for f in out if f["rule_id"] == "SENDER_REPLY_TO_MISMATCH"]
        assert len(rows) == 1, rows
        assert rows[0]["severity"] == "CRITICAL", rows[0]
        assert rows[0]["points"] == 15  # winner keeps full points

    def test_critical_arriving_second_still_wins(self):
        """Order independence: HIGH first, CRITICAL second."""
        score, cls, out, _, _ = RiskScorer().calculate_score(
            [self._mismatch("HIGH", 8), self._mismatch("CRITICAL", 15)]
        )
        rows = [f for f in out if f["rule_id"] == "SENDER_REPLY_TO_MISMATCH"]
        assert len(rows) == 1, rows
        assert rows[0]["severity"] == "CRITICAL", rows[0]
        assert rows[0]["points"] == 15

    def test_equal_severity_keeps_first_no_double_count(self):
        score, cls, out, _, _ = RiskScorer().calculate_score(
            [self._mismatch("HIGH", 8), self._mismatch("HIGH", 8)]
        )
        rows = [f for f in out if f["rule_id"] == "SENDER_REPLY_TO_MISMATCH"]
        assert len(rows) == 1, rows
        assert rows[0]["points"] == 8  # first copy, full points, once

    def test_lower_severity_dropped_not_merged(self):
        """A weaker duplicate is dropped; it never produces a mixed row."""
        score, cls, out, _, _ = RiskScorer().calculate_score(
            [self._mismatch("CRITICAL", 15), self._mismatch("LOW", 2)]
        )
        rows = [f for f in out if f["rule_id"] == "SENDER_REPLY_TO_MISMATCH"]
        assert len(rows) == 1, rows
        assert rows[0]["severity"] == "CRITICAL"
        # No frankenstein row: points must be the winner's own full points.
        assert rows[0]["points"] == 15


# ═════════════════════════════ F-10 ═════════════════════════════

class TestF10UrgencyCredentialOnce:
    """The urgency+credential combination bonus is applied exactly once."""

    def _analyzer(self):
        return ContentAnalyzer()

    # — single signals must not fire the combination —

    def test_urgency_alone(self):
        findings = self._analyzer().analyze("URGENT: Act immediately, final warning!")
        rules = _rules(findings)
        assert "CONTENT_URGENCY" in rules
        assert "CONTENT_CREDENTIAL_REQUEST" not in rules
        assert "CONTENT_URGENCY_CREDENTIAL_COMBO" not in rules

    def test_credential_alone(self):
        findings = self._analyzer().analyze("Please enter your password to continue.")
        rules = _rules(findings)
        assert "CONTENT_CREDENTIAL_REQUEST" in rules
        assert "CONTENT_URGENCY" not in rules
        assert "CONTENT_URGENCY_CREDENTIAL_COMBO" not in rules

    # — combination fires at the content level —

    def test_urgency_plus_credential_fires_combo(self):
        findings = self._analyzer().analyze(
            "URGENT: Your account will be suspended. Enter your password now."
        )
        rules = _rules(findings)
        assert "CONTENT_URGENCY" in rules
        assert "CONTENT_CREDENTIAL_REQUEST" in rules
        assert "CONTENT_URGENCY_CREDENTIAL_COMBO" in rules

    # — the combination bonus is scored EXACTLY ONCE —

    def test_combination_bonus_scored_exactly_once_end_to_end(self):
        """Full engine path: CORR_URGENCY_CREDENTIAL owns the bonus (+10);
        the content-level combo is present as a ZERO-point marker. Sum of all
        urgency+credential combination points == 10, never 15."""
        engine = DetectionEngine()

        class P:
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

        results = engine.analyze(P())
        combo_points = sum(
            f["points"] for f in results["findings"]
            if f["rule_id"] in ("CORR_URGENCY_CREDENTIAL",
                                "CONTENT_URGENCY_CREDENTIAL_COMBO")
        )
        assert combo_points == 10, (
            f"combination bonus applied {combo_points} points, expected exactly 10"
        )
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "CORR_URGENCY_CREDENTIAL" in rule_ids
        assert "CONTENT_URGENCY_CREDENTIAL_COMBO" in rule_ids
        marker = next(f for f in results["findings"]
                      if f["rule_id"] == "CONTENT_URGENCY_CREDENTIAL_COMBO")
        assert marker["points"] == 0, marker  # zero-point evidence marker

    def test_base_signals_not_suppressed_by_correlation(self):
        """F-10 prunes only the DUPLICATE combo — the base URGENCY and
        CREDENTIAL findings must survive untouched."""
        engine = DetectionEngine()

        class P:
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

        rule_ids = [f["rule_id"] for f in engine.analyze(P())["findings"]]
        assert "CONTENT_URGENCY" in rule_ids
        assert "CONTENT_CREDENTIAL_REQUEST" in rule_ids

    # — benign wording stays clean —

    @pytest.mark.parametrize("body", [
        "Your account dashboard has new features. "
        "The account manager will present quarterly results.",
        "We updated our password policy documentation last week.",
        "The manager shared the Q3 roadmap. Urgent budget review is next month, "
        "but no action is needed from you.",
    ])
    def test_benign_wording_not_flagged(self, body):
        findings = self._analyzer().analyze(body)
        rules = _rules(findings)
        assert "CONTENT_URGENCY" not in rules or "CONTENT_CREDENTIAL_REQUEST" not in rules
        assert "CONTENT_URGENCY_CREDENTIAL_COMBO" not in rules


# ═════════════════════════════ F-12 ═════════════════════════════

class TestF12ContentNormalization:
    """Obfuscated credential vocabulary must normalize back to detectable form."""

    # — normalization primitives —

    def test_nfkc_fullwidth(self):
        assert normalize_content("ｐａｓｓｗｏｒｄ") == "password"

    def test_zero_width_stripped(self):
        text = "pa\u200bs\u200cs\u200dw\u2060o\ufeffr\u00add"
        assert normalize_content(text) == "password"

    def test_whitespace_collapsed_original_untouched(self):
        original = "line one\nline\ttwo"
        normalized = normalize_content(original)
        assert normalized == "line one line two"
        assert original == "line one\nline\ttwo"  # input never mutated

    def test_empty_and_none_safe(self):
        assert normalize_content("") == ""
        assert normalize_content(None) == ""

    # — de-obfuscated credential requests are detected —

    @pytest.mark.parametrize("body", [
        "Please enter your p.a.s.s.w.o.r.d.",
        "Enter your p a s s w o r d now.",
        "Your session expired — enter your passw0rd.",
        "Submit your pa\u200bssword to verify.",          # zero-width space
        "Confirm your ｐａｓｓｗｏｒｄ.",               # full-width NFKC
        "Send us your p-a-s-s-w-o-r-d.",
    ])
    def test_obfuscated_requests_detected(self, body):
        findings = ContentAnalyzer().analyze(body)
        assert "CONTENT_CREDENTIAL_REQUEST" in _rules(findings), body

    def test_plain_password_detected(self):
        findings = ContentAnalyzer().analyze("Please enter your password.")
        assert "CONTENT_CREDENTIAL_REQUEST" in _rules(findings)

    # — benign password DISCUSSION stays benign —

    @pytest.mark.parametrize("body", [
        "The password policy was updated last week.",
        "Our team discussed password hygiene in the security training.",
        "A strong password protects your device; see the guide for tips.",
    ])
    def test_benign_password_discussion_not_flagged(self, body):
        findings = ContentAnalyzer().analyze(body)
        assert "CONTENT_CREDENTIAL_REQUEST" not in _rules(findings), body


# ═════════════════════════════ F-21 ═════════════════════════════

class TestF21CanonicalRiskRepresentation:
    """Engine output is canonical HIGH_RISK; legacy 'HIGH RISK' stays compatible."""

    def test_classify_risk_returns_machine_form(self):
        assert classify_risk(90) == "HIGH_RISK"
        assert classify_risk(90) != "HIGH RISK"
        assert classify_risk(60) == "SUSPICIOUS"
        assert classify_risk(30) == "LOW_RISK"
        assert classify_risk(10) == "SAFE"

    def test_legacy_display_form_normalizes(self):
        assert normalize_risk_level("HIGH RISK") == "HIGH_RISK"
        assert normalize_risk_level("high risk") == "HIGH_RISK"
        assert normalize_risk_level("HIGH_RISK") == "HIGH_RISK"
        assert normalize_risk_level("LOW RISK") == "LOW_RISK"

    def test_display_label_derived_from_both_forms(self):
        assert risk_display_label("HIGH_RISK") == "HIGH RISK"
        assert risk_display_label("HIGH RISK") == "HIGH RISK"

    def test_is_risky_level_accepts_both_forms(self):
        assert is_risky_level("HIGH_RISK")
        assert is_risky_level("HIGH RISK")
        assert is_risky_level("SUSPICIOUS")
        assert not is_risky_level("SAFE")
        assert not is_risky_level("LOW_RISK")

    def test_engine_produces_canonical_high_risk(self):
        """Full engine path: a classic phishing email yields classification
        'HIGH_RISK' (machine form), never 'HIGH RISK'."""
        engine = DetectionEngine()

        class P:
            sender_email = "security@paypa1-secure.example"
            sender_name = "PayPal Security"
            sender_domain = "paypa1-secure.example"
            urls = ["https://paypa1-secure.example/login?next=/verify"]
            anchor_text = ""
            body_text = ("URGENT: Your account has been suspended. "
                         "Enter your password and verification code within 24 hours.")
            body_html = ""
            headers = {}
            attachments = []
            spf_result = "fail"
            dkim_result = "fail"
            dmarc_result = "fail"
            received_headers = []
            message_id = ""
            subject = "Your account has been suspended"

        results = engine.analyze(P())
        assert results["risk_score"] >= 75, results["risk_score"]
        assert results["classification"] == "HIGH_RISK", results["classification"]
        assert " " not in results["classification"]

    def test_priority_receives_canonical_value(self):
        """MailBuddy priority consumes the canonical value end-to-end."""
        from backend.app.mailbuddy.priority import heuristic_classify
        result = heuristic_classify(
            subject="Your account has been suspended",
            sender="PayPal Security",
            sender_email="security@paypa1-secure.example",
            sender_domain="paypa1-secure.example",
            body_text="URGENT: Enter your password to restore access within 24 hours.",
            security_classification="HIGH_RISK",
        )
        assert result["priority"] == "HIGH", result
        assert any("security engine" in r.lower() for r in result["reasons"]), result

    def test_assistant_accepts_canonical_value(self):
        """The assistant's grounded answer path works with canonical input."""
        from backend.app.mailbuddy.assistant import _deterministic_email_answer

        class Row:
            classification = "HIGH_RISK"
            risk_score = 88.0
            detection_findings = '[{"rule_id": "X", "severity": "HIGH", "message": "test indicator"}]'
            ai_verdict = None
            ai_status = None

        answer = _deterministic_email_answer(Row(), "is this suspicious?")
        assert "HIGH_RISK" in answer
        assert "test indicator" in answer

    def test_assistant_flagged_detection_dual_form(self):
        """Flagged-ness is recognized for BOTH stored forms."""
        from backend.app.mailbuddy import assistant

        class Row:
            risk_score = 88.0
            detection_findings = "[]"
            ai_verdict = None
            ai_status = None

        for value in ("HIGH_RISK", "HIGH RISK", "SUSPICIOUS"):
            Row.classification = value
            assert assistant._deterministic_email_answer(
                Row(), "is this suspicious?") is not None


# ═══════════════ cross-cutting: no Session 1–3 regressions ═══════════════

class TestSessions13StillHold:
    def test_phishing_email_still_high_risk(self):
        from detection.engine import DetectionEngine
        from detection.rules import is_risky_level

        class P:
            sender_email = "security@paypa1-secure.com"
            sender_name = "PayPal Security"
            sender_domain = "paypa1-secure.com"
            urls = ["https://paypa1-secure.com/login?next=/verify"]
            anchor_text = ""
            body_text = ("URGENT: Your account has been suspended. "
                         "Enter your password and verification code within 24 hours.")
            body_html = ""
            headers = {"Reply-To": "collector@evil-libs.example"}
            attachments = []
            spf_result = "fail"
            dkim_result = "fail"
            dmarc_result = "fail"
            received_headers = []
            message_id = ""
            subject = "Your account has been suspended"

        results = DetectionEngine().analyze(P())
        assert results["risk_score"] >= 50
        assert is_risky_level(results["classification"])
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "CONTENT_CREDENTIAL_REQUEST" in rule_ids
        assert "SENDER_BRAND_IMPERSONATION" in rule_ids

    def test_legitimate_email_stays_safe(self):
        from detection.engine import DetectionEngine

        class P:
            sender_email = "john@acmecorp.com"
            sender_name = "John Smith"
            sender_domain = "acmecorp.com"
            urls = []
            anchor_text = ""
            body_text = ("Hi team, please review the attached quarterly report. "
                         "The account manager will present the results on Monday.")
            body_html = ""
            headers = {}
            attachments = []
            spf_result = "pass"
            dkim_result = "pass"
            dmarc_result = "pass"
            received_headers = []
            message_id = ""
            subject = "Quarterly report review"

        results = DetectionEngine().analyze(P())
        assert results["classification"] in ("SAFE", "LOW_RISK"), (
            f"{results['classification']} ({results['risk_score']})"
        )

    def test_regional_domains_still_clean(self):
        from detection.url_analyzer import URLAnalyzer
        for url in ("https://google.de", "https://amazon.co.uk"):
            assert "URL_LOOKALIKE_DOMAIN" not in _rules(URLAnalyzer().analyze([url]))


# ═══════════════ end-to-end API probe (uses app fixtures) ═══════════════

class TestSession4EndToEnd:
    """Full pipeline through the FastAPI app, mirroring test_security_repair's
    isolation strategy (PHISHGUARD_DATA_DIR set by conftest before import)."""

    @pytest.fixture(scope="class")
    def client(self):
        from backend.app.database.connection import init_db
        from backend.app.main import app
        init_db()
        from fastapi.testclient import TestClient
        with TestClient(app) as c:
            yield c

    @pytest.fixture
    def api_token(self, client):
        from backend.app.auth import token_manager
        token = token_manager.load_or_create_token()
        assert token
        return token

    PHISH_EML = (
        "From: PayPal Security <security@paypa1-secure.example>\r\n"
        "To: user@example.com\r\n"
        "Subject: Your account has been suspended\r\n"
        "Authentication-Results: mx.example.com; spf=fail dkim=fail dmarc=fail\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<p>URGENT: Your account has been suspended.</p>"
        "<p><a href=\"https://paypa1-secure.example/login?next=/verify\">"
        "https://paypa1-secure.example/login</a></p>"
        "<p>Enter your password and verification code within 24 hours.</p>"
    )

    def _headers(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_analyze_raw_canonical_high_risk(self, client, api_token):
        r = client.post("/api/analyze/raw",
                        json={"email_content": self.PHISH_EML},
                        headers=self._headers(api_token))
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["risk_score"] >= 75, data["risk_score"]
        assert data["classification"] == "HIGH_RISK", data["classification"]

    def test_stored_row_canonical_and_retrievable(self, client, api_token):
        r = client.post("/api/analyze/raw",
                        json={"email_content": self.PHISH_EML},
                        headers=self._headers(api_token))
        assert r.status_code == 200
        email_id = r.json()["id"]

        detail = client.get(f"/api/emails/{email_id}", headers=self._headers(api_token))
        assert detail.status_code == 200, detail.text
        assert detail.json()["classification"] == "HIGH_RISK"

        # The email appears in the statistics' high-risk bucket (dual-form query;
        # risk_distribution keeps spaced display keys for the frontend contract).
        stats = client.get("/api/statistics", headers=self._headers(api_token))
        assert stats.status_code == 200
        assert stats.json().get("high_risk_count", 0) >= 1
        assert stats.json().get("risk_distribution", {}).get("HIGH RISK", 0) >= 1

        # MailBuddy priority surfaces the same canonical row: the summary's
        # "attention" list reports priority_level plus the stored security
        # classification (canonical HIGH_RISK under the "security" key).
        summary = client.get("/api/mailbuddy/priority/summary",
                             headers=self._headers(api_token))
        assert summary.status_code == 200
        attention = summary.json().get("attention") or []
        assert any(item.get("security") == "HIGH_RISK" and item.get("priority") == "HIGH"
                   for item in attention), (
            [(i.get("security"), i.get("priority")) for i in attention]
        )


if __name__ == "__main__":
    print("Run with: python -m pytest tests/test_session4_repair.py -v")
