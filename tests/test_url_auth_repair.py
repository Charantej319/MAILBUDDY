"""
URL / link / email-authentication repair — focused regression tests (Session 3).

Covers:
  F-3  Visible link text vs actual href (end-to-end through parser + engine)
  F-4  Punycode/IDN homoglyph detection (safe decoding, brand comparison)
  F-5  SPF/DKIM/DMARC normalization (distinct semantic states)
  F-6  Composite authentication severity floor (strong failure combinations)

Session 2 regression examples are re-verified at the end.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from detection.url_analyzer import URLAnalyzer, detect_punycode_brand_lookalike, decode_punycode_domain
from detection.header_analyzer import HeaderAnalyzer
from detection.scoring import RiskScorer
from detection.rules import Finding, Category
from detection.engine import DetectionEngine
from backend.app.parser.email_parser import (
    parse_eml_content,
    normalize_auth_result,
    extract_anchors_from_html,
)


def _rules(findings):
    return [f.rule_id for f in findings]


def _make_eml(body_html: str, auth_header: str = "", from_addr: str = "news@acmecorp.com") -> bytes:
    headers = (
        f"From: {from_addr}\r\n"
        "To: user@example.com\r\n"
        "Subject: Session 3 test\r\n"
    )
    if auth_header:
        headers += f"Authentication-Results: {auth_header}\r\n"
    return (
        headers.encode() +
        b"Content-Type: text/html\r\n\r\n" +
        body_html.encode()
    )


def _engine_results(parsed) -> dict:
    return DetectionEngine().analyze(parsed)


def _parsed_from_eml(eml: bytes):
    return parse_eml_content(eml)


# ───────────────────────────── F-3 ─────────────────────────────

class TestF3VisibleLinkMismatch:
    CRITICAL_CASE = ('<a href="https://evil-login.example/verify">'
                     'https://google.com/verify</a>')

    def test_parser_extracts_both_href_and_visible_text(self):
        parsed = _parsed_from_eml(_make_eml(self.CRITICAL_CASE))
        assert parsed.anchors == [
            ("https://evil-login.example/verify", "https://google.com/verify")
        ]

    def test_critical_case_not_safe_end_to_end(self):
        """THE regression: displayed Google URL over an evil href must not
        classify SAFE through the full DetectionEngine path."""
        parsed = _parsed_from_eml(_make_eml(self.CRITICAL_CASE))
        assert any(href == "https://evil-login.example/verify" and
                   text == "https://google.com/verify"
                   for href, text in parsed.anchors)
        results = _engine_results(parsed)
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "URL_VISIBLE_LINK_MISMATCH" in rule_ids, rule_ids
        assert results["classification"] != "SAFE", (
            f"{results['classification']} ({results['risk_score']})"
        )

    def test_matching_url_anchor_stays_clean(self):
        html = '<a href="https://google.com/verify">https://google.com/verify</a>'
        findings = URLAnalyzer().analyze(
            ["https://google.com/verify"],
            anchors=[("https://google.com/verify", "https://google.com/verify")],
        )
        assert "URL_VISIBLE_LINK_MISMATCH" not in _rules(findings)

    def test_ordinary_text_anchor_not_flagged(self):
        findings = URLAnalyzer().analyze(
            ["https://example.com/reset"],
            anchors=[("https://example.com/reset", "Reset your password")],
        )
        assert "URL_VISIBLE_LINK_MISMATCH" not in _rules(findings)

    def test_whitespace_and_entity_normalization(self):
        # Newlines/indentation inside the anchor + HTML entity in text.
        html = ('<a href="https://google.com/verify">\n        '
                'https://google.com/verify\u00a0\n    </a>')
        anchors = extract_anchors_from_html(html)
        findings = URLAnalyzer().analyze(
            ["https://google.com/verify"], anchors=anchors,
        )
        assert "URL_VISIBLE_LINK_MISMATCH" not in _rules(findings)

    def test_case_insensitive_url_match(self):
        findings = URLAnalyzer().analyze(
            ["https://google.com/verify"],
            anchors=[("https://google.com/verify", "HTTPS://GOOGLE.COM/VERIFY")],
        )
        assert "URL_VISIBLE_LINK_MISMATCH" not in _rules(findings)

    def test_href_entity_decoding(self):
        """HTML entities in the href are decoded by html.parser attrs."""
        html = '<a href="https://google.com/a?b=1&amp;c=2">https://google.com/a?b=1&amp;c=2</a>'
        anchors = extract_anchors_from_html(html)
        assert anchors[0][0] == "https://google.com/a?b=1&c=2"
        findings = URLAnalyzer().analyze(
            ["https://google.com/a?b=1&c=2"], anchors=anchors,
        )
        assert "URL_VISIBLE_LINK_MISMATCH" not in _rules(findings)

    def test_nested_formatting_tags_flattened(self):
        html = ('<a href="https://google.com/verify"><b>https://google.com'
                '/verify</b></a>')
        anchors = extract_anchors_from_html(html)
        assert anchors == [("https://google.com/verify", "https://google.com/verify")]

    def test_subdomain_display_consistent_with_href(self):
        """Displayed 'google.com/verify' for href on mail.google.com is the
        same site — not a mismatch."""
        findings = URLAnalyzer().analyze(
            ["https://mail.google.com/verify"],
            anchors=[("https://mail.google.com/verify", "google.com/verify")],
        )
        assert "URL_VISIBLE_LINK_MISMATCH" not in _rules(findings)

    def test_relative_href_ignored(self):
        """Relative hrefs are not URL claims; never a mismatch."""
        findings = URLAnalyzer().analyze(
            ["/reset"],
            anchors=[("/reset", "Reset your password")],
        )
        assert "URL_VISIBLE_LINK_MISMATCH" not in _rules(findings)

    def test_multiple_anchors_one_mismatch(self):
        html = (
            '<a href="https://good.example.com/a">https://good.example.com/a</a>'
            '<a href="https://evil.example/login">https://google.com/login</a>'
        )
        anchors = extract_anchors_from_html(html)
        findings = URLAnalyzer().analyze(
            ["https://good.example.com/a", "https://evil.example/login"],
            anchors=anchors,
        )
        mismatches = [f for f in findings
                      if f.rule_id == "URL_VISIBLE_LINK_MISMATCH"]
        assert len(mismatches) == 1
        assert "evil.example" in mismatches[0].evidence

    def test_mismatch_carries_high_severity(self):
        findings = URLAnalyzer().analyze(
            ["https://evil-login.example/verify"],
            anchors=[("https://evil-login.example/verify",
                      "https://google.com/verify")],
        )
        f = [x for x in findings if x.rule_id == "URL_VISIBLE_LINK_MISMATCH"][0]
        assert f.severity == "HIGH"


# ───────────────────────────── F-4 ─────────────────────────────

class TestF4PunycodeHomoglyph:
    def test_decode_pple(self):
        decoded = decode_punycode_domain("xn--pple-43d.example")
        assert decoded is not None
        assert decoded.endswith(".example")

    def test_pple_detected_as_apple(self):
        assert detect_punycode_brand_lookalike("xn--pple-43d.example") == "apple"

    def test_all_cyrillic_apple_detected(self):
        # xn--80ak6aa92e.com = "аррӏе.com" (the famous Apple homoglyph).
        assert detect_punycode_brand_lookalike("xn--80ak6aa92e.com") == "apple"

    def test_malformed_punycode_fails_safely(self):
        for domain in ("xn--!!!.example", "xn--", "xn--.com"):
            assert decode_punycode_domain(domain) is None
            assert detect_punycode_brand_lookalike(domain) is None

    def test_normal_domain_untouched(self):
        assert decode_punycode_domain("example.com") is None
        assert detect_punycode_brand_lookalike("example.com") is None
        assert detect_punycode_brand_lookalike("microsoft-0nline.com") is None

    def test_legitimate_idn_not_flagged(self):
        """xn--mnchen-3ya.de = münchen.de — a real German IDN."""
        assert detect_punycode_brand_lookalike("xn--mnchen-3ya.de") is None
        findings = URLAnalyzer().analyze(["https://xn--mnchen-3ya.de/contact"])
        assert "URL_PUNYCODE_HOMOGLYPH" not in _rules(findings)

    def test_full_analyzer_produces_dedicated_finding(self):
        findings = URLAnalyzer().analyze(["https://xn--pple-43d.example/login"])
        assert "URL_PUNYCODE_HOMOGLYPH" in _rules(findings)

    def test_survives_detection_engine_path(self):
        """Punycode detection must survive the full DetectionEngine path."""
        parsed = _parsed_from_eml(_make_eml(
            '<a href="https://xn--pple-43d.example/login">Sign in</a>',
            from_addr="security@xn--pple-43d.example",
        ))
        results = _engine_results(parsed)
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "URL_PUNYCODE_HOMOGLYPH" in rule_ids, rule_ids


# ───────────────────────────── F-5 ─────────────────────────────

class TestF5AuthNormalization:
    # — parser unit tests —

    @pytest.mark.parametrize("token,mech,expected", [
        ("spf=softfail", "spf", "softfail"),
        ("spf=fail", "spf", "fail"),
        ("spf=pass", "spf", "pass"),
        ("spf=neutral", "spf", "neutral"),
        ("spf=none", "spf", "none"),
        ("spf=temperror", "spf", "temperror"),
        ("spf=permerror", "spf", "permerror"),
        ("dkim=none", "dkim", "none"),
        ("dkim=fail", "dkim", "fail"),
        ("dkim=pass", "dkim", "pass"),
        ("dmarc=none", "dmarc", "none"),
        ("dmarc=fail", "dmarc", "fail"),
        ("dmarc=pass", "dmarc", "pass"),
    ])
    def test_individual_verdicts(self, token, mech, expected):
        assert normalize_auth_result(token)[mech] == expected

    def test_combined_header_distinct_states(self):
        result = normalize_auth_result(
            "mx.example.com; spf=softfail dkim=none dmarc=none")
        assert result == {"spf": "softfail", "dkim": "none", "dmarc": "none"}

    def test_malformed_token_maps_to_unknown(self):
        result = normalize_auth_result("spf=bananas dkim=pass")
        assert result["spf"] == "unknown"
        assert result["dkim"] == "pass"

    def test_empty_header(self):
        assert normalize_auth_result("") == {
            "spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    # — end-to-end parser tests —

    def test_eml_softfail_preserved(self):
        parsed = _parsed_from_eml(
            _make_eml("<p>hi</p>", "mx.example.com; spf=softfail dkim=none dmarc=none"))
        assert parsed.spf_result == "softfail"
        assert parsed.dkim_result == "none"
        assert parsed.dmarc_result == "none"

    def test_eml_fail_preserved(self):
        parsed = _parsed_from_eml(
            _make_eml("<p>hi</p>", "spf=fail dkim=fail dmarc=fail"))
        assert parsed.spf_result == "fail"
        assert parsed.dkim_result == "fail"
        assert parsed.dmarc_result == "fail"

    # — analyzer-level tests —

    def test_softfail_is_not_fail_finding(self):
        rules = _rules(HeaderAnalyzer().analyze({}, spf_result="softfail"))
        assert "HEADER_SPF_SOFTFAIL" in rules
        assert "HEADER_SPF_FAIL" not in rules

    def test_dkim_none_is_not_fail(self):
        rules = _rules(HeaderAnalyzer().analyze({}, dkim_result="none"))
        assert "HEADER_DKIM_NONE" in rules
        assert "HEADER_DKIM_FAIL" not in rules

    def test_dmarc_none_is_not_fail(self):
        rules = _rules(HeaderAnalyzer().analyze({}, dmarc_result="none"))
        assert "HEADER_DMARC_NONE" in rules
        assert "HEADER_DMARC_FAIL" not in rules

    def test_none_states_not_high_or_critical(self):
        """'none' is informational, never a failure-grade verdict: nothing
        above MEDIUM (DKIM none's pre-existing level), never HIGH/CRITICAL."""
        findings = (HeaderAnalyzer().analyze({}, dkim_result="none") +
                    HeaderAnalyzer().analyze({}, dmarc_result="none") +
                    HeaderAnalyzer().analyze({}, spf_result="none"))
        assert findings, "none states must produce findings"
        assert all(f.severity not in ("HIGH", "CRITICAL") for f in findings)

    def test_auth_results_token_not_miscounted(self):
        """'softfail' must never count as a failure in the auth-results scan."""
        findings = HeaderAnalyzer().analyze(
            {"Authentication-Results": "spf=softfail dkim=none dmarc=none"})
        assert "HEADER_MULTIPLE_AUTH_FAILURES" not in _rules(findings)

    def test_genuine_failures_still_detected(self):
        rules = _rules(HeaderAnalyzer().analyze({}, spf_result="fail",
                                                dkim_result="fail",
                                                dmarc_result="fail"))
        assert {"HEADER_SPF_FAIL", "HEADER_DKIM_FAIL", "HEADER_DMARC_FAIL"} <= set(rules)


# ───────────────────────────── F-6 ─────────────────────────────

class TestF6AuthSeverityFloor:
    def _score(self, findings):
        return RiskScorer().calculate_score(findings)[0]

    def _hf(self, rule_id, points):
        return Finding(rule_id=rule_id, category=Category.HEADER,
                       severity="HIGH", points=points, message="m")

    def test_spf_fail_only_not_disproportionate(self):
        score = self._score([self._hf("HEADER_SPF_FAIL", 8)])
        assert score < 25  # stays SAFE-range: no overreaction

    def test_dkim_fail_only_not_disproportionate(self):
        score = self._score([self._hf("HEADER_DKIM_FAIL", 7)])
        assert score < 25

    def test_dmarc_fail_only_not_disproportionate(self):
        score = self._score([self._hf("HEADER_DMARC_FAIL", 8)])
        assert score < 25

    def test_spf_plus_dkim_not_floor(self):
        score = self._score([self._hf("HEADER_SPF_FAIL", 8),
                             self._hf("HEADER_DKIM_FAIL", 7)])
        assert score < 50  # floor requires the strong combination

    def test_all_three_fail_cannot_be_safe(self):
        """E: the classic all-fail combination must clear the HEADER cap via
        the composite floor and never classify SAFE."""
        score = self._score([
            self._hf("HEADER_SPF_FAIL", 8),
            self._hf("HEADER_DKIM_FAIL", 7),
            self._hf("HEADER_DMARC_FAIL", 8),
            self._hf("HEADER_MULTIPLE_AUTH_FAILURES", 10),
        ])
        assert score >= 50  # >= SUSPICIOUS boundary

    def test_floor_never_exceeds_raw_score(self):
        """The floor only RAISES scores; strong other-category evidence must
        keep its full contribution (floor never lowers)."""
        findings = [
            self._hf("HEADER_SPF_FAIL", 8),
            self._hf("HEADER_DKIM_FAIL", 7),
            self._hf("HEADER_DMARC_FAIL", 8),
            Finding(rule_id="SENDER_BRAND_IMPERSONATION", category=Category.SENDER,
                    severity="HIGH", points=15, message="m"),
        ]
        score = self._score(findings)
        # HEADER: 23 raw -> deduped then capped at 20; SENDER: 15 (uncapped).
        # 20 + 15 = 35 < 50 pre-floor, so the floor lifts it to exactly 50:
        # the assertion proves the floor RAISED the score (never lowers it).
        assert score >= 50

    def test_softfail_none_none_not_three_failures(self):
        """F: softfail + none + none must NOT activate the floor."""
        findings = [
            Finding(rule_id="HEADER_SPF_SOFTFAIL", category=Category.HEADER,
                    severity="MEDIUM", points=5, message="m"),
            Finding(rule_id="HEADER_DKIM_NONE", category=Category.HEADER,
                    severity="MEDIUM", points=4, message="m"),
            Finding(rule_id="HEADER_DMARC_NONE", category=Category.HEADER,
                    severity="LOW", points=2, message="m"),
        ]
        score = self._score(findings)
        assert score < 25  # no floor; capped HEADER total only

    def test_floor_respects_100_ceiling(self):
        """The composite floor must not bypass the overall final ceiling."""
        findings = [
            self._hf("HEADER_SPF_FAIL", 8),
            self._hf("HEADER_DKIM_FAIL", 7),
            self._hf("HEADER_DMARC_FAIL", 8),
            self._hf("HEADER_MULTIPLE_AUTH_FAILURES", 10),
            Finding(rule_id="SENDER_BRAND_IMPERSONATION", category=Category.SENDER,
                    severity="HIGH", points=15, message="m"),
            Finding(rule_id="URL_LOOKALIKE_DOMAIN", category=Category.URL,
                    severity="HIGH", points=12, message="m"),
            Finding(rule_id="CONTENT_CREDENTIAL_REQUEST", category=Category.CONTENT,
                    severity="HIGH", points=10, message="m"),
            Finding(rule_id="CORR_CREDENTIAL_PHISHING", category=Category.CORRELATION,
                    severity="CRITICAL", points=15, message="m"),
        ]
        score = self._score(findings)
        assert score <= 100

    def test_engine_all_fail_not_safe(self):
        """End-to-end: three hard failures through the engine cannot be SAFE."""
        parsed = _parsed_from_eml(_make_eml(
            "<p>quarterly report attached</p>",
            auth_header="mx.example.com; spf=fail dkim=fail dmarc=fail",
            from_addr="ceo@spoofed-bank.example",
        ))
        results = _engine_results(parsed)
        assert results["classification"] != "SAFE", (
            f"{results['classification']} ({results['risk_score']})"
        )

    def test_engine_benign_auth_passes_stay_safe(self):
        """Existing benign signals: all-pass authentication keeps a plain
        email safe."""
        parsed = _parsed_from_eml(_make_eml(
            "<p>Lunch on Friday?</p>",
            auth_header="spf=pass dkim=pass dmarc=pass",
        ))
        results = _engine_results(parsed)
        assert results["classification"] in ("SAFE", "LOW RISK")


# ─────────────────── Session 2 regression guard ───────────────────

class TestSession2Regressions:
    @pytest.mark.parametrize("url", [
        "https://google.de",
        "https://google.co.in",
        "https://amazon.de",
        "https://outlook.office.com",
    ])
    def test_regional_domains_still_clean(self, url):
        assert "URL_LOOKALIKE_DOMAIN" not in _rules(URLAnalyzer().analyze([url]))

    def test_brand_cases_unchanged(self):
        from detection.sender import SenderAnalyzer
        sa = SenderAnalyzer()
        # dhl.example: exactly ONE brand finding
        f = sa.analyze("track@dhl.example", "DHL Express", "dhl.example")
        assert _rules(f).count("SENDER_BRAND_IMPERSONATION") == 1
        # google.docs.share.example: no brand/lookalike finding
        r = _rules(sa.analyze("d@google.docs.share.example", "D",
                              "google.docs.share.example"))
        assert "SENDER_BRAND_IMPERSONATION" not in r
        assert "SENDER_LOOKALIKE_DOMAIN" not in r
        # paypai-secure.com: still caught
        assert "SENDER_BRAND_IMPERSONATION" in _rules(
            sa.analyze("a@paypai-secure.com", "PayPal", "paypai-secure.com"))
        # microsoft-0nline.com: still caught (homoglyph or brand)
        r = _rules(sa.analyze("admin@microsoft-0nline.com", "Microsoft Admin",
                              "microsoft-0nline.com"))
        assert "SENDER_HOMOGLYPH" in r or "SENDER_BRAND_IMPERSONATION" in r

    def test_credential_cases_unchanged(self):
        from detection.content_analyzer import ContentAnalyzer
        ca = ContentAnalyzer()
        assert "CONTENT_CREDENTIAL_REQUEST" not in _rules(
            ca.analyze("Your account dashboard has new features."))
        assert "CONTENT_CREDENTIAL_REQUEST" in _rules(
            ca.analyze("Please enter your account password."))

    def test_digit_domain_case_unchanged(self):
        from detection.sender import SenderAnalyzer
        r = _rules(SenderAnalyzer().analyze("x@7-eleven.com", "Co", "7-eleven.com"))
        assert "SENDER_SUSPICIOUS_DOMAIN" not in r
        assert "SENDER_HOMOGLYPH" not in r
