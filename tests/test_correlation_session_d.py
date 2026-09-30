"""
Session D — cross-signal correlation engine tests.

All tests are hermetic: every network seam (RDAP, Safe Browsing HTTP,
TLS probes, DNS/MX) is mocked; the correlation layer itself is purely
offline and consumes findings already produced by the pipeline.

Covers: rules A–H (trigger + no-false-trigger), unknown/failure
semantics, multi-URL isolation, duplicate-evidence dedup, scoring
stability (no inflation, CORRELATION cap, INTEL cap unchanged), and
regression guards for the pre-existing correlation rules.
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from detection.engine import DetectionEngine
from detection.intelligence import tls_intelligence as tls_mod
from detection.intelligence.threat_intel import google_safe_browsing as gsb
from detection.intelligence.domain_intelligence import (
    DomainIntelligence,
    clear_cache as clear_intel_cache,
)
from detection.intelligence.tls_intelligence import (
    clear_cache as clear_tls_cache,
)
from detection.rules import CATEGORY_WEIGHTS


# ── harness ──────────────────────────────────────────────────────────────

YOUNG_RDAP = {
    "events": [{
        "eventAction": "registration",
        "eventDate": (datetime.now(timezone.utc)
                      - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }],
}
OLD_RDAP = {
    "events": [{
        "eventAction": "registration",
        "eventDate": (datetime.now(timezone.utc)
                      - timedelta(days=3000)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }],
}


def _payload(base, state, **meta):
    from detection.intelligence.tls_intelligence import TLSResult
    d = TLSResult(url=base.url, state=state,
                  hostname=base.hostname).to_dict()
    d.update(meta)
    return d


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """Hermetic offline pipeline for every test."""
    clear_intel_cache()
    clear_tls_cache()
    gsb._cache.clear()
    monkeypatch.delenv(gsb.SB_API_KEY_ENV, raising=False)
    monkeypatch.delenv(gsb.SB_ENABLED_ENV, raising=False)
    monkeypatch.setattr(tls_mod, "_network_allowed", False)
    DomainIntelligence._sb_provider = None
    _quiet_dns(monkeypatch)
    yield
    clear_intel_cache()
    clear_tls_cache()
    gsb._cache.clear()
    DomainIntelligence._sb_provider = None


def _quiet_dns(monkeypatch):
    monkeypatch.setattr(DomainIntelligence, "_check_dns_resolution",
                        lambda self, d: True)
    monkeypatch.setattr(DomainIntelligence, "_check_mx_records",
                        lambda self, d: False)


def _mock_tls(monkeypatch, responder):
    def fake(hostname, base):
        payload = responder(hostname, base)
        if payload is not None:
            raise tls_mod._TLSVerdict(payload)
        raise tls_mod._TLSUnavailable()
    monkeypatch.setattr(tls_mod, "_probe_with_socket", fake)
    monkeypatch.setattr(tls_mod, "_network_allowed", True)


def _with_sb(monkeypatch, matches=None, fail=None):
    """Configure SB: confirmed match, or a specific failure mode."""
    monkeypatch.setenv(gsb.SB_API_KEY_ENV, "test-key-not-real")

    def fake_post(api_key, body, timeout):
        if fail == "http500":
            raise RuntimeError("SB_HTTP_500")
        if matches:
            return {"matches": [
                {"threatType": tt,
                 "threat": {"url": body["threatInfo"]["threatEntries"][0]["url"]}}
                for tt in matches]}
        return {}

    monkeypatch.setattr(gsb, "_post_threat_matches", fake_post)


class P:
    """Parsed-email stand-in for direct engine calls."""

    sender_email = "info@phish-sender.com"
    sender_name = "Sender"
    sender_domain = "phish-sender.com"
    urls: list = []
    anchor_text = ""
    body_text = "Hello, please review the attached quarterly summary."
    body_html = ""
    headers: dict = {}
    attachments: list = []
    spf_result = "pass"
    dkim_result = "pass"
    dmarc_result = "pass"
    received_headers: list = []
    message_id = ""
    subject = "Notice"

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def corr_rule_ids(results):
    return [f["rule_id"] for f in results["categorized_findings"]["CORRELATION"]]


def intel_rule_ids(results):
    return [f["rule_id"] for f in results["categorized_findings"]["INTEL"]]


def analyze(**kw):
    return DetectionEngine().analyze(P(**kw))


# ── Rule A: NEW_DOMAIN + CREDENTIAL_REQUEST ─────────────────────────────

class TestRuleANewDomainCredential:
    CRED = ("Please verify your account by providing your password at "
            "https://phish-sender.com/secure-login.")

    def test_triggers(self, monkeypatch):
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: YOUNG_RDAP)
        results = analyze(body_text=self.CRED)
        assert "INTEL_YOUNG_DOMAIN" in intel_rule_ids(results)
        assert "CONTENT_CREDENTIAL_REQUEST" in [
            f["rule_id"] for f in results["findings"]]
        assert "CORR_NEW_DOMAIN_CREDENTIAL_REQUEST" in corr_rule_ids(results)

    def test_no_trigger_when_domain_established(self, monkeypatch):
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: OLD_RDAP)
        results = analyze(body_text=self.CRED)
        assert "INTEL_YOUNG_DOMAIN" not in intel_rule_ids(results)
        assert "CORR_NEW_DOMAIN_CREDENTIAL_REQUEST" not in corr_rule_ids(results)

    def test_no_trigger_without_credential_request(self, monkeypatch):
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: YOUNG_RDAP)
        results = analyze(body_text="Hello, welcome to our quarterly newsletter.")
        assert "CORR_NEW_DOMAIN_CREDENTIAL_REQUEST" not in corr_rule_ids(results)

    def test_no_trigger_when_age_unknown(self, monkeypatch):
        def offline(u, t):
            raise OSError("no network")
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            offline)
        results = analyze(body_text=self.CRED)
        assert "INTEL_YOUNG_DOMAIN" not in intel_rule_ids(results)
        assert "CORR_NEW_DOMAIN_CREDENTIAL_REQUEST" not in corr_rule_ids(results)

    def test_evidence_names_both_signals(self, monkeypatch):
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: YOUNG_RDAP)
        results = analyze(body_text=self.CRED)
        corr = next(f for f in results["findings"]
                    if f["rule_id"] == "CORR_NEW_DOMAIN_CREDENTIAL_REQUEST")
        blob = (corr["evidence"] + " " + corr["explanation"]).lower()
        assert "credential" in blob
        assert "domain" in blob and "recent" in blob
        # Factual, non-verdict wording.
        assert "definitely" not in blob

    def test_rule_b_new_domain_brand(self, monkeypatch):
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: YOUNG_RDAP)
        # 'paypa1-secure' style lookalike on a young domain.
        results = DetectionEngine().analyze(P(
            sender_domain="paypa1-secure.com",
            sender_email="service@paypa1-secure.com",
            body_text="Your account needs attention. Please log in.",
        ))
        assert "CORR_NEW_DOMAIN_BRAND_IMPERSONATION" in corr_rule_ids(results)

    def test_rule_b_no_false_trigger(self, monkeypatch):
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: OLD_RDAP)
        results = analyze(body_text="Welcome to our service. Enjoy!")
        assert "CORR_NEW_DOMAIN_BRAND_IMPERSONATION" not in corr_rule_ids(results)


# ── Rule C: THREAT_INTEL + CREDENTIAL_REQUEST ───────────────────────────

class TestRuleCThreatIntel:

    def test_known_threat_triggers(self, monkeypatch):
        _with_sb(monkeypatch, matches=["SOCIAL_ENGINEERING"])
        results = analyze(body_text="Please confirm your account password.",
                          urls=["https://listed.example/login"])
        assert "INTEL_SAFE_BROWSING_THREAT" in intel_rule_ids(results)
        assert "CORR_THREAT_CREDENTIAL_REQUEST" in corr_rule_ids(results)

    def test_no_match_does_not_trigger(self, monkeypatch):
        _with_sb(monkeypatch, matches=None)
        results = analyze(body_text="Please confirm your account password.",
                          urls=["https://listed.example/login"])
        assert "INTEL_SAFE_BROWSING_THREAT" not in intel_rule_ids(results)
        assert "CORR_THREAT_CREDENTIAL_REQUEST" not in corr_rule_ids(results)

    def test_unavailable_does_not_trigger(self, monkeypatch):
        # no API key -> UNAVAILABLE
        results = analyze(body_text="Please confirm your account password.",
                          urls=["https://listed.example/login"])
        assert "CORR_THREAT_CREDENTIAL_REQUEST" not in corr_rule_ids(results)

    def test_error_does_not_trigger(self, monkeypatch):
        _with_sb(monkeypatch, fail="http500")
        results = analyze(body_text="Please confirm your account password.",
                          urls=["https://listed.example/login"])
        assert "CORR_THREAT_CREDENTIAL_REQUEST" not in corr_rule_ids(results)


# ── Rule D: SHORTENER + CREDENTIAL_REQUEST ──────────────────────────────

class TestRuleDShortener:

    def test_triggers(self, monkeypatch):
        # Wording that independently produces CONTENT_CREDENTIAL_REQUEST
        # (verified against the content analyzer) plus a shortener URL.
        results = analyze(
            body_text="Please provide your account password: https://bit.ly/reset-now",
            urls=["https://bit.ly/reset-now"],
        )
        assert "CONTENT_CREDENTIAL_REQUEST" in [
            f["rule_id"] for f in results["findings"]]
        assert "URL_SHORTENER" in [f["rule_id"] for f in results["findings"]]
        assert "CORR_SHORTENER_CREDENTIAL_REQUEST" in corr_rule_ids(results)

    def test_no_false_trigger_without_shortener(self, monkeypatch):
        results = analyze(
            body_text="Please provide your account password: https://example.com/reset",
            urls=["https://example.com/reset"],
        )
        assert "CORR_SHORTENER_CREDENTIAL_REQUEST" not in corr_rule_ids(results)

    def test_no_false_trigger_without_credential(self, monkeypatch):
        results = analyze(
            body_text="Read the article: https://bit.ly/news",
            urls=["https://bit.ly/news"],
        )
        assert "CORR_SHORTENER_CREDENTIAL_REQUEST" not in corr_rule_ids(results)


# ── Rule E: BRAND + URL_DECEPTION + CREDENTIAL ──────────────────────────

class TestRuleEBrandUrlDeception:

    def test_triggers_with_all_three(self, monkeypatch):
        # F-3 mismatch evidence comes from the parser's (href, visible)
        # pairs — the displayed URL points at a different site than the
        # actual href on the impersonation domain.
        results = DetectionEngine().analyze(P(
            sender_domain="paypa1-secure.com",
            sender_email="service@paypa1-secure.com",
            urls=["http://paypa1-secure.com/login"],
            anchors=[("http://paypa1-secure.com/login",
                      "https://paypal.com/wallet")],
            body_text="Please provide your account password to continue.",
        ))
        assert "URL_VISIBLE_LINK_MISMATCH" in [
            f["rule_id"] for f in results["findings"]]
        assert "CORR_BRAND_URL_CREDENTIAL" in corr_rule_ids(results)

    def test_no_trigger_without_url_deception(self, monkeypatch):
        results = DetectionEngine().analyze(P(
            sender_domain="paypa1-secure.com",
            sender_email="service@paypa1-secure.com",
            urls=["https://paypa1-secure.com/login"],
            anchors=[("https://paypa1-secure.com/login",
                      "https://paypa1-secure.com/login")],
            body_text="Please provide your account password to continue.",
        ))
        assert "CORR_BRAND_URL_CREDENTIAL" not in corr_rule_ids(results)

    def test_no_trigger_without_brand(self, monkeypatch):
        results = DetectionEngine().analyze(P(
            sender_domain="plain-company.com",
            sender_email="news@plain-company.com",
            urls=["http://plain-company.com/signin"],
            anchors=[("http://plain-company.com/signin",
                      "https://some-other-site.com/account")],
            body_text="Please provide your account password to continue.",
        ))
        assert "CORR_BRAND_URL_CREDENTIAL" not in corr_rule_ids(results)


# ── Rule F: AUTH hard failure + CREDENTIAL_REQUEST ──────────────────────

class TestRuleFAuthCredential:
    CRED = "Please provide your account password to verify your identity."

    def test_hard_failure_triggers(self, monkeypatch):
        results = analyze(body_text=self.CRED,
                          spf_result="fail", dkim_result="fail",
                          dmarc_result="fail")
        assert "HEADER_DMARC_FAIL" in [f["rule_id"] for f in results["findings"]]
        assert "CORR_AUTH_CREDENTIAL_REQUEST" in corr_rule_ids(results)

    def test_pass_does_not_trigger(self, monkeypatch):
        results = analyze(body_text=self.CRED,
                          spf_result="pass", dkim_result="pass",
                          dmarc_result="pass")
        assert "CORR_AUTH_CREDENTIAL_REQUEST" not in corr_rule_ids(results)

    @pytest.mark.parametrize("state", [
        ("softfail", "none", "none"),
        ("none", "none", "none"),
        ("neutral", "neutral", "neutral"),
    ])
    def test_weak_states_do_not_trigger(self, monkeypatch, state):
        spf, dkim, dmarc = state
        results = analyze(body_text=self.CRED,
                          spf_result=spf, dkim_result=dkim,
                          dmarc_result=dmarc)
        hard_fails = {"HEADER_SPF_FAIL", "HEADER_DKIM_FAIL", "HEADER_DMARC_FAIL"}
        assert not (hard_fails & {f["rule_id"] for f in results["findings"]})
        assert "CORR_AUTH_CREDENTIAL_REQUEST" not in corr_rule_ids(results)


# ── Rule G: TLS anomaly + CREDENTIAL_REQUEST ────────────────────────────

class TestRuleGTlsCredential:
    CRED = "Please enter your account credentials to continue."

    def _run(self, monkeypatch, state):
        if state is None:
            _mock_tls(monkeypatch, lambda h, b: None)  # unreachable host
        else:
            _mock_tls(monkeypatch,
                      lambda h, b: _payload(b, state))
        return analyze(
            body_text=self.CRED + " https://auth-portal.example.com/signin",
            urls=["https://auth-portal.example.com/signin"],
        )

    @pytest.mark.parametrize("state", ["TLS_EXPIRED",
                                       "TLS_HOSTNAME_MISMATCH",
                                       "TLS_INVALID"])
    def test_anomalies_trigger(self, monkeypatch, state):
        results = self._run(monkeypatch, state)
        assert f"INTEL_{state}" in intel_rule_ids(results)
        assert "CORR_TLS_CREDENTIAL_REQUEST" in corr_rule_ids(results)

    @pytest.mark.parametrize("state", ["TLS_VALID", "HTTP",
                                       "TLS_UNAVAILABLE", "TLS_ERROR"])
    def test_non_anomalies_do_not_trigger(self, monkeypatch, state):
        results = self._run(monkeypatch, state)
        assert "CORR_TLS_CREDENTIAL_REQUEST" not in corr_rule_ids(results)

    def test_factual_language(self, monkeypatch):
        results = self._run(monkeypatch, "TLS_EXPIRED")
        corr = next(f for f in results["findings"]
                    if f["rule_id"] == "CORR_TLS_CREDENTIAL_REQUEST")
        blob = (corr["message"] + corr["evidence"]
                + corr["explanation"]).lower()
        assert "expired" in blob
        # Factual: names the state, explicitly avoids safety claims, and
        # never calls the site phishing.
        assert "not evidence of safety" in blob
        assert "phishing" not in blob
        assert "definitely" not in blob


# ── Composite: NEW_DOMAIN + BRAND + CREDENTIAL ──────────────────────────

class TestCompositeNewDomainBrandCredential:

    def test_three_way_triggers(self, monkeypatch):
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: YOUNG_RDAP)
        results = DetectionEngine().analyze(P(
            sender_domain="paypa1-secure.com",
            sender_email="service@paypa1-secure.com",
            body_text="Please provide your account password immediately.",
        ))
        ids = corr_rule_ids(results)
        assert "CORR_NEW_DOMAIN_CREDENTIAL_REQUEST" in ids
        assert "CORR_NEW_DOMAIN_BRAND_IMPERSONATION" in ids
        assert "CORR_NEW_DOMAIN_BRAND_CREDENTIAL" in ids

    def test_composite_names_all_three_signals(self, monkeypatch):
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: YOUNG_RDAP)
        results = DetectionEngine().analyze(P(
            sender_domain="paypa1-secure.com",
            sender_email="service@paypa1-secure.com",
            body_text="Please provide your account password immediately.",
        ))
        corr = next(f for f in results["findings"]
                    if f["rule_id"] == "CORR_NEW_DOMAIN_BRAND_CREDENTIAL")
        blob = (corr["evidence"] + " " + corr["explanation"]).lower()
        for token in ("credential", "brand", "recent"):
            assert token in blob


# ── Multi-URL isolation & duplicate evidence ────────────────────────────

class TestMultiUrlIsolationAndDedup:

    def test_dedup_same_url_twice_single_correlation(self, monkeypatch):
        _with_sb(monkeypatch, matches=["MALWARE"])
        url = "https://evil.example/login"
        results = DetectionEngine().analyze(P(
            urls=[url, url, url + "#frag"],
            body_text="Please confirm your account password.",
        ))
        count = corr_rule_ids(results).count("CORR_THREAT_CREDENTIAL_REQUEST")
        assert count == 1

    def test_unrelated_second_url_does_not_break_correlation(self, monkeypatch):
        _with_sb(monkeypatch, matches=["MALWARE"])
        results = DetectionEngine().analyze(P(
            urls=["https://evil.example/login", "https://good.example/docs"],
            body_text="Please confirm your account password.",
        ))
        assert "CORR_THREAT_CREDENTIAL_REQUEST" in corr_rule_ids(results)


# ── Scoring: stability, caps, no inflation ──────────────────────────────

class TestScoringStability:

    def _capped_contributions(self, findings):
        subtotals = {}
        for f in findings:
            subtotals[f["category"]] = (subtotals.get(f["category"], 0.0)
                                        + f["points"])
        capped = {k: max(min(v, CATEGORY_WEIGHTS.get(k, 5)), -5)
                  for k, v in subtotals.items()}
        return subtotals, capped

    def test_correlation_fits_correlation_cap(self, monkeypatch):
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: YOUNG_RDAP)
        results = DetectionEngine().analyze(P(
            sender_domain="paypa1-secure.com",
            sender_email="service@paypa1-secure.com",
            body_text="Please provide your account password immediately.",
        ))
        # Every correlation rule fires (A, B, composite): still bounded.
        assert len(corr_rule_ids(results)) >= 3
        _, capped = self._capped_contributions(results["findings"])
        assert capped.get("CORRELATION", 0) <= CATEGORY_WEIGHTS["CORRELATION"]
        assert capped.get("INTEL", 0) <= CATEGORY_WEIGHTS["INTEL"]
        # And the engine total equals the capped math (clamped).
        clamped = max(0.0, min(sum(capped.values()), 100.0))
        assert abs(clamped - results["risk_score"]) < 1e-9

    def test_correlation_reproduces_engine_score(self, monkeypatch):
        _with_sb(monkeypatch, matches=["SOCIAL_ENGINEERING"])
        results = analyze(body_text="Please confirm your account password.")
        subtotals, capped = self._capped_contributions(results["findings"])
        clamped = max(0.0, min(sum(capped.values()), 100.0))
        assert abs(clamped - results["risk_score"]) < 1e-9

    def test_duplicate_signal_scores_once(self, monkeypatch):
        """Same email twice: score is deterministic, not compounded."""
        _with_sb(monkeypatch, matches=["MALWARE"])
        kw = dict(body_text="Please confirm your account password.",
                  urls=["https://evil.example/x"])
        r1 = DetectionEngine().analyze(P(**kw))
        r2 = DetectionEngine().analyze(P(**kw))
        assert r1["risk_score"] == r2["risk_score"]

    def test_intel_cap_with_all_sources_and_correlation(self, monkeypatch):
        """SB + young domain + TLS anomaly + correlations: INTEL cap holds."""
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: YOUNG_RDAP)
        _with_sb(monkeypatch, matches=["MALWARE"])
        _mock_tls(monkeypatch,
                  lambda h, b: _payload(b, "TLS_HOSTNAME_MISMATCH"))
        results = DetectionEngine().analyze(P(
            sender_domain="paypa1-secure.com",
            sender_email="service@paypa1-secure.com",
            urls=["https://paypa1-secure.com/login"],
            body_text="Please provide your account password immediately.",
        ))
        raw_intel = sum(f["points"] for f in results["categorized_findings"]["INTEL"])
        assert raw_intel >= 20  # 10 SB + 8 age + 4 TLS (setup sanity)
        _, capped = self._capped_contributions(results["findings"])
        assert capped["INTEL"] == CATEGORY_WEIGHTS["INTEL"]  # 5, unchanged

    def test_correlation_alone_cannot_make_high_risk(self, monkeypatch):
        """Benign message + young domain: correlation adds bounded evidence."""
        monkeypatch.setattr("detection.intelligence.domain_age._http_get_json",
                            lambda u, t: YOUNG_RDAP)
        results = analyze(body_text="Check out our new site, hello!")
        assert results["classification"] != "HIGH_RISK"


# ── Regression: pre-existing correlation rules unaffected ───────────────

class TestPreExistingCorrelationRegression:

    def test_urgency_credential_still_works(self):
        results = analyze(body_text="URGENT: verify your password now or your "
                                    "account will be suspended.")
        assert "CORR_URGENCY_CREDENTIAL" in corr_rule_ids(results)

    def test_spoofed_phishing_still_works(self):
        # CORR_SPOOFED_PHISHING requires a SENDER anomaly: Reply-To pointing
        # at an unrelated domain (verified against the sender analyzer).
        results = DetectionEngine().analyze(P(
            body_text="Please provide your account password.",
            headers={"Reply-To": "scammer@totally-different.com"},
            spf_result="fail", dkim_result="fail", dmarc_result="fail",
        ))
        assert "CORR_SPOOFED_PHISHING" in corr_rule_ids(results)

    def test_legitimate_signals_still_work(self):
        # CORR_LEGITIMATE_SIGNALS requires a SENDER-category finding plus
        # all-pass auth and no suspicious content; a benign domain with a
        # structural anomaly supplies the sender finding without tainting
        # the legitimacy signal (F-13: 5+ digit runs are structural noise).
        results = DetectionEngine().analyze(P(
            sender_domain="updates-123456.com",
            sender_email="news@updates-123456.com",
            body_text="Thanks for attending the meeting yesterday.",
            spf_result="pass", dkim_result="pass", dmarc_result="pass",
        ))
        assert "CORR_LEGITIMATE_SIGNALS" in corr_rule_ids(results)

    def test_f10_single_owner_marker_still_present(self):
        results = analyze(body_text="URGENT: verify your password now.")
        zero_markers = [f for f in results["findings"]
                        if f["rule_id"] == "CONTENT_URGENCY_CREDENTIAL_COMBO"]
        assert zero_markers and all(f["points"] == 0 for f in zero_markers)
