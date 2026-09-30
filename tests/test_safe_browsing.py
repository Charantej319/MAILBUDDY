"""
Session B — Google Safe Browsing threat intelligence tests.

All tests are hermetic: the HTTP boundary (_post_threat_matches) is
mocked; no test ever contacts Google. The suite-wide conftest gate
additionally blocks real network access.

Covers the 26 required cases: the four provider states, all supported
threat types, unknown types, HTTP error classes, timeout/connection
failures, malformed responses, caching (hit/expiry/dedup), URL
normalization, privacy (no email metadata, no key leakage), engine
integration (finding produced, cap enforced, failure never raises risk),
and unchanged deterministic URL analysis.
"""

import json
from unittest.mock import patch

import pytest

from detection.intelligence.threat_intel import base as ti_base
from detection.intelligence.threat_intel.base import ThreatStatus
from detection.intelligence.threat_intel import google_safe_browsing as gsb
from detection.intelligence.threat_intel.google_safe_browsing import (
    GoogleSafeBrowsingProvider,
    SB_API_KEY_ENV,
    SB_ENABLED_ENV,
    clear_cache,
    normalize_url,
)
from detection.intelligence.domain_intelligence import (
    DomainIntelligence,
    clear_cache as clear_intel_cache,
)


API_KEY = "test-key-not-real"  # test fixture value, never a real key


# ── fixtures / helpers ───────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """Hermetic isolation: no real network, no caches, no dev config."""
    clear_cache()
    clear_intel_cache()
    monkeypatch.delenv(SB_API_KEY_ENV, raising=False)
    monkeypatch.delenv(SB_ENABLED_ENV, raising=False)
    DomainIntelligence._sb_provider = None
    yield
    clear_cache()
    clear_intel_cache()
    DomainIntelligence._sb_provider = None


def _with_key(monkeypatch, enabled="true"):
    monkeypatch.setenv(SB_API_KEY_ENV, API_KEY)
    if enabled is not None:
        monkeypatch.setenv(SB_ENABLED_ENV, enabled)


def _mock_http(monkeypatch, responder):
    """Patch the HTTP boundary; returns the recorded call log."""
    calls = []

    def _fake(api_key, body, timeout):
        calls.append({"api_key": api_key, "body": body, "timeout": timeout})
        return responder(api_key, body, timeout)

    monkeypatch.setattr(gsb, "_post_threat_matches", _fake)
    return calls


def _sb_response(*matches):
    return {"matches": list(matches)} if matches else {}


def _match(threat_type="MALWARE", url="http://evil.example/payload"):
    return {
        "threatType": threat_type,
        "platformType": "ANY_PLATFORM",
        "threat": {"url": url},
        "cacheDuration": "300s",
    }


def _quiet_dns(monkeypatch):
    monkeypatch.setattr(DomainIntelligence, "_check_dns_resolution",
                        lambda self, d: True)
    monkeypatch.setattr(DomainIntelligence, "_check_mx_records",
                        lambda self, d: False)


# ── URL normalization ────────────────────────────────────────────────────

class TestNormalization:

    @pytest.mark.parametrize("raw,expected", [
        ("HTTPS://EXAMPLE.com/Path", "https://example.com/Path"),
        ("http://example.com:80/x", "http://example.com/x"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        ("https://example.com/a#anchor", "https://example.com/a"),
        ("https://example.com", "https://example.com/"),
        ("  https://example.com/a  ", "https://example.com/a"),
    ])
    def test_normalization(self, raw, expected):
        assert normalize_url(raw) == expected

    @pytest.mark.parametrize("bad", [
        "", "   ", None, "not-a-url", "ftp://example.com/file",
        "javascript:alert(1)", "http://", "https://", 12345,
        "http://user:pass@example.com/x", "http://x:badport/",
        "https://example.com/" + "a" * 3000,
    ])
    def test_malformed_never_normalize(self, bad):
        assert normalize_url(bad) is None


# ── provider states ──────────────────────────────────────────────────────

class TestProviderStates:

    def test_missing_key_is_unavailable(self, monkeypatch):
        # no key configured
        result = GoogleSafeBrowsingProvider().check_url("https://example.com/x")
        assert result.status == ThreatStatus.UNAVAILABLE
        assert result.error == "MISSING_API_KEY"
        assert result.available is False

    def test_disabled_provider_is_unavailable(self, monkeypatch):
        _with_key(monkeypatch, enabled="false")
        result = GoogleSafeBrowsingProvider().check_url("https://example.com/x")
        assert result.status == ThreatStatus.UNAVAILABLE
        assert result.error == "PROVIDER_DISABLED"

    def test_disabled_false_string_variants(self, monkeypatch):
        for off in ("0", "no", "off", "FALSE"):
            monkeypatch.setenv(SB_ENABLED_ENV, off)
            monkeypatch.setenv(SB_API_KEY_ENV, API_KEY)
            result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
            assert result.status == ThreatStatus.UNAVAILABLE, off

    def test_no_match(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch, lambda k, b, t: {})
        result = GoogleSafeBrowsingProvider().check_url("https://example.com/ok")
        assert result.status == ThreatStatus.NO_MATCH
        assert result.available is True
        assert result.threat_types == ()

    def test_known_threat_malware(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch, lambda k, b, t: _sb_response(_match("MALWARE")))
        result = GoogleSafeBrowsingProvider().check_url("https://evil.example/payload")
        assert result.status == ThreatStatus.KNOWN_THREAT
        assert result.threat_types == ("MALWARE",)
        assert result.available is True

    def test_known_threat_social_engineering(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: _sb_response(_match("SOCIAL_ENGINEERING")))
        result = GoogleSafeBrowsingProvider().check_url("https://evil.example/login")
        assert result.status == ThreatStatus.KNOWN_THREAT
        assert result.threat_types == ("SOCIAL_ENGINEERING",)

    def test_known_threat_unwanted_software(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: _sb_response(_match("UNWANTED_SOFTWARE")))
        result = GoogleSafeBrowsingProvider().check_url("https://evil.example/setup.exe")
        assert result.status == ThreatStatus.KNOWN_THREAT
        assert result.threat_types == ("UNWANTED_SOFTWARE",)

    def test_known_threat_harmful_application(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: _sb_response(
                       _match("POTENTIALLY_HARMFUL_APPLICATION")))
        result = GoogleSafeBrowsingProvider().check_url("https://evil.example/app.apk")
        assert result.status == ThreatStatus.KNOWN_THREAT
        assert result.threat_types == ("POTENTIALLY_HARMFUL_APPLICATION",)

    def test_known_threat_multiple_types(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch, lambda k, b, t: _sb_response(
            _match("MALWARE"), _match("SOCIAL_ENGINEERING")))
        result = GoogleSafeBrowsingProvider().check_url("https://evil.example/x")
        assert result.status == ThreatStatus.KNOWN_THREAT
        assert set(result.threat_types) == {"MALWARE", "SOCIAL_ENGINEERING"}

    def test_unknown_threat_type_preserved(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch, lambda k, b, t: _sb_response(
            _match("SOME_FUTURE_THREAT_TYPE")))
        result = GoogleSafeBrowsingProvider().check_url("https://evil.example/x")
        # Not collapsed, not silently safe, not a crash.
        assert result.status == ThreatStatus.KNOWN_THREAT
        assert result.threat_types == ("SOME_FUTURE_THREAT_TYPE",)


# ── error handling ───────────────────────────────────────────────────────

class TestErrorHandling:

    def test_http_400(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: (_ for _ in ()).throw(RuntimeError("SB_HTTP_400")))
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
        assert result.status == ThreatStatus.ERROR
        assert result.error == "HTTP_400_BAD_REQUEST"

    @pytest.mark.parametrize("code", ["401", "403"])
    def test_http_auth(self, monkeypatch, code):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: (_ for _ in ()).throw(RuntimeError(f"SB_HTTP_{code}")))
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
        assert result.status == ThreatStatus.ERROR
        assert result.error == "HTTP_AUTH_FORBIDDEN"

    def test_http_429(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: (_ for _ in ()).throw(RuntimeError("SB_HTTP_429")))
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
        assert result.status == ThreatStatus.ERROR
        assert result.error == "HTTP_RATE_LIMITED"

    def test_http_500(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: (_ for _ in ()).throw(RuntimeError("SB_HTTP_500")))
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
        assert result.status == ThreatStatus.ERROR
        assert result.error == "HTTP_SERVER_ERROR"

    def test_timeout(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: (_ for _ in ()).throw(TimeoutError()))
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
        assert result.status == ThreatStatus.ERROR
        assert result.error == "TIMEOUT"

    def test_connection_failure(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: (_ for _ in ()).throw(RuntimeError("SB_CONNECTION_FAILURE")))
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
        assert result.status == ThreatStatus.ERROR
        assert result.error == "CONNECTION_FAILURE"

    def test_malformed_json(self, monkeypatch):
        _with_key(monkeypatch)
        def boom(k, b, t):
            raise gsb.json.JSONDecodeError("Expecting value", "{", 0)
        _mock_http(monkeypatch, boom)
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
        assert result.status == ThreatStatus.ERROR
        assert result.error == "MALFORMED_RESPONSE"

    def test_malformed_schema(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch, lambda k, b, t: ["not", "a", "dict"])
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
        assert result.status == ThreatStatus.ERROR
        assert result.error == "MALFORMED_RESPONSE"

    def test_malformed_url_is_error_not_crash(self, monkeypatch):
        _with_key(monkeypatch)
        calls = _mock_http(monkeypatch, lambda k, b, t: {})
        result = GoogleSafeBrowsingProvider().check_url("not a url")
        assert result.status == ThreatStatus.ERROR
        assert result.error == "MALFORMED_URL"
        assert not calls, "unusable URL must never reach the HTTP layer"

    def test_unexpected_exception_classified(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: (_ for _ in ()).throw(ValueError("weird")))
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
        assert result.status == ThreatStatus.ERROR
        assert result.error in ("MALFORMED_RESPONSE", "REQUEST_FAILED")


# ── request shape / privacy / security ───────────────────────────────────

class TestRequestSecurityAndPrivacy:

    def test_request_contains_only_the_url(self, monkeypatch):
        _with_key(monkeypatch)
        calls = _mock_http(monkeypatch, lambda k, b, t: {})
        GoogleSafeBrowsingProvider().check_url("https://example.com/page")
        body = calls[0]["body"]
        entries = body["threatInfo"]["threatEntries"]
        assert entries == [{"url": "https://example.com/page"}]
        # No email metadata anywhere in the request body.
        blob = json.dumps(body)
        for forbidden in ("sender", "recipient", "subject", "body",
                          "attachment", "headers", "account"):
            assert forbidden not in blob

    def test_timeout_is_strict(self, monkeypatch):
        _with_key(monkeypatch)
        calls = _mock_http(monkeypatch, lambda k, b, t: {})
        GoogleSafeBrowsingProvider().check_url("https://example.com/page")
        assert calls[0]["timeout"] == gsb.SB_TIMEOUT_SECONDS
        assert gsb.SB_TIMEOUT_SECONDS <= 5.0

    def test_no_redirects_configuration(self, monkeypatch):
        """The HTTP seam is built to refuse redirects (structural check)."""
        _with_key(monkeypatch)
        # Structural: the module-level _NoRedirects handler aborts any 3xx.
        assert hasattr(gsb, "_NoRedirects"), "redirect-disabling handler must exist"
        assert gsb._NoRedirects.redirect_request(
            None, None, 301, "moved", {}, "http://evil/", "http://evil/finally") is None
        assert gsb._NoRedirects.redirect_request(
            None, None, 302, "found", {}, "https://a.example/x",
            "https://attacker.example/") is None

    def test_https_only_endpoint(self):
        # The endpoint construction is internal; verify via source contract:
        # the only URL constant in the module is HTTPS.
        import inspect
        src = inspect.getsource(gsb._post_threat_matches)
        assert "https://safebrowsing.googleapis.com" in src
        assert "http://" not in src.replace("https://", "")

    def test_api_key_never_in_errors_or_results(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: (_ for _ in ()).throw(RuntimeError("SB_HTTP_403")))
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/secret-path")
        assert API_KEY not in result.error
        assert API_KEY not in result.to_dict().__str__()

    def test_error_classifications_are_fixed_strings(self, monkeypatch):
        """Errors are stable classifications, never raw exception text."""
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: (_ for _ in ()).throw(
                       RuntimeError("secret internal detail with key=abc")))
        result = GoogleSafeBrowsingProvider().check_url("https://e.com/")
        assert result.error == "REQUEST_FAILED"
        assert "secret" not in result.error and "abc" not in result.error


# ── caching ──────────────────────────────────────────────────────────────

class TestCaching:

    def test_cache_hit_prevents_second_request(self, monkeypatch):
        _with_key(monkeypatch)
        calls = _mock_http(monkeypatch, lambda k, b, t: {})
        GoogleSafeBrowsingProvider().check_url("https://e.com/once")
        GoogleSafeBrowsingProvider().check_url("https://e.com/once")
        assert len(calls) == 1

    def test_duplicate_url_prevention_across_variants(self, monkeypatch):
        """Same normalized URL via different spellings = one request."""
        _with_key(monkeypatch)
        calls = _mock_http(monkeypatch, lambda k, b, t: {})
        p = GoogleSafeBrowsingProvider()
        p.check_url("https://e.com/dup")
        p.check_url("https://E.com/dup#frag")
        assert len(calls) == 1

    def test_cache_expiry(self, monkeypatch):
        _with_key(monkeypatch)
        calls = _mock_http(monkeypatch, lambda k, b, t: {})
        GoogleSafeBrowsingProvider().check_url("https://e.com/exp")
        # Force the timestamp into the past beyond every TTL.
        for entry in gsb._cache.values():
            entry["ts"] -= 7000.0
        GoogleSafeBrowsingProvider().check_url("https://e.com/exp")
        assert len(calls) == 2

    def test_error_state_negative_cached(self, monkeypatch):
        _with_key(monkeypatch)
        calls = _mock_http(monkeypatch,
                           lambda k, b, t: (_ for _ in ()).throw(RuntimeError("SB_HTTP_500")))
        GoogleSafeBrowsingProvider().check_url("https://e.com/err")
        n = len(calls)
        GoogleSafeBrowsingProvider().check_url("https://e.com/err")
        assert len(calls) == n  # served from negative cache

    def test_distinct_urls_cached_separately(self, monkeypatch):
        _with_key(monkeypatch)
        calls = _mock_http(monkeypatch, lambda k, b, t: {})
        GoogleSafeBrowsingProvider().check_url("https://e.com/a")
        GoogleSafeBrowsingProvider().check_url("https://e.com/b")
        assert len(calls) == 2


# ── DomainIntelligence integration ───────────────────────────────────────

class TestDomainIntelligenceIntegration:

    def test_structured_result_and_finding(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: _sb_response(_match("SOCIAL_ENGINEERING")))
        _quiet_dns(monkeypatch)
        intel = DomainIntelligence().analyze(
            "sender-domain.com", urls=["http://evil.example/login"])
        assert intel["safe_browsing"][0]["status"] == "KNOWN_THREAT"
        rule_ids = [f.rule_id for f in intel["findings"]]
        assert "INTEL_SAFE_BROWSING_THREAT" in rule_ids
        finding = next(f for f in intel["findings"]
                       if f.rule_id == "INTEL_SAFE_BROWSING_THREAT")
        assert finding.points == 10
        assert finding.category.value == "INTEL"
        assert "SOCIAL_ENGINEERING" in finding.message

    def test_no_match_creates_no_finding(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch, lambda k, b, t: {})
        _quiet_dns(monkeypatch)
        intel = DomainIntelligence().analyze(
            "sender-domain.com", urls=["https://fine.example/ok"])
        rule_ids = [f.rule_id for f in intel["findings"]]
        assert "INTEL_SAFE_BROWSING_THREAT" not in rule_ids
        assert intel["safe_browsing"][0]["status"] == "NO_MATCH"

    def test_unavailable_creates_no_finding(self, monkeypatch):
        # no key configured at all
        _quiet_dns(monkeypatch)
        intel = DomainIntelligence().analyze(
            "sender-domain.com", urls=["https://fine.example/ok"])
        rule_ids = [f.rule_id for f in intel["findings"]]
        assert "INTEL_SAFE_BROWSING_THREAT" not in rule_ids
        assert intel["safe_browsing"][0]["status"] == "UNAVAILABLE"

    def test_error_creates_no_finding(self, monkeypatch):
        _with_key(monkeypatch)
        _mock_http(monkeypatch,
                   lambda k, b, t: (_ for _ in ()).throw(RuntimeError("SB_HTTP_500")))
        _quiet_dns(monkeypatch)
        intel = DomainIntelligence().analyze(
            "sender-domain.com", urls=["https://fine.example/ok"])
        rule_ids = [f.rule_id for f in intel["findings"]]
        assert "INTEL_SAFE_BROWSING_THREAT" not in rule_ids
        assert intel["safe_browsing"][0]["status"] == "ERROR"

    def test_duplicate_urls_one_request_per_analysis(self, monkeypatch):
        _with_key(monkeypatch)
        calls = _mock_http(monkeypatch,
                           lambda k, b, t: _sb_response(_match("MALWARE")))
        _quiet_dns(monkeypatch)
        DomainIntelligence().analyze(
            "sender-domain.com",
            urls=["http://evil.example/p", "http://evil.example/p#x",
                  "http://evil.example/p"],
        )
        assert len(calls) == 1

    def test_per_domain_cache_does_not_leak_url_results(self, monkeypatch):
        """Two emails, same sender domain, different URLs -> both looked up."""
        _with_key(monkeypatch)
        seen_urls = []

        def responder(k, b, t):
            seen_urls.append(b["threatInfo"]["threatEntries"][0]["url"])
            return {}

        _mock_http(monkeypatch, responder)
        _quiet_dns(monkeypatch)
        di = DomainIntelligence()
        di.analyze("same-sender.com", urls=["https://first.example/a"])
        di.analyze("same-sender.com", urls=["https://second.example/b"])
        assert "https://first.example/a" in seen_urls
        assert "https://second.example/b" in seen_urls

    def test_no_urls_skips_provider_entirely(self, monkeypatch):
        _with_key(monkeypatch)
        calls = _mock_http(monkeypatch, lambda k, b, t: {})
        _quiet_dns(monkeypatch)
        intel = DomainIntelligence().analyze("sender-domain.com", urls=[])
        assert intel["safe_browsing"] == []
        assert not calls

    def test_provider_exception_never_breaks_intel(self, monkeypatch):
        _with_key(monkeypatch)

        class _Boom:
            name = "boom"

            def check_url(self, url):
                raise RuntimeError("provider exploded")

        monkeypatch.setattr(DomainIntelligence, "_sb_provider", _Boom())
        _quiet_dns(monkeypatch)
        intel = DomainIntelligence().analyze(
            "sender-domain.com", urls=["https://e.com/x"])  # must not raise
        assert intel["safe_browsing"][0]["status"] == "ERROR"
        assert intel["safe_browsing"][0]["error"] == "INTEGRATION_FAILURE"


# ── engine-level: scoring, cap, regression guards ────────────────────────

def _engine_analyze(monkeypatch, urls, sb_responder):
    from detection.engine import DetectionEngine
    _with_key(monkeypatch)
    calls = _mock_http(monkeypatch, sb_responder)
    _quiet_dns(monkeypatch)

    # NOTE: the local variable must be captured with a DIFFERENT name than
    # the class attribute — inside a class body, `urls = urls` resolves the
    # right-hand side to the (not yet defined) class attribute, not the
    # enclosing function parameter.
    email_urls = list(urls)

    class P:
        sender_email = "info@sender-domain.com"
        sender_name = "Sender"
        sender_domain = "sender-domain.com"
        urls = email_urls
        anchor_text = ""
        body_text = "Hello, please review the attached quarterly summary."
        body_html = ""
        headers = {"From": "info@sender-domain.com"}
        attachments = []
        spf_result = "pass"
        dkim_result = "pass"
        dmarc_result = "pass"
        received_headers = []
        message_id = ""
        subject = "Quarterly summary"

    return DetectionEngine().analyze(P()), calls


class TestEngineIntegration:

    def test_confirmed_threat_produces_finding(self, monkeypatch):
        results, _ = _engine_analyze(
            monkeypatch,
            ["http://evil.example/payload"],
            lambda k, b, t: _sb_response(_match("SOCIAL_ENGINEERING")),
        )
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "INTEL_SAFE_BROWSING_THREAT" in rule_ids

    def test_sb_failure_does_not_increase_risk(self, monkeypatch):
        base_results, _ = _engine_analyze(monkeypatch, [], lambda k, b, t: {})
        failed_results, _ = _engine_analyze(
            monkeypatch, ["https://e.com/x"],
            lambda k, b, t: (_ for _ in ()).throw(RuntimeError("SB_HTTP_500")),
        )
        assert failed_results["risk_score"] == base_results["risk_score"]
        rule_ids = [f["rule_id"] for f in failed_results["findings"]]
        assert "INTEL_SAFE_BROWSING_THREAT" not in rule_ids

    def test_sb_unavailable_does_not_increase_risk(self, monkeypatch):
        base_results, _ = _engine_analyze(monkeypatch, [], lambda k, b, t: {})
        # provider unconfigured -> UNAVAILABLE
        monkeypatch.delenv(SB_API_KEY_ENV, raising=False)
        unav_results, _ = _engine_analyze(
            monkeypatch, ["https://e.com/x"], lambda k, b, t: {})
        assert unav_results["risk_score"] == base_results["risk_score"]

    def test_static_url_analyzer_still_works_when_sb_fails(self, monkeypatch):
        """Deterministic URL findings are unaffected by provider failure."""
        results, _ = _engine_analyze(
            monkeypatch,
            ["http://user:pass@evil.example/login"],
            lambda k, b, t: (_ for _ in ()).throw(RuntimeError("SB_CONNECTION_FAILURE")),
        )
        rule_ids = [f["rule_id"] for f in results["findings"]]
        # Deterministic findings still present (credentialed URL + path).
        assert "URL_CREDENTIALS_IN_URL" in rule_ids
        assert "URL_SUSPICIOUS_PATH" in rule_ids
        assert "INTEL_SAFE_BROWSING_THREAT" not in rule_ids

    def test_intel_cap_enforced_with_sb(self, monkeypatch):
        """Raw SB points must flow through the existing INTEL cap (5)."""
        from detection.rules import CATEGORY_WEIGHTS

        # Worst case: SB threat (10) + young domain (8) => raw INTEL 18.
        def responder(k, b, t):
            return _sb_response(_match("MALWARE"), _match("SOCIAL_ENGINEERING"))

        import detection.intelligence.domain_age as domain_age
        from datetime import datetime, timedelta, timezone

        monkeypatch.setattr(
            domain_age, "_http_get_json",
            lambda u, t: {
                "events": [{
                    "eventAction": "registration",
                    "eventDate": (datetime.now(timezone.utc)
                                  - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }],
            },
        )

        results, _ = _engine_analyze(
            monkeypatch, ["http://evil.example/payload"], responder)

        intel_dicts = results["categorized_findings"]["INTEL"]
        raw_intel = sum(f["points"] for f in intel_dicts)
        # Raw evidence must exceed the cap for this test to be meaningful.
        assert raw_intel >= 15, f"setup: raw INTEL only {raw_intel}"
        # Reproduce scorer cap math.
        subtotals = {}
        for f in results["findings"]:
            subtotals[f["category"]] = subtotals.get(f["category"], 0.0) + f["points"]
        intel_final = max(min(subtotals.get("INTEL", 0.0),
                              CATEGORY_WEIGHTS["INTEL"]), -5)
        assert intel_final == 5, f"INTEL cap violated: {intel_final}"
        # And the reported total is consistent with capped math (clamped 0-100).
        capped_total = sum(
            max(min(v, CATEGORY_WEIGHTS.get(k, 5)), -5)
            for k, v in subtotals.items()
        )
        clamped = max(0.0, min(capped_total, 100.0))
        assert abs(clamped - results["risk_score"]) < 1e-9
        # Confirmed external threat alone must not reach HIGH_RISK.
        assert results["classification"] != "HIGH_RISK"
