"""
Session C — TLS/certificate intelligence tests.

All tests are hermetic: the socket/probe boundary is mocked; no test ever
opens a real TLS connection. The suite-wide conftest gate additionally
disables TLS network access.

Covers the 27 required cases: all seven certificate states, private/local
target rejection (before any connection), dedup, caching, finding
generation (and its absence for valid/unavailable), engine integration,
INTEL cap enforcement, and regression guards for static URL analysis,
Domain Age, and Safe Browsing.
"""

from urllib.parse import urlparse

import pytest

from detection.intelligence import tls_intelligence as tls_mod
from detection.intelligence.tls_intelligence import (
    TLS_FINDING_RULES,
    TLS_TOTAL_TIMEOUT,
    TLS_CONNECT_TIMEOUT,
    TLSResult,
    clear_cache,
    is_safe_public_hostname,
    probe_tls,
)
from detection.intelligence.domain_intelligence import (
    DomainIntelligence,
    clear_cache as clear_intel_cache,
)
from detection.intelligence.threat_intel import google_safe_browsing as gsb


# ── fixtures / helpers ───────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """Hermetic: no sockets, no caches, no config leakage between tests.

    The gate default here is False; tests that mock the probe seam
    (_probe_with_socket) re-enable it, because the mock replaces the
    entire network path — no real socket can be opened either way.
    """
    clear_cache()
    clear_intel_cache()
    monkeypatch.setattr(tls_mod, "_network_allowed", False)
    yield
    clear_cache()
    clear_intel_cache()


def _mock_probe(monkeypatch, responder):
    """Patch the network seam (_probe_with_socket).

    The mock replaces the ENTIRE network path, so the gate is opened for
    the test — no real socket can be opened either way (there is nothing
    behind the seam but the mock). Tests that do NOT mock the seam keep
    the gate closed and exercise the offline safety paths.
    """
    calls = []

    def _fake_probe_with_socket(hostname, base):
        calls.append((hostname, base.url))
        payload = responder(hostname, base)
        if payload is not None:
            raise tls_mod._TLSVerdict(payload)
        raise tls_mod._TLSUnavailable()

    monkeypatch.setattr(tls_mod, "_probe_with_socket", _fake_probe_with_socket)
    monkeypatch.setattr(tls_mod, "_network_allowed", True)
    return calls


def _payload(base: TLSResult, state: str, **meta) -> dict:
    d = TLSResult(url=base.url, state=state,
                  hostname=base.hostname).to_dict()
    d.update(meta)
    return d


def _quiet_dns(monkeypatch):
    monkeypatch.setattr(DomainIntelligence, "_check_dns_resolution",
                        lambda self, d: True)
    monkeypatch.setattr(DomainIntelligence, "_check_mx_records",
                        lambda self, d: False)


# ── 1–4: certificate states (via mocked probe seam) ─────────────────────

class TestCertificateStates:

    def test_valid_certificate(self, monkeypatch):
        calls = _mock_probe(monkeypatch, lambda h, b: _payload(
            b, "TLS_VALID", issuer="Let's Encrypt", subject_cn=h,
            not_before="Sep 01 00:00:00 2026 GMT",
            not_after="Nov 30 23:59:59 2026 GMT"))
        r = probe_tls("https://good.example.com/page")
        assert r["state"] == "TLS_VALID"
        assert r["issuer"] == "Let's Encrypt"
        assert r["subject_cn"] == "good.example.com"
        assert r["not_after"].startswith("Nov")
        assert len(calls) == 1

    def test_expired_certificate(self, monkeypatch):
        _mock_probe(monkeypatch, lambda h, b: _payload(b, "TLS_EXPIRED"))
        assert probe_tls("https://old.example.com/")["state"] == "TLS_EXPIRED"

    def test_hostname_mismatch(self, monkeypatch):
        _mock_probe(monkeypatch,
                    lambda h, b: _payload(b, "TLS_HOSTNAME_MISMATCH"))
        r = probe_tls("https://wrong-cert.example.com/")
        assert r["state"] == "TLS_HOSTNAME_MISMATCH"

    def test_invalid_certificate(self, monkeypatch):
        _mock_probe(monkeypatch, lambda h, b: _payload(b, "TLS_INVALID"))
        assert probe_tls("https://bad.example.com/")["state"] == "TLS_INVALID"

    def test_state_classification_helper(self, monkeypatch):
        # _classify_failure maps the stable stdlib reason strings.
        assert tls_mod._classify_failure(
            Exception("certificate is not valid for 'other.example'")) \
            == "TLS_HOSTNAME_MISMATCH"
        assert tls_mod._classify_failure(Exception("certificate expired")) \
            == "TLS_EXPIRED"
        assert tls_mod._classify_failure(Exception("self signed certificate")) \
            == "TLS_INVALID"


# ── 5–9: failure modes and non-HTTPS schemes ────────────────────────────

class TestFailureModes:

    def test_tls_timeout(self, monkeypatch):
        def timeout(h, b):
            raise tls_mod._TLSTimeout()
        calls = _mock_probe(monkeypatch, timeout)
        # The mock opens the gate; the responder raises through it.
        monkeypatch.setattr(tls_mod, "_network_allowed", True)
        r = probe_tls("https://slow.example.com/")
        assert r["state"] == "TLS_ERROR"
        assert r["error"] == "TIMEOUT"

    def test_connection_failure(self, monkeypatch):
        _mock_probe(monkeypatch, lambda h, b: None)  # -> _TLSUnavailable
        r = probe_tls("https://unreachable.example.com/")
        assert r["state"] == "TLS_UNAVAILABLE"
        assert r["error"] == "CONNECT_FAILED"

    def test_malformed_url(self, monkeypatch):
        calls = _mock_probe(monkeypatch, lambda h, b: (_ for _ in ()).throw(
            AssertionError("must not probe")))
        r = probe_tls("not a url at all")
        assert r["state"] == "TLS_ERROR"
        assert r["error"] == "MALFORMED_URL"
        assert not calls

    def test_http_url_no_tls_probe(self, monkeypatch):
        calls = _mock_probe(monkeypatch, lambda h, b: (_ for _ in ()).throw(
            AssertionError("HTTP must never trigger a probe")))
        r = probe_tls("http://plain.example.com/page")
        assert r["state"] == "HTTP"
        assert r["hostname"] == "plain.example.com"
        assert not calls, "HTTP URL must not open any connection"

    def test_non_http_schemes_rejected(self, monkeypatch):
        calls = _mock_probe(monkeypatch, lambda h, b: (_ for _ in ()).throw(
            AssertionError("non-HTTP(S) must never probe")))
        for url in ("ftp://example.com/file", "javascript:alert(1)",
                    "mailto:user@example.com", "file:///etc/passwd"):
            r = probe_tls(url)
            assert r["state"] == "TLS_ERROR", url
            assert r["error"] == "MALFORMED_URL"  # normalizer rejects scheme
        assert not calls


# ── 10–14: private / local target protection ────────────────────────────

class TestPrivateTargetProtection:

    @pytest.mark.parametrize("host", [
        "localhost", "127.0.0.1", "10.1.2.3", "172.16.0.9", "172.31.255.1",
        "192.168.1.10", "169.254.169.254", "[::1]", "[fe80::1]",
        "[fd00::5]", "0.0.0.0", "metadata.google.internal",
        "server.local", "host.internal", "intranet.corp",
    ])
    def test_unsafe_targets_never_probe(self, monkeypatch, host):
        calls = _mock_probe(monkeypatch, lambda h, b: (_ for _ in ()).throw(
            AssertionError(f"must not connect to {host}")))
        r = probe_tls(f"https://{host}/x")
        assert r["state"] == "TLS_ERROR"
        assert r["error"] == "UNSAFE_TARGET"
        assert not calls, f"a connection was attempted for {host}"

    def test_rebinding_guard(self, monkeypatch):
        """A resolved private IP is refused at probe time."""
        assert tls_mod._rebound_to_private_ip("10.0.0.5") is True
        assert tls_mod._rebound_to_private_ip("192.168.0.1") is True
        assert tls_mod._rebound_to_private_ip("::1") is True
        assert tls_mod._rebound_to_private_ip("93.184.216.34") is False

    def test_safe_hostname_classifier(self):
        assert is_safe_public_hostname("example.com") is True
        assert is_safe_public_hostname("localhost") is False
        assert is_safe_public_hostname("127.0.0.1") is False
        assert is_safe_public_hostname("192.168.0.1") is False
        assert is_safe_public_hostname("[fd00::1]") is False
        assert is_safe_public_hostname("169.254.1.1") is False

    def test_resolved_private_ip_refused_before_connect(self, monkeypatch):
        """getaddrinfo returning a private IP for a public-looking name."""
        def fake_getaddrinfo(host, port):
            return [(2, 1, 6, "", ("192.168.0.99", port))]

        connected = []
        monkeypatch.setattr(tls_mod, "_getaddrinfo", fake_getaddrinfo)
        monkeypatch.setattr(tls_mod, "_socket_connect",
                            lambda *a: connected.append(a))
        monkeypatch.setattr(tls_mod, "_network_allowed", True)
        r = probe_tls("https://evil-rebind.example.com/")
        assert r["state"] == "TLS_ERROR"
        assert r["error"] == "UNSAFE_TARGET"
        assert not connected, "socket was opened to a private IP"


# ── 15–17: dedup + caching ──────────────────────────────────────────────

class TestDedupAndCaching:

    def test_duplicate_hostname_dedup_in_integration(self, monkeypatch):
        calls = _mock_probe(monkeypatch, lambda h, b: _payload(b, "TLS_VALID"))
        _quiet_dns(monkeypatch)
        DomainIntelligence().analyze(
            "sender-domain.com",
            urls=["https://shop.example.com/a", "https://shop.example.com/b",
                  "https://other.example.com/c"],
        )
        probed_hosts = [h for h, _ in calls]
        assert sorted(probed_hosts) == ["other.example.com", "shop.example.com"]

    def test_cache_hit(self, monkeypatch):
        calls = _mock_probe(monkeypatch, lambda h, b: _payload(b, "TLS_VALID"))
        probe_tls("https://cached.example.com/x")
        probe_tls("https://cached.example.com/x")
        assert len(calls) == 1

    def test_cache_expiry(self, monkeypatch):
        calls = _mock_probe(monkeypatch, lambda h, b: _payload(b, "TLS_VALID"))
        probe_tls("https://expiring.example.com/x")
        for entry in tls_mod._cache.values():
            entry["ts"] -= 100000.0  # beyond every TTL
        probe_tls("https://expiring.example.com/x")
        assert len(calls) == 2

    def test_negative_state_short_ttl(self, monkeypatch):
        calls = _mock_probe(monkeypatch, lambda h, b: None)
        probe_tls("https://down.example.com/")     # TLS_UNAVAILABLE
        probe_tls("https://down.example.com/")     # cached negative
        assert len(calls) == 1
        for entry in tls_mod._cache.values():
            entry["ts"] -= 61.0                    # past the 60s negative TTL
        probe_tls("https://down.example.com/")
        assert len(calls) == 2

    def test_cache_is_bounded(self, monkeypatch):
        _mock_probe(monkeypatch, lambda h, b: _payload(b, "TLS_VALID"))
        for i in range(tls_mod._CACHE_MAX_ENTRIES + 10):
            probe_tls(f"https://host{i}.example.com/")
        assert len(tls_mod._cache) <= tls_mod._CACHE_MAX_ENTRIES


# ── findings semantics ──────────────────────────────────────────────────

class TestFindingSemantics:

    def _intel_with(self, monkeypatch, url, responder):
        _mock_probe(monkeypatch, responder)
        _quiet_dns(monkeypatch)
        return DomainIntelligence().analyze("sender-domain.com", urls=[url])

    def test_valid_tls_creates_no_finding(self, monkeypatch):
        intel = self._intel_with(
            monkeypatch, "https://fine.example.com/ok",
            lambda h, b: _payload(b, "TLS_VALID"))
        rule_ids = [f.rule_id for f in intel["findings"]]
        assert not any(r.startswith("INTEL_TLS") for r in rule_ids)
        assert intel["tls"][0]["state"] == "TLS_VALID"

    def test_expired_produces_evidence_finding(self, monkeypatch):
        intel = self._intel_with(
            monkeypatch, "https://old.example.com/",
            lambda h, b: _payload(b, "TLS_EXPIRED", not_after="Jan 01 2025 GMT"))
        finding = next(f for f in intel["findings"]
                       if f.rule_id == "INTEL_TLS_EXPIRED")
        assert finding.points == TLS_FINDING_RULES["TLS_EXPIRED"][1]
        assert finding.severity == "LOW"
        assert "expired" in finding.message.lower()
        assert "phishing" not in finding.message.lower()

    def test_mismatch_produces_evidence_finding(self, monkeypatch):
        intel = self._intel_with(
            monkeypatch, "https://wrong.example.com/",
            lambda h, b: _payload(b, "TLS_HOSTNAME_MISMATCH"))
        finding = next(f for f in intel["findings"]
                       if f.rule_id == "INTEL_TLS_HOSTNAME_MISMATCH")
        assert finding.severity == "MEDIUM"
        assert "does not match" in finding.message

    def test_invalid_produces_evidence_finding(self, monkeypatch):
        intel = self._intel_with(
            monkeypatch, "https://broken.example.com/",
            lambda h, b: _payload(b, "TLS_INVALID"))
        assert any(f.rule_id == "INTEL_TLS_INVALID"
                   for f in intel["findings"])

    def test_unavailable_and_error_never_create_findings(self, monkeypatch):
        for state, err in (("TLS_UNAVAILABLE", "CONNECT_FAILED"),
                           ("TLS_ERROR", "TIMEOUT")):
            clear_cache()
            def responder(h, b, _state=state, _err=err):
                return _payload(b, _state, error=_err)
            _mock_probe(monkeypatch, responder)
            _quiet_dns(monkeypatch)
            intel = DomainIntelligence().analyze(
                "sender-domain.com", urls=["https://x.example.com/"])
            assert not any(f.rule_id.startswith("INTEL_TLS")
                           for f in intel["findings"]), state
            assert intel["tls"][0]["state"] == state

    def test_factual_language_no_verdicts(self, monkeypatch):
        intel = self._intel_with(
            monkeypatch, "https://old.example.com/",
            lambda h, b: _payload(b, "TLS_EXPIRED"))
        f = next(f for f in intel["findings"]
                 if f.rule_id == "INTEL_TLS_EXPIRED")
        text = (f.message + " " + f.explanation).lower()
        assert "phishing" not in text
        assert "proves" not in text
        assert "safe" not in text

    def test_no_email_body_leakage_in_evidence(self, monkeypatch):
        intel = self._intel_with(
            monkeypatch, "https://old.example.com/",
            lambda h, b: _payload(b, "TLS_EXPIRED"))
        blob = str(intel["tls"])
        # 'subject_cn' is a certificate field name; check the real email
        # metadata keys and values rather than substring 'subject'.
        for forbidden in ("sender@", "email_subject", "body_text",
                          "body_html", "attachment", "password", "secret"):
            assert forbidden not in blob


# ── 20: TLS failure must not falsely classify as SAFE ───────────────────

def _engine_analyze(monkeypatch, urls, tls_responder=None, sb_responder=None):
    from detection.engine import DetectionEngine

    # Provide an SB key so the provider reaches its (mocked) HTTP seam
    # exactly as Session B tests do.
    monkeypatch.setenv(gsb.SB_API_KEY_ENV, "test-key-not-real")
    _mock_probe(monkeypatch, tls_responder or (lambda h, b: None))
    calls_sb = []

    def fake_sb_post(api_key, body, timeout):
        calls_sb.append(body)
        if sb_responder:
            return sb_responder(api_key, body, timeout)
        return {}

    monkeypatch.setattr(gsb, "_post_threat_matches", fake_sb_post)
    _quiet_dns(monkeypatch)

    email_urls = list(urls)

    class P:
        sender_email = "info@sender-domain.com"
        sender_name = "Sender"
        sender_domain = "sender-domain.com"
        urls = email_urls
        anchor_text = ""
        body_text = "Please review the quarterly report."
        body_html = ""
        headers = {"From": "info@sender-domain.com"}
        attachments = []
        spf_result = "pass"
        dkim_result = "pass"
        dmarc_result = "pass"
        received_headers = []
        message_id = ""
        subject = "Quarterly report"

    return DetectionEngine().analyze(P()), calls_sb


class TestEngineRegressionAndScoring:

    def test_tls_failure_does_not_falsely_classify_safe(self, monkeypatch):
        """TLS_UNAVAILABLE must not ADD safety: baseline == failed score."""
        base, _ = _engine_analyze(monkeypatch, [])
        failed, _ = _engine_analyze(
            monkeypatch, ["https://down.example.com/x"])
        assert failed["risk_score"] == base["risk_score"]
        assert not any(f["rule_id"].startswith("INTEL_TLS")
                       for f in failed["findings"])

    def test_tls_evidence_raises_score_only_minimally(self, monkeypatch):
        base, _ = _engine_analyze(monkeypatch, [])
        with_expired, _ = _engine_analyze(
            monkeypatch, ["https://old.example.com/x"],
            tls_responder=lambda h, b: _payload(b, "TLS_EXPIRED"))
        assert with_expired["risk_score"] >= base["risk_score"]
        # Minimal impact: an expired cert adds at most 2 raw points.
        assert with_expired["risk_score"] <= base["risk_score"] + 2 + 1e-9

    def test_existing_url_analysis_regression(self, monkeypatch):
        """Deterministic URL findings survive with TLS enabled."""
        results, _ = _engine_analyze(
            monkeypatch, ["http://user:pass@evil.example/login"])
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "URL_CREDENTIALS_IN_URL" in rule_ids
        assert "URL_SUSPICIOUS_PATH" in rule_ids

    def test_domain_age_regression(self, monkeypatch):
        """Session A still functions alongside TLS intelligence."""
        import detection.intelligence.domain_age as domain_age
        from datetime import datetime, timedelta, timezone

        monkeypatch.setattr(
            domain_age, "_http_get_json",
            lambda u, t: {"events": [{
                "eventAction": "registration",
                "eventDate": (datetime.now(timezone.utc)
                              - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }]},
        )
        results, _ = _engine_analyze(monkeypatch, ["https://x.example.com/"])
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "INTEL_YOUNG_DOMAIN" in rule_ids

    def test_safe_browsing_regression(self, monkeypatch):
        """Session B still functions alongside TLS intelligence."""
        results, sb_calls = _engine_analyze(
            monkeypatch, ["http://evil.example/login"],
            sb_responder=lambda k, b, t: {"matches": [{
                "threatType": "SOCIAL_ENGINEERING",
                "threat": {"url": "http://evil.example/login"}}]})
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "INTEL_SAFE_BROWSING_THREAT" in rule_ids
        assert sb_calls, "Safe Browsing was skipped"

    def test_intel_cap_remains_enforced(self, monkeypatch):
        """SB (10) + young domain (8) + TLS mismatch (4) still caps at 5.

        The URL is HTTPS so the TLS evidence genuinely participates (an
        http:// URL correctly never probes TLS and would weaken this test).
        """
        from detection.rules import CATEGORY_WEIGHTS
        import detection.intelligence.domain_age as domain_age
        from datetime import datetime, timedelta, timezone

        monkeypatch.setattr(
            domain_age, "_http_get_json",
            lambda u, t: {"events": [{
                "eventAction": "registration",
                "eventDate": (datetime.now(timezone.utc)
                              - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }]},
        )
        results, _ = _engine_analyze(
            monkeypatch, ["https://evil.example/login"],
            tls_responder=lambda h, b: _payload(b, "TLS_HOSTNAME_MISMATCH"),
            sb_responder=lambda k, b, t: {"matches": [{
                "threatType": "MALWARE",
                "threat": {"url": "https://evil.example/login"}}]})

        intel_dicts = results["categorized_findings"]["INTEL"]
        intel_rules = [f["rule_id"] for f in intel_dicts]
        # All three intelligence sources must actually be in the mix.
        assert "INTEL_SAFE_BROWSING_THREAT" in intel_rules
        assert "INTEL_YOUNG_DOMAIN" in intel_rules
        assert "INTEL_TLS_HOSTNAME_MISMATCH" in intel_rules
        raw_intel = sum(f["points"] for f in intel_dicts)
        assert raw_intel == 22, f"setup: raw INTEL is {raw_intel}, expected 22"

        subtotals = {}
        for f in results["findings"]:
            subtotals[f["category"]] = (subtotals.get(f["category"], 0.0)
                                        + f["points"])
        intel_final = max(min(subtotals.get("INTEL", 0.0),
                              CATEGORY_WEIGHTS["INTEL"]), -5)
        assert intel_final == 5, f"INTEL cap violated: {intel_final}"

        capped_total = sum(max(min(v, CATEGORY_WEIGHTS.get(k, 5)), -5)
                           for k, v in subtotals.items())
        clamped = max(0.0, min(capped_total, 100.0))
        assert abs(clamped - results["risk_score"]) < 1e-9
        # TLS evidence alone must not make an email HIGH_RISK.
        assert results["classification"] != "HIGH_RISK"

    def test_timeouts_are_strict(self):
        assert TLS_CONNECT_TIMEOUT <= 5.0
        assert TLS_TOTAL_TIMEOUT <= 10.0

    def test_no_webpage_fetch_or_redirects_structurally(self, monkeypatch):
        """The probe module must contain no HTTP-fetch primitives."""
        import inspect
        src = inspect.getsource(tls_mod)
        for banned in ("urlopen", "urllib.request", "http.client",
                       "requests.get", "HTTPConnection"):
            assert banned not in src, f"web-fetch primitive present: {banned}"

    def test_dataclass_shape(self):
        r = TLSResult(url="https://h/", state="TLS_VALID", hostname="h")
        d = r.to_dict()
        assert set(d) == {"url", "state", "hostname", "issuer", "subject_cn",
                          "not_before", "not_after", "error"}
        assert r.has_tls is True
        assert TLSResult(url="u", state="HTTP").has_tls is False
