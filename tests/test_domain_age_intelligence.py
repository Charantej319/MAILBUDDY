"""
Session A — Domain Age Intelligence tests.

All tests are hermetic: RDAP network access is fully mocked (no test ever
touches the network). Covers:

1. Parsing of RDAP timestamps / creation events / registrar info.
2. Age classification buckets and finding generation.
3. Fail-safe behavior of get_domain_age (bad input, network failure,
   malformed/missing data) — never raises, always 'no evidence'.
4. Cache-first behavior (one fetch per domain, clear_age_cache resets).
5. Integration: DomainIntelligence.analyze() exposes domain_age and the
   age findings flow into the detection engine.
"""

from datetime import datetime, timedelta, timezone

import pytest

from detection.intelligence import domain_age
from detection.intelligence.domain_age import (
    AGE_RULE_ID_YOUNG,
    YOUNG_DOMAIN_DAYS,
    ESTABLISHED_DOMAIN_DAYS,
    _age_findings,
    _classify_age,
    _extract_creation_event,
    _extract_registrar,
    _parse_iso8601,
    clear_age_cache,
    get_domain_age,
)
from detection.intelligence.domain_intelligence import (
    DomainIntelligence,
    clear_cache as clear_intel_cache,
)


# ── helpers ──────────────────────────────────────────────────────────────

def _rdap_response(age_days: int, domain: str = "example-tool.com") -> dict:
    """Minimal RDAP record whose registration event is `age_days` old."""
    created = datetime.now(timezone.utc) - timedelta(days=age_days)
    return {
        "ldhName": domain,
        "status": ["client transfer prohibited"],
        "events": [
            {
                "eventAction": "registrar expiration",
                "eventDate": (datetime.now(timezone.utc)
                              + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            {
                "eventAction": "registration",
                "eventDate": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Test Registrar Inc."],
                    ],
                ],
                "links": [{"href": "https://registrar.example/about"}],
            },
        ],
    }


def _patch_rdap(monkeypatch, responder):
    """Patch the network seam (_http_get_json) with a test responder."""
    calls: list[str] = []

    def _fake_http_get_json(url: str, timeout: float):
        calls.append(url)
        return responder(url)

    monkeypatch.setattr(domain_age, "_http_get_json", _fake_http_get_json)
    return calls


@pytest.fixture(autouse=True)
def _clean_caches():
    """Isolate module caches between tests (no cross-test age leakage)."""
    clear_age_cache()
    clear_intel_cache()
    yield
    clear_age_cache()
    clear_intel_cache()


# ── 1. RDAP parsing ─────────────────────────────────────────────────────

class TestRdapParsing:

    def test_parse_iso_zulu(self):
        dt = _parse_iso8601("2026-09-01T10:00:00Z")
        assert dt is not None
        assert (dt.year, dt.month, dt.day, dt.hour) == (2026, 9, 1, 10)
        assert dt.tzinfo is None  # normalized to naive UTC

    def test_parse_iso_offset_normalized_to_utc(self):
        dt = _parse_iso8601("2026-09-01T12:00:00+02:00")
        assert dt is not None
        assert (dt.hour, dt.minute) == (10, 0)  # 12:00+02:00 == 10:00Z

    def test_parse_iso_fractional_seconds(self):
        assert _parse_iso8601("2026-09-01T10:00:00.123Z") is not None

    def test_parse_iso_garbage_and_none(self):
        assert _parse_iso8601("not-a-date") is None
        assert _parse_iso8601("") is None
        assert _parse_iso8601(None) is None
        assert _parse_iso8601(12345) is None

    def test_creation_event_prefers_registration(self):
        rdap = _rdap_response(10)
        dt = _extract_creation_event(rdap)
        expected = datetime.now(timezone.utc) - timedelta(days=10)
        assert dt is not None
        assert abs((expected.replace(tzinfo=None) - dt).total_seconds()) < 5

    def test_creation_event_ignores_other_actions(self):
        rdap = {"events": [{"eventAction": "last changed",
                            "eventDate": "2026-01-01T00:00:00Z"}]}
        assert _extract_creation_event(rdap) is None

    def test_creation_event_legacy_field_fallback(self):
        rdap = {"creationDate": "2020-05-05T00:00:00Z"}
        dt = _extract_creation_event(rdap)
        assert dt is not None and dt.year == 2020

    def test_creation_event_missing(self):
        assert _extract_creation_event({}) is None
        assert _extract_creation_event({"events": []}) is None
        assert _extract_creation_event(None) is None

    def test_registrar_extraction(self):
        name, url = _extract_registrar(_rdap_response(10))
        assert name == "Test Registrar Inc."
        assert url == "https://registrar.example/about"

    def test_registrar_missing(self):
        rdap = {"entities": [{"roles": ["administrative"]}], "events": []}
        name, url = _extract_registrar(rdap)
        assert name is None and url is None
        assert _extract_registrar({}) == (None, None)


# ── 2. Age buckets and findings ─────────────────────────────────────────

class TestAgeClassificationAndFindings:

    def test_buckets(self):
        assert _classify_age(0) == "young"
        assert _classify_age(YOUNG_DOMAIN_DAYS - 1) == "young"
        assert _classify_age(YOUNG_DOMAIN_DAYS) == "recent"
        assert _classify_age(ESTABLISHED_DOMAIN_DAYS - 1) == "recent"
        assert _classify_age(ESTABLISHED_DOMAIN_DAYS) == "established"

    def test_young_domain_finding(self):
        age = get_domain_age("brand-new-tool.com")  # patched below
        findings = _age_findings({
            "age_known": True, "age_days": 5,
            "creation_date": "2026-09-24", "source": "rdap.verisign.com",
        })
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == AGE_RULE_ID_YOUNG
        assert f.severity == "MEDIUM"
        assert f.points == 8
        assert f.category.value == "INTEL"
        assert "5 day" in f.message

    def test_recent_domain_finding(self):
        findings = _age_findings({
            "age_known": True, "age_days": 200,
            "creation_date": "2026-03-14", "source": "rdap.org",
        })
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "INTEL_DOMAIN_RECENT"
        assert f.severity == "LOW"
        assert f.points == 3

    def test_established_domain_no_finding(self):
        assert _age_findings({
            "age_known": True, "age_days": 3650,
            "creation_date": "2016-01-01", "source": "rdap.verisign.com",
        }) == []

    def test_unknown_age_no_finding(self):
        assert _age_findings({"age_known": False, "age_days": None}) == []


# ── 3. get_domain_age happy path + fail-safe ────────────────────────────

class TestGetDomainAge:

    def test_happy_path_young(self, monkeypatch):
        calls = _patch_rdap(monkeypatch, lambda url: _rdap_response(5))
        result = get_domain_age("example-tool.com")
        assert result["age_known"] is True
        assert 4 <= result["age_days"] <= 6
        assert result["age_category"] == "young"
        assert result["registrar"] == "Test Registrar Inc."
        assert result["creation_date"] is not None
        assert calls, "RDAP endpoint must have been queried"

    def test_happy_path_established(self, monkeypatch):
        _patch_rdap(monkeypatch, lambda url: _rdap_response(3000))
        result = get_domain_age("example-tool.com")
        assert result["age_known"] is True
        assert result["age_category"] == "established"

    @pytest.mark.parametrize("bad", [
        "", "   ", None, "localhost", "not a domain", "-bad-.com",
        "a", "under_score.com", "http://x.com",
    ])
    def test_implausible_input_never_raises(self, monkeypatch, bad):
        calls = _patch_rdap(
            monkeypatch,
            lambda url: (_ for _ in ()).throw(AssertionError("must not fetch")),
        )
        result = get_domain_age(bad)
        assert result == {
            "age_known": False, "age_days": None, "creation_date": None,
            "registrar": None, "registrar_url": None,
            "age_category": "unknown", "source": None,
        }
        assert not calls, "garbage input must never reach the network"

    def test_subdomain_resolves_to_registrable(self, monkeypatch):
        seen = {}

        def responder(url):
            seen["url"] = url
            return _rdap_response(100)

        _patch_rdap(monkeypatch, responder)
        result = get_domain_age("mail.alerts.example-tool.com")
        assert result["age_known"] is True
        assert "example-tool.com" in seen["url"]

    def test_network_failure_fails_safe(self, monkeypatch):
        def responder(url):
            raise OSError("simulated network outage")

        _patch_rdap(monkeypatch, responder)
        result = get_domain_age("example-tool.com")  # must not raise
        assert result["age_known"] is False
        assert result["age_category"] == "unknown"

    def test_http_error_404_fails_safe(self, monkeypatch):
        import urllib.error

        def responder(url):
            raise urllib.error.HTTPError(url, 404, "not found", None, None)

        _patch_rdap(monkeypatch, responder)
        assert get_domain_age("example-tool.com")["age_known"] is False

    def test_malformed_rdap_fails_safe(self, monkeypatch):
        _patch_rdap(monkeypatch, lambda url: ["not", "a", "dict"])
        assert get_domain_age("example-tool.com")["age_known"] is False

    def test_rdap_without_creation_event_fails_safe(self, monkeypatch):
        _patch_rdap(monkeypatch, lambda url: {"ldhName": "example-tool.com"})
        assert get_domain_age("example-tool.com")["age_known"] is False

    def test_https_only(self):
        with pytest.raises(ValueError):
            domain_age._http_get_json("http://rdap.org/domain/x", 1.0)


# ── 4. Caching ──────────────────────────────────────────────────────────

class TestAgeCaching:

    def test_cache_prevents_refetch(self, monkeypatch):
        calls = _patch_rdap(monkeypatch, lambda url: _rdap_response(5))
        get_domain_age("example-tool.com")
        get_domain_age("example-tool.com")
        get_domain_age("example-tool.com")
        assert len(calls) == 1

    def test_clear_cache_allows_refetch(self, monkeypatch):
        calls = _patch_rdap(monkeypatch, lambda url: _rdap_response(5))
        get_domain_age("example-tool.com")
        clear_age_cache()
        get_domain_age("example-tool.com")
        assert len(calls) == 2

    def test_failure_is_cached_briefly(self, monkeypatch):
        """A failed lookup is cached so a broken endpoint is not hammered.

        One logical lookup may attempt several candidate RDAP endpoints
        (IANA bootstrap, then direct registry fallback), so the assertion
        is on the SECOND get_domain_age call adding zero HTTP attempts.
        """
        calls = _patch_rdap(monkeypatch, lambda url: (_ for _ in ()).throw(OSError("down")))
        get_domain_age("example-tool.com")
        first_round = len(calls)
        assert first_round >= 1
        get_domain_age("example-tool.com")  # served from the failure cache
        assert len(calls) == first_round

    def test_different_domains_cached_separately(self, monkeypatch):
        calls = _patch_rdap(monkeypatch, lambda url: _rdap_response(5))
        get_domain_age("example-tool.com")
        get_domain_age("other-tool.net")
        assert len(calls) == 2


# ── 5. DomainIntelligence / engine integration ──────────────────────────

def _patch_dns_quiet(monkeypatch):
    """Silence the real DNS checks so analyze() stays hermetic."""
    monkeypatch.setattr(DomainIntelligence, "_check_dns_resolution",
                        lambda self, d: True)
    monkeypatch.setattr(DomainIntelligence, "_check_mx_records",
                        lambda self, d: False)


class TestDomainIntelligenceIntegration:

    def test_analyze_exposes_age_and_young_finding(self, monkeypatch):
        _patch_rdap(monkeypatch, lambda url: _rdap_response(5))
        _patch_dns_quiet(monkeypatch)

        intel = DomainIntelligence().analyze("example-tool.com")
        assert intel["domain_age"]["age_known"] is True
        assert intel["domain_age"]["age_category"] == "young"
        assert "domain_age_young" in intel["domain_indicators"]
        rule_ids = [f.rule_id for f in intel["findings"]]
        assert "INTEL_YOUNG_DOMAIN" in rule_ids

    def test_analyze_established_domain_no_age_finding(self, monkeypatch):
        _patch_rdap(monkeypatch, lambda url: _rdap_response(3000))
        _patch_dns_quiet(monkeypatch)

        intel = DomainIntelligence().analyze("example-tool.com")
        assert intel["domain_age"]["age_category"] == "established"
        assert "domain_age_established" in intel["domain_indicators"]
        rule_ids = [f.rule_id for f in intel["findings"]]
        assert AGE_RULE_ID_YOUNG not in rule_ids
        assert "INTEL_DOMAIN_RECENT" not in rule_ids

    def test_analyze_rdap_failure_degrades_gracefully(self, monkeypatch):
        def responder(url):
            raise OSError("no network")

        _patch_rdap(monkeypatch, responder)
        _patch_dns_quiet(monkeypatch)

        intel = DomainIntelligence().analyze("example-tool.com")  # must not raise
        assert intel["domain_age"]["age_known"] is False
        assert not any(
            ind.startswith("domain_age_")
            for ind in intel["domain_indicators"]
        )
        rule_ids = [f.rule_id for f in intel["findings"]]
        assert AGE_RULE_ID_YOUNG not in rule_ids

    def test_empty_domain_still_has_age_shape(self):
        intel = DomainIntelligence().analyze("")
        assert intel["domain_age"]["age_known"] is False
        assert intel["domain_age"]["age_category"] == "unknown"

    def test_engine_receives_age_finding(self, monkeypatch):
        """End-to-end: the age finding flows into DetectionEngine results."""
        from detection.engine import DetectionEngine

        _patch_rdap(monkeypatch, lambda url: _rdap_response(5))
        _patch_dns_quiet(monkeypatch)

        class P:
            sender_email = "warn@example-tool.com"
            sender_name = "Example Tool"
            sender_domain = "example-tool.com"
            urls = []
            anchor_text = ""
            body_text = "Please confirm your account details."
            body_html = ""
            headers = {}
            attachments = []
            spf_result = "pass"
            dkim_result = "pass"
            dmarc_result = "pass"
            received_headers = []
            message_id = ""
            subject = "Welcome"

        results = DetectionEngine().analyze(P())
        rule_ids = [f["rule_id"] for f in results["findings"]]
        assert "INTEL_YOUNG_DOMAIN" in rule_ids
