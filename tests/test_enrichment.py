import pytest

from mispsk.enrichment import enrich_event


# ---------------------------------------------------------------------------
# --- fixtures/helpers ---
# ---------------------------------------------------------------------------


class FakeAttribute:
    """Minimal fake MISP attribute used for enrichment tests."""

    def __init__(self, attr_type, value):
        self.type = attr_type
        self.value = value
        self.comment = ""
        self.uuid = "fake-uuid"
        self.Tag = []


class FakeEvent:
    """Minimal fake MISP event used for enrichment tests."""

    def __init__(self, attributes):
        self.Attribute = attributes
        self.id = 1
        self.info = "Test enrichment event"


class FakeMisp:
    """Fake PyMISP client recording write operations."""

    def __init__(self):
        self.updated_attributes = []
        self.tags = []
        self.untags = []

    def update_attribute(self, attribute):
        self.updated_attributes.append(attribute)

    def tag(self, uuid, tag):
        self.tags.append((uuid, tag))

    def untag(self, uuid, tag):
        self.untags.append((uuid, tag))


# ---------------------------------------------------------------------------
# --- enrich_event : VirusTotal ---
# ---------------------------------------------------------------------------


def test_enrich_event_enriches_hash_with_virustotal():
    """A supported hash attribute should be enriched through VirusTotal."""

    event = FakeEvent(
        [
            FakeAttribute(
                "sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
        ]
    )

    class FakeVT:
        def lookup_hash(self, value):
            return {
                "malicious": 65,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 9,
                "total": 74,
                "reputation": 3787,
            }

    results, skipped, stopped = enrich_event(
        event,
        FakeVT(),
        None,
        90,
        True,
        FakeMisp(),
    )

    assert skipped == 0
    assert stopped is False

    assert "sha256" in results
    assert results["sha256"][0][0] == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


# ---------------------------------------------------------------------------
# --- enrich_event : AbuseIPDB ---
# ---------------------------------------------------------------------------


def test_enrich_event_enriches_ip_with_abuseipdb():
    """A supported IP attribute should be enriched through AbuseIPDB."""

    event = FakeEvent(
        [
            FakeAttribute(
                "ip-src",
                "8.8.8.8",
            )
        ]
    )

    class FakeAbuseIPDB:
        def lookup_ip(self, value, max_age_days):
            assert value == "8.8.8.8"
            assert max_age_days == 30

            return {
                "abuse_score": 100,
                "total_reports": 10,
                "country_code": "US",
                "isp": "Google",
            }

    results, skipped, stopped = enrich_event(
        event,
        None,
        FakeAbuseIPDB(),
        30,
        True,
        FakeMisp(),
    )

    assert skipped == 0
    assert stopped is False

    assert "ip-src" in results


# ---------------------------------------------------------------------------
# --- enrich_event : skipped attributes ---
# ---------------------------------------------------------------------------


def test_enrich_event_skips_unsupported_attribute_type():
    """Unsupported MISP attribute types should be skipped."""

    event = FakeEvent(
        [
            FakeAttribute(
                "domain",
                "example.com",
            )
        ]
    )

    results, skipped, stopped = enrich_event(
        event,
        None,
        None,
        90,
        True,
        FakeMisp(),
    )

    assert results == {}
    assert skipped == 1
    assert stopped is False


def test_enrich_event_skips_hash_when_vt_is_not_configured():
    """Hash attributes should be skipped when VirusTotal is unavailable."""

    event = FakeEvent(
        [
            FakeAttribute(
                "md5",
                "d41d8cd98f00b204e9800998ecf8427e",
            )
        ]
    )

    results, skipped, stopped = enrich_event(
        event,
        None,
        None,
        90,
        True,
        FakeMisp(),
    )

    assert results == {}
    assert skipped == 1
    assert stopped is False


# ---------------------------------------------------------------------------
# --- enrich_event : cache ---
# ---------------------------------------------------------------------------


def test_enrich_event_uses_cache_for_duplicate_attributes():
    """Duplicate IOC values should only trigger one API lookup."""

    event = FakeEvent(
        [
            FakeAttribute("sha256", "samehash"),
            FakeAttribute("sha256", "samehash"),
        ]
    )

    class FakeVT:
        def __init__(self):
            self.calls = 0

        def lookup_hash(self, value):
            self.calls += 1

            return {
                "malicious": 1,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 10,
                "total": 11,
                "reputation": 0,
            }

    vt = FakeVT()

    enrich_event(
        event,
        vt,
        None,
        90,
        True,
        FakeMisp(),
    )

    assert vt.calls == 1


# ---------------------------------------------------------------------------
# --- enrich_event : dry-run ---
# ---------------------------------------------------------------------------


def test_enrich_event_dry_run_does_not_update_misp():
    """Dry-run mode should not write comments or tags to MISP."""

    event = FakeEvent(
        [
            FakeAttribute(
                "md5",
                "d41d8cd98f00b204e9800998ecf8427e",
            )
        ]
    )

    class FakeVT:
        def lookup_hash(self, value):
            return {
                "malicious": 10,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total": 10,
                "reputation": 0,
            }

    misp = FakeMisp()

    enrich_event(
        event,
        FakeVT(),
        None,
        90,
        True,
        misp,
    )

    assert misp.updated_attributes == []
    assert misp.tags == []


# ---------------------------------------------------------------------------
# --- enrich_event : API errors ---
# ---------------------------------------------------------------------------


def test_enrich_event_stops_on_runtime_error():
    """A RuntimeError from an enricher should stop processing."""

    event = FakeEvent(
        [
            FakeAttribute(
                "sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
        ]
    )

    class FakeVT:
        def lookup_hash(self, value):
            raise RuntimeError("VirusTotal rate limit exceeded")

    results, skipped, stopped = enrich_event(
        event,
        FakeVT(),
        None,
        90,
        True,
        FakeMisp(),
    )

    assert stopped is True
