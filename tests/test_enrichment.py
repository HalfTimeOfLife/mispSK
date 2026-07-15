import pytest
import requests

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


class FakeTag:
    """Minimal fake MISP tag."""

    def __init__(self, name):
        self.name = name


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


def test_enrich_event_extracts_hash_from_composite_filename_type():
    """A 'filename|md5' attribute should be enriched using only the hash
    portion, not the full 'filename|hash' string."""

    event = FakeEvent(
        [
            FakeAttribute(
                "filename|md5",
                "malware.exe|d41d8cd98f00b204e9800998ecf8427e",
            )
        ]
    )

    class FakeVT:
        def __init__(self):
            self.received_value = None

        def lookup_hash(self, value):
            self.received_value = value
            return {
                "malicious": 10,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total": 10,
                "reputation": 0,
            }

    vt = FakeVT()

    results, skipped, stopped = enrich_event(
        event,
        vt,
        None,
        90,
        True,
        FakeMisp(),
    )

    assert skipped == 0
    assert stopped is False
    assert vt.received_value == "d41d8cd98f00b204e9800998ecf8427e"

    assert (
        results["filename|md5"][0][0] == "malware.exe|d41d8cd98f00b204e9800998ecf8427e"
    )


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


def test_enrich_event_extracts_ip_from_composite_port_type():
    """An 'ip-src|port' attribute should be enriched using only the IP
    portion, not the full 'ip|port' string."""

    event = FakeEvent(
        [
            FakeAttribute(
                "ip-src|port",
                "203.0.113.42|8080",
            )
        ]
    )

    class FakeAbuseIPDB:
        def __init__(self):
            self.received_value = None

        def lookup_ip(self, value, max_age_days):
            self.received_value = value
            return {
                "abuse_score": 50,
                "total_reports": 5,
                "country_code": "FR",
                "isp": "Example ISP",
            }

    abuseipdb = FakeAbuseIPDB()

    results, skipped, stopped = enrich_event(
        event,
        None,
        abuseipdb,
        90,
        True,
        FakeMisp(),
    )

    assert skipped == 0
    assert stopped is False
    assert abuseipdb.received_value == "203.0.113.42"
    assert results["ip-src|port"][0][0] == "203.0.113.42|8080"


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


def test_enrich_event_cache_uses_extracted_value_for_composite_types():
    """Two composite attributes with different filenames but the same
    hash should share the cache (one API call, not two)."""

    event = FakeEvent(
        [
            FakeAttribute("filename|sha256", "file_a.exe|samehash"),
            FakeAttribute("filename|sha256", "file_b.dll|samehash"),
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
# --- enrich_event : write mode (not dry_run) ---
# ---------------------------------------------------------------------------


def test_enrich_event_write_mode_updates_comment_and_tag_on_first_run():
    """A first enrichment run (no prior comment/tag) should call both
    update_attribute and tag."""

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

    misp = FakeMisp()

    enrich_event(
        event,
        FakeVT(),
        None,
        90,
        False,
        misp,
    )

    assert len(misp.updated_attributes) == 1
    assert misp.tags == [("fake-uuid", 'enrich:vt="malicious"')]
    assert misp.untags == []


def test_enrich_event_write_mode_skips_tag_when_only_comment_changes():
    """If the classification/tag is unchanged but the comment text would
    differ, only update_attribute should be called, not tag/untag."""

    attribute = FakeAttribute(
        "sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    attribute.comment = "[VT] 10/74 malicious, reputation 100"
    attribute.Tag = [FakeTag('enrich:vt="malicious"')]

    event = FakeEvent([attribute])

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

    misp = FakeMisp()

    enrich_event(
        event,
        FakeVT(),
        None,
        90,
        False,
        misp,
    )

    assert len(misp.updated_attributes) == 1
    assert misp.tags == []
    assert misp.untags == []


def test_enrich_event_write_mode_skips_comment_update_when_only_tag_changes():
    """If the comment is already up to date but the classification tag
    changed, only tag/untag should be called, not update_attribute."""

    attribute = FakeAttribute(
        "sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    attribute.comment = "[VT] 65/74 malicious, reputation 3787"
    attribute.Tag = [FakeTag('enrich:vt="suspicious"')]

    event = FakeEvent([attribute])

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

    misp = FakeMisp()

    enrich_event(
        event,
        FakeVT(),
        None,
        90,
        False,
        misp,
    )

    assert misp.updated_attributes == []
    assert misp.untags == [("fake-uuid", 'enrich:vt="suspicious"')]
    assert misp.tags == [("fake-uuid", 'enrich:vt="malicious"')]


def test_enrich_event_write_mode_no_changes_when_rerun_identically():
    """Re-running enrichment on an attribute already carrying the correct
    comment and tag should not call update_attribute, tag, or untag at all."""

    attribute = FakeAttribute(
        "sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    attribute.comment = "[VT] 65/74 malicious, reputation 3787"
    attribute.Tag = [FakeTag('enrich:vt="malicious"')]

    event = FakeEvent([attribute])

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

    misp = FakeMisp()

    enrich_event(
        event,
        FakeVT(),
        None,
        90,
        False,
        misp,
    )

    assert misp.updated_attributes == []
    assert misp.tags == []
    assert misp.untags == []


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


def test_enrich_event_stops_on_http_error():
    """An unexpected requests.HTTPError from an enricher should stop
    processing gracefully, same as RuntimeError."""

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
            raise requests.HTTPError("500 Server Error")

    results, skipped, stopped = enrich_event(
        event,
        FakeVT(),
        None,
        90,
        True,
        FakeMisp(),
    )

    assert stopped is True
