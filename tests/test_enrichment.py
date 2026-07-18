import pytest
import requests

from mispsk.enrichment import enrich_event

from mispsk.enrichment import (
    classify_vt_result,
    classify_abuseipdb_result,
    _classify_by_threshold,
    build_enrichment_comment,
    build_enrichment_tag,
    build_tree_output,
)


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
# --- fixtures (ioc_enrich classification) ---
# ---------------------------------------------------------------------------


@pytest.fixture
def vt_stats_malicious():
    """VT stats well above VT_MALICIOUS_THRESHOLD."""
    return {"malicious": 65}


@pytest.fixture
def vt_stats_malicious_exact_threshold():
    """VT stats exactly at VT_MALICIOUS_THRESHOLD (5)."""
    return {"malicious": 5}


@pytest.fixture
def vt_stats_suspicious():
    """VT stats between VT_SUSPICIOUS_THRESHOLD (1) and VT_MALICIOUS_THRESHOLD (5)."""
    return {"malicious": 2}


@pytest.fixture
def vt_stats_clean():
    """VT stats with zero malicious detections."""
    return {"malicious": 0}


@pytest.fixture
def abuseipdb_score_high_risk():
    """AbuseIPDB score well above ABUSEIPDB_HIGH_RISK_THRESHOLD (75)."""
    return 100


@pytest.fixture
def abuseipdb_score_high_risk_exact_threshold():
    """AbuseIPDB score exactly at ABUSEIPDB_HIGH_RISK_THRESHOLD (75)."""
    return 75


@pytest.fixture
def abuseipdb_score_suspicious():
    """AbuseIPDB score between ABUSEIPDB_SUSPICIOUS_THRESHOLD (25) and
    ABUSEIPDB_HIGH_RISK_THRESHOLD (75)."""
    return 42


@pytest.fixture
def abuseipdb_score_low_risk():
    """AbuseIPDB score below ABUSEIPDB_SUSPICIOUS_THRESHOLD (25)."""
    return 0


# ---------------------------------------------------------------------------
# --- classify_vt_result / classify_abuseipdb_result / _classify_by_threshold ---
# ---------------------------------------------------------------------------


def test_classify_vt_result_returns_malicious_above_threshold(vt_stats_malicious):
    """malicious count well above VT_MALICIOUS_THRESHOLD should classify as
    'malicious'."""
    result = classify_vt_result(vt_stats_malicious)

    assert result == "malicious"


def test_classify_vt_result_returns_malicious_at_exact_threshold(
    vt_stats_malicious_exact_threshold,
):
    """malicious count exactly equal to VT_MALICIOUS_THRESHOLD (5) should
    still classify as 'malicious' (boundary is inclusive, >=)."""
    result = classify_vt_result(vt_stats_malicious_exact_threshold)

    assert result == "malicious"


def test_classify_vt_result_returns_suspicious(vt_stats_suspicious):
    """malicious count between 1 and 4 should classify as 'suspicious'."""
    result = classify_vt_result(vt_stats_suspicious)

    assert result == "suspicious"


def test_classify_vt_result_returns_clean(vt_stats_clean):
    """malicious count of 0 should classify as 'clean'."""
    result = classify_vt_result(vt_stats_clean)

    assert result == "clean"


def test_classify_abuseipdb_result_returns_high_risk(abuseipdb_score_high_risk):
    """Score >= 75 should classify as 'high-risk'."""
    result = classify_abuseipdb_result(abuseipdb_score_high_risk)

    assert result == "high-risk"


def test_classify_abuseipdb_result_returns_suspicious(abuseipdb_score_suspicious):
    """Score between 25 and 74 should classify as 'suspicious'."""
    result = classify_abuseipdb_result(abuseipdb_score_suspicious)

    assert result == "suspicious"


def test_classify_abuseipdb_result_returns_low_risk(abuseipdb_score_low_risk):
    """Score below 25 should classify as 'low-risk'."""
    result = classify_abuseipdb_result(abuseipdb_score_low_risk)

    assert result == "low-risk"


def test_classify_by_threshold_returns_first_matching_label():
    """Given an ordered list of thresholds, the first one the value meets
    or exceeds should be returned."""
    thresholds = [(10, "high"), (5, "medium"), (0, "low")]

    result = _classify_by_threshold(7, thresholds)

    assert result == "medium"


def test_classify_by_threshold_falls_back_to_last_label():
    """A value below every threshold's min_value should still return the
    last label in the list (the catch-all, e.g. 0)."""
    thresholds = [(10, "high"), (5, "medium"), (0, "low")]

    result = _classify_by_threshold(-3, thresholds)

    assert result == "low"


# ---------------------------------------------------------------------------
# --- build_enrichment_comment ---
# ---------------------------------------------------------------------------


def test_build_enrichment_comment_formats_vt_result():
    """A VT result dict should produce a '[VT] X/Y malicious, reputation Z'
    style comment."""
    result = {
        "malicious": 65,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 9,
        "total": 74,
        "reputation": 3787,
    }

    comment = build_enrichment_comment("vt", result)

    assert comment == "[VT] 65/74 malicious, reputation 3787"


def test_build_enrichment_comment_formats_abuseipdb_result():
    """An AbuseIPDB result dict should produce a '[AbuseIPDB] score X/100,
    Y reports, CC' style comment."""
    result = {
        "abuse_score": 0,
        "total_reports": 121,
        "country_code": "US",
        "isp": "Google LLC",
    }

    comment = build_enrichment_comment("abuseipdb", result)

    assert comment == "[AbuseIPDB] score 0/100, 121 reports, US"


def test_build_enrichment_comment_handles_none_result_for_vt():
    """A None result with source='vt' should return the VT-specific
    'no result' message."""
    comment = build_enrichment_comment("vt", None)

    assert comment == "[VT] no result (hash unknown to VirusTotal)"


def test_build_enrichment_comment_handles_none_result_for_abuseipdb():
    """A None result with source='abuseipdb' should return the
    AbuseIPDB-specific 'no result' message."""
    comment = build_enrichment_comment("abuseipdb", None)

    assert comment == "[AbuseIPDB] no result"


def test_build_enrichment_comment_raises_on_unknown_source():
    """An unrecognized source string should raise ValueError."""
    with pytest.raises(ValueError, match="Unknown enrichment source"):
        build_enrichment_comment("unknow_source", None)


# ---------------------------------------------------------------------------
# --- build_enrichment_tag ---
# ---------------------------------------------------------------------------


def test_build_enrichment_tag_returns_vt_malicious_tag():
    """A malicious VT result should produce 'enrich:vt="malicious"'."""
    result = {
        "malicious": 65,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 9,
        "total": 74,
        "reputation": 3787,
    }

    tag = build_enrichment_tag("vt", result)

    assert tag == 'enrich:vt="malicious"'


def test_build_enrichment_tag_returns_abuseipdb_high_risk_tag():
    """A high-risk AbuseIPDB result should produce
    'enrich:abuseipdb="high-risk"'."""
    result = {
        "abuse_score": 100,
        "total_reports": 166,
        "country_code": "DE",
        "isp": "Example Hosting LLC",
    }

    tag = build_enrichment_tag("abuseipdb", result)

    assert tag == 'enrich:abuseipdb="high-risk"'


def test_build_enrichment_tag_returns_unknown_tag_when_result_is_none():
    """A None result should produce 'enrich:{source}="unknown"' without
    calling classify_vt_result/classify_abuseipdb_result."""
    tag_vt = build_enrichment_tag("vt", None)
    tag_abuseipdb = build_enrichment_tag("abuseipdb", None)

    assert tag_vt == 'enrich:vt="unknown"'
    assert tag_abuseipdb == 'enrich:abuseipdb="unknown"'


def test_build_enrichment_tag_raises_on_unknown_source():
    """An unrecognized source string should raise ValueError."""
    with pytest.raises(ValueError, match="Unknown enrichment source"):
        build_enrichment_tag("unknown_source", None)


# ---------------------------------------------------------------------------
# --- build_tree_output ---
# ---------------------------------------------------------------------------


def test_build_tree_output_prints_event_header(capsys):
    """The tree output should start with the event ID and info."""
    enrichment_results = {
        "md5": [
            (
                "44d88612fea8a8f36de82e1278abb02f",
                "[VT] 65/74 malicious, reputation 3787",
                'enrich:vt="malicious"',
            )
        ],
    }

    build_tree_output(
        event_id=3,
        event_info="ioc_enrich_test",
        enrichment_results=enrichment_results,
        skipped_count=0,
        dry_run=False,
    )

    captured = capsys.readouterr()
    assert 'Event #3 — "ioc_enrich_test"' in captured.out


def test_build_tree_output_groups_by_attribute_type(capsys):
    """Attributes should be grouped under their type (md5, ip-dst, ...),
    each group showing its attribute count."""
    enrichment_results = {
        "md5": [
            (
                "44d88612fea8a8f36de82e1278abb02f",
                "[VT] 65/74 malicious, reputation 3787",
                'enrich:vt="malicious"',
            ),
            (
                "5d41402abc4b2a76b9719d911017c592",
                "[VT] 0/74 malicious, reputation 0",
                'enrich:vt="clean"',
            ),
        ],
        "ip-dst": [
            (
                "8.8.8.8",
                "[AbuseIPDB] score 0/100, 121 reports, US",
                'enrich:abuseipdb="low-risk"',
            ),
        ],
    }

    build_tree_output(
        event_id=3,
        event_info="ioc_enrich_test",
        enrichment_results=enrichment_results,
        skipped_count=0,
        dry_run=False,
    )

    captured = capsys.readouterr()
    assert "md5 (2 attributes)" in captured.out
    assert "ip-dst (1 attribute)" in captured.out


def test_build_tree_output_hides_tag_suffix_for_unknown_results(capsys):
    """An entry whose tag ends with '="unknown"' should not show the
    ' -> enrich:...' suffix in its printed line."""
    enrichment_results = {
        "sha256": [
            (
                "3a4348327da5b72b70e265b2c1205e030d6828bc893322deff9c001890600fff",
                "[VT] no result (hash unknown to VirusTotal)",
                'enrich:vt="unknown"',
            )
        ],
    }

    build_tree_output(
        event_id=3,
        event_info="ioc_enrich_test",
        enrichment_results=enrichment_results,
        skipped_count=0,
        dry_run=False,
    )

    captured = capsys.readouterr()
    assert "[VT] no result (hash unknown to VirusTotal)" in captured.out
    assert '→ enrich:vt="unknown"' not in captured.out


def test_build_tree_output_summary_counts_are_correct(capsys):
    """The summary line should correctly report processed, enriched,
    no-result, and skipped counts."""
    enrichment_results = {
        "sha1": [
            (
                "3395856ce81f2b7382dee72602f798b642f14140",
                "[VT] 65/74 malicious, reputation 3787",
                'enrich:vt="malicious"',
            )
        ],
    }

    build_tree_output(
        event_id=3,
        event_info="ioc_enrich_test",
        enrichment_results=enrichment_results,
        skipped_count=0,
        dry_run=False,
    )

    captured = capsys.readouterr()
    assert "[VT] 65/74 malicious, reputation 3787" in captured.out
    assert '→ enrich:vt="malicious"' in captured.out


def test_build_tree_output_shows_dry_run_marker_when_true(capsys):
    """dry_run=True should print the '[DRY-RUN]' marker at the end."""
    enrichment_results = {
        "sha1": [
            (
                "3395856ce81f2b7382dee72602f798b642f14140",
                "[VT] 65/74 malicious, reputation 3787",
                'enrich:vt="malicious"',
            )
        ],
    }

    build_tree_output(
        event_id=3,
        event_info="ioc_enrich_test",
        enrichment_results=enrichment_results,
        skipped_count=0,
        dry_run=True,
    )

    captured = capsys.readouterr()
    assert "[DRY-RUN] No changes written to MISP" in captured.out


def test_build_tree_output_omits_dry_run_marker_when_false(capsys):
    """dry_run=False should not print the '[DRY-RUN]' marker."""
    enrichment_results = {
        "sha1": [
            (
                "3395856ce81f2b7382dee72602f798b642f14140",
                "[VT] 65/74 malicious, reputation 3787",
                'enrich:vt="malicious"',
            )
        ],
    }

    build_tree_output(
        event_id=3,
        event_info="ioc_enrich_test",
        enrichment_results=enrichment_results,
        skipped_count=0,
        dry_run=False,
    )

    captured = capsys.readouterr()
    assert "[DRY-RUN] No changes written to MISP" not in captured.out


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
