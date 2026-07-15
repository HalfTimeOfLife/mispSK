import json

import pytest
from pymisp import MISPEvent, MISPGalaxy, MISPGalaxyCluster, MISPOrganisation

from mispsk.utils import (
    extract_summary,
    format_output,
    _get_tlp,
    _get_attack_tags,
    classify_vt_result,
    classify_abuseipdb_result,
    _classify_by_threshold,
    build_enrichment_comment,
    build_enrichment_tag,
    build_tree_output,
)

# ---------------------------------------------------------------------------
# --- fixtures/helpers (event_search) ---
# ---------------------------------------------------------------------------


def _build_event_with_galaxy(namespace, cluster_value):
    """Build a MISPEvent with a single galaxy/cluster attached."""
    cluster = MISPGalaxyCluster()
    cluster.value = cluster_value

    galaxy = MISPGalaxy()
    galaxy.namespace = namespace
    galaxy.GalaxyCluster = [cluster]

    event = MISPEvent()
    event.Galaxy = [galaxy]
    return event


@pytest.fixture
def sample_event():
    """A fully-populated MISPEvent (3 attributes, a TLP tag, an
    ATT&CK galaxy cluster, and an org) reused across extract_summary tests.
    """
    event = MISPEvent()
    event.id = 2
    event.info = "Test event mispSK"
    event.add_attribute("md5", "d41d8cd98f00b204e9800998ecf8427e")
    event.add_attribute("md5", "5d41402abc4b2a76b9719d911017c592")
    event.add_attribute("ip-dst", "203.0.113.42")
    event.add_tag("tlp:amber")

    cluster = MISPGalaxyCluster()
    cluster.value = "Phishing - T1566"
    galaxy = MISPGalaxy()
    galaxy.namespace = "mitre-attack"
    galaxy.GalaxyCluster = [cluster]
    event.Galaxy = [galaxy]

    org = MISPOrganisation()
    org.name = "ADMIN"
    event.Orgc = org

    return event


@pytest.fixture
def sample_summary():
    """A plain summary dict, shaped like extract_summary's output,
    used to test format_output without needing a real MISPEvent.
    """
    return {
        "event_id": 2,
        "event_info": "Test event mispSK",
        "attribute_count": 3,
        "attribute_types": {"md5": 2, "ip-dst": 1},
        "org": "ADMIN",
        "tlp": "tlp:amber",
        "attack_tags": ["Phishing - T1566"],
    }


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
# --- _get_tlp ---
# ---------------------------------------------------------------------------


def test_get_tlp_returns_tlp_tag_when_present():
    """An event with a 'tlp:*' tag should have that tag returned as-is."""
    event = MISPEvent()
    event.add_tag("tlp:amber")

    assert _get_tlp(event) == "tlp:amber"


def test_get_tlp_returns_none_when_absent():
    """An event with tags but none starting with 'tlp:' should return None."""
    event = MISPEvent()
    event.add_tag('misp-galaxy:mitre-attack-pattern="Phishing - T1566"')

    assert _get_tlp(event) is None


# ---------------------------------------------------------------------------
# --- _get_attack_tags ---
# ---------------------------------------------------------------------------


def test_get_attack_tags_returns_matching_clusters():
    """A galaxy in the mitre-attack namespace should have its cluster value
    included in the returned list.
    """
    event = _build_event_with_galaxy("mitre-attack", "Phishing - T1566")

    assert _get_attack_tags(event) == ["Phishing - T1566"]


def test_get_attack_tags_ignores_non_mitre_attack_galaxies():
    """A galaxy outside the mitre-attack namespace should be filtered out,
    even if it has clusters attached.
    """
    event = _build_event_with_galaxy("misp", "Some Other Cluster")

    assert _get_attack_tags(event) == []


def test_get_attack_tags_returns_empty_list_when_no_galaxies():
    """An event with no galaxies at all should return an empty list, not
    raise an error.
    """
    event = MISPEvent()
    event.Galaxy = []

    assert _get_attack_tags(event) == []


# ---------------------------------------------------------------------------
# --- extract_summary ---
# ---------------------------------------------------------------------------


def test_extract_summary_returns_expected_fields(sample_event):
    """The summary dict should contain every expected key, regardless of
    the values themselves.
    """
    summary = extract_summary(sample_event)

    expected_keys = {
        "event_id",
        "event_info",
        "attribute_count",
        "attribute_types",
        "org",
        "tlp",
        "attack_tags",
    }
    assert expected_keys.issubset(summary.keys())


def test_extract_summary_attribute_count_matches_number_of_attributes(sample_event):
    """attribute_count should equal the number of attributes on the event."""
    summary = extract_summary(sample_event)

    assert summary["attribute_count"] == 3


def test_extract_summary_attribute_types_counts_by_type(sample_event):
    """attribute_types should tally attributes correctly per type."""
    summary = extract_summary(sample_event)

    assert summary["attribute_types"] == {"md5": 2, "ip-dst": 1}


# ---------------------------------------------------------------------------
# --- format_output ---
# ---------------------------------------------------------------------------


def test_format_output_json_prints_valid_json(capsys, sample_summary):
    """In JSON mode, the printed output should be valid JSON matching the
    original summary.
    """
    format_output(sample_summary, "json")
    captured = capsys.readouterr()

    parsed = json.loads(captured.out)
    assert parsed == sample_summary


def test_format_output_table_prints_table(capsys, sample_summary):
    """In table mode, key fields and their values should appear in the
    printed output.
    """
    format_output(sample_summary, "table")
    captured = capsys.readouterr()

    assert "event_id" in captured.out
    assert "2" in captured.out
    assert "ADMIN" in captured.out


def test_format_output_table_handles_missing_tlp(capsys, sample_summary):
    """A missing TLP (None) should be displayed as 'Not set', not crash or
    print an empty cell silently.
    """
    sample_summary["tlp"] = None

    format_output(sample_summary, "table")
    captured = capsys.readouterr()

    assert "Not set" in captured.out


def test_format_output_table_handles_empty_attack_tags(capsys, sample_summary):
    """An empty attack_tags list should be displayed as 'None', not crash or
    print an empty cell silently.
    """
    sample_summary["attack_tags"] = []

    format_output(sample_summary, "table")
    captured = capsys.readouterr()

    assert "None" in captured.out


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
