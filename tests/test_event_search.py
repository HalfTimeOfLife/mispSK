import json
 
import pytest
from pymisp import MISPEvent, MISPGalaxy, MISPGalaxyCluster, MISPOrganisation
 
from mispsk.utils import extract_summary, format_output, _get_tlp, _get_attack_tags

# -------------------------------------------------------------------
# --- fixtures/helpers ---
# -------------------------------------------------------------------

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




# -------------------------------------------------------------------
# --- _get_tlp ---
# -------------------------------------------------------------------

def test_get_tlp_returns_tlp_tag_when_present():
    """An event with a 'tlp:*' tag should have that tag returned as-is."""
    event = MISPEvent()
    event.add_tag("tlp:amber")
 
    assert _get_tlp(event) == "tlp:amber"
 
 
def test_get_tlp_returns_none_when_absent():
    """An event with tags but none starting with 'tlp:' should return None."""
    event = MISPEvent()
    event.add_tag("misp-galaxy:mitre-attack-pattern=\"Phishing - T1566\"")
 
    assert _get_tlp(event) is None


# -------------------------------------------------------------------
# --- _get_attack_tags ---
# -------------------------------------------------------------------

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


# -------------------------------------------------------------------
# --- extract_summary ---
# -------------------------------------------------------------------

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


# -------------------------------------------------------------------
# --- format_output ---
# -------------------------------------------------------------------

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
