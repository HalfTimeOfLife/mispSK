from pymisp import MISPEvent, MISPGalaxy, MISPGalaxyCluster

from mispsk.attack_layer import (
    extract_technique_id,
    compute_score,
    aggregate_attack_tags,
    build_navigator_layer,
)

# ---------------------------------------------------------------------------
# --- fixtures/helpers ---
# ---------------------------------------------------------------------------


def _build_cluster(value, external_id=None, extra_meta=None):
    """Build a MISPGalaxyCluster with an optional external_id in meta."""
    cluster = MISPGalaxyCluster()
    cluster.value = value
    meta = dict(extra_meta) if extra_meta else {}
    if external_id is not None:
        meta["external_id"] = [external_id]
    cluster.meta = meta
    return cluster


def _build_event_with_clusters(event_id, namespace, clusters):
    """Build a MISPEvent with a single galaxy holding the given clusters."""
    galaxy = MISPGalaxy()
    galaxy.namespace = namespace
    galaxy.GalaxyCluster = clusters

    event = MISPEvent()
    event.id = event_id
    event.Galaxy = [galaxy]
    return event


# ---------------------------------------------------------------------------
# --- extract_technique_id ---
# ---------------------------------------------------------------------------


def test_extract_technique_id_returns_id_when_present():
    """A cluster with external_id in meta should return that ID."""
    cluster = _build_cluster("Phishing - T1566", external_id="T1566")

    assert extract_technique_id(cluster) == "T1566"


def test_extract_technique_id_returns_none_when_meta_empty():
    """A cluster with no meta at all should return None."""
    cluster = _build_cluster("Phishing - T1566")

    assert extract_technique_id(cluster) is None


def test_extract_technique_id_returns_none_when_external_id_missing():
    """A cluster with meta present but no external_id key should return None."""
    cluster = _build_cluster(
        "Phishing - T1566", extra_meta={"kill_chain": ["attack-Linux:initial-access"]}
    )

    assert extract_technique_id(cluster) is None


def test_extract_technique_id_returns_first_id_when_multiple_present():
    """If external_id somehow holds multiple values, the first one should be used."""
    cluster = _build_cluster(
        "Phishing - T1566", extra_meta={"external_id": ["T1566", "T9999"]}
    )

    assert extract_technique_id(cluster) == "T1566"


# ---------------------------------------------------------------------------
# --- compute_score ---
# ---------------------------------------------------------------------------


def test_compute_score_returns_100_when_count_equals_max():
    """A technique matching the max count should score 100."""
    assert compute_score(3, 3) == 100


def test_compute_score_returns_proportional_score():
    """A count below max should return a proportionally lower score."""
    assert compute_score(1, 3) == 33


def test_compute_score_returns_0_when_max_count_is_zero():
    """max_count of 0 should return 0, not raise a ZeroDivisionError."""
    assert compute_score(0, 0) == 0


# ---------------------------------------------------------------------------
# --- aggregate_attack_tags ---
# ---------------------------------------------------------------------------


def test_aggregate_attack_tags_counts_single_cluster_single_event():
    """A single event with a single mitre-attack cluster should produce
    one entry with count 1."""
    cluster = _build_cluster("Phishing - T1566", external_id="T1566")
    event = _build_event_with_clusters(1659, "mitre-attack", [cluster])

    result = aggregate_attack_tags([event])

    assert result["Phishing - T1566"]["count"] == 1
    assert result["Phishing - T1566"]["event_ids"] == [1659]
    assert result["Phishing - T1566"]["cluster"] is cluster


def test_aggregate_attack_tags_counts_shared_cluster_across_events():
    """The same cluster appearing in multiple events should increment the
    count and collect all event IDs."""
    cluster_a = _build_cluster("Phishing - T1566", external_id="T1566")
    cluster_b = _build_cluster("Phishing - T1566", external_id="T1566")

    event_1 = _build_event_with_clusters(1660, "mitre-attack", [cluster_a])
    event_2 = _build_event_with_clusters(1659, "mitre-attack", [cluster_b])

    result = aggregate_attack_tags([event_1, event_2])

    assert result["Phishing - T1566"]["count"] == 2
    assert result["Phishing - T1566"]["event_ids"] == [1660, 1659]


def test_aggregate_attack_tags_handles_multiple_clusters_per_event():
    """An event with several clusters should produce one entry per cluster."""
    cluster_a = _build_cluster(
        "Command and Scripting Interpreter - T1059", external_id="T1059"
    )
    cluster_b = _build_cluster("Phishing - T1566", external_id="T1566")

    event = _build_event_with_clusters(1659, "mitre-attack", [cluster_a, cluster_b])

    result = aggregate_attack_tags([event])

    assert set(result.keys()) == {
        "Command and Scripting Interpreter - T1059",
        "Phishing - T1566",
    }


def test_aggregate_attack_tags_ignores_non_mitre_attack_galaxies():
    """Galaxies outside the mitre-attack namespace should be ignored entirely."""
    cluster = _build_cluster("Some Other Cluster")
    event = _build_event_with_clusters(1659, "misp", [cluster])

    result = aggregate_attack_tags([event])

    assert result == {}


def test_aggregate_attack_tags_returns_empty_dict_when_no_events():
    """An empty event list should return an empty dict, not raise."""
    assert aggregate_attack_tags([]) == {}


# ---------------------------------------------------------------------------
# --- build_navigator_layer ---
# ---------------------------------------------------------------------------


def test_build_navigator_layer_includes_expected_fields():
    """The layer dict should include name, versions, domain, and techniques."""
    cluster = _build_cluster("Phishing - T1566", external_id="T1566")
    technique_counts = {
        "Phishing - T1566": {"cluster": cluster, "count": 1, "event_ids": [1659]}
    }

    layer = build_navigator_layer(technique_counts, "Test layer", "enterprise-attack")

    assert layer["name"] == "Test layer"
    assert layer["domain"] == "enterprise-attack"
    assert "versions" in layer
    assert len(layer["techniques"]) == 1


def test_build_navigator_layer_computes_correct_scores():
    """Techniques should be scored relative to the highest count in the batch."""
    cluster_a = _build_cluster(
        "Command and Scripting Interpreter - T1059", external_id="T1059"
    )
    cluster_b = _build_cluster("Phishing - T1566", external_id="T1566")
    cluster_c = _build_cluster("Brute Force - T1110", external_id="T1110")

    technique_counts = {
        "Command and Scripting Interpreter - T1059": {
            "cluster": cluster_a,
            "count": 3,
            "event_ids": [1661, 1660, 1659],
        },
        "Phishing - T1566": {
            "cluster": cluster_b,
            "count": 2,
            "event_ids": [1660, 1659],
        },
        "Brute Force - T1110": {"cluster": cluster_c, "count": 1, "event_ids": [1659]},
    }

    layer = build_navigator_layer(technique_counts, "Test layer")
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}

    assert scores == {"T1059": 100, "T1566": 67, "T1110": 33}


def test_build_navigator_layer_formats_comment_with_event_ids():
    """Each technique's comment should list the event IDs it was seen in."""
    cluster = _build_cluster("Phishing - T1566", external_id="T1566")
    technique_counts = {
        "Phishing - T1566": {"cluster": cluster, "count": 2, "event_ids": [1660, 1659]}
    }

    layer = build_navigator_layer(technique_counts, "Test layer")

    assert layer["techniques"][0]["comment"] == "Seen in events: 1660, 1659"


def test_build_navigator_layer_skips_clusters_without_technique_id():
    """A cluster with no resolvable technique ID should be excluded from
    the output, without raising an error."""
    cluster_valid = _build_cluster("Phishing - T1566", external_id="T1566")
    cluster_invalid = _build_cluster("Unknown Cluster")

    technique_counts = {
        "Phishing - T1566": {"cluster": cluster_valid, "count": 1, "event_ids": [1659]},
        "Unknown Cluster": {
            "cluster": cluster_invalid,
            "count": 1,
            "event_ids": [1659],
        },
    }

    layer = build_navigator_layer(technique_counts, "Test layer")

    technique_ids = [t["techniqueID"] for t in layer["techniques"]]
    assert technique_ids == ["T1566"]


def test_build_navigator_layer_returns_empty_techniques_when_all_skipped():
    """If no cluster can be mapped to a technique ID, techniques should be
    an empty list, not raise."""
    cluster_invalid = _build_cluster("Unknown Cluster")
    technique_counts = {
        "Unknown Cluster": {"cluster": cluster_invalid, "count": 1, "event_ids": [1659]}
    }

    layer = build_navigator_layer(technique_counts, "Test layer")

    assert layer["techniques"] == []
