def aggregate_attack_tags(events):
    """Aggregate ATT&CK galaxy clusters across multiple MISP events.

    Args:
        events (list[MISPEvent]): The events to scan.

    Returns:
        dict: Mapping {cluster.value: {"cluster": MISPGalaxyCluster,
            "count": int, "event_ids": [int, ...]}}
            - "cluster" keeps a reference to the actual cluster object,
              needed later by extract_technique_id.
    """
    result = {}
    for event in events:
        for galaxy in event.Galaxy:
            if galaxy.namespace != "mitre-attack":
                continue
            for cluster in galaxy.GalaxyCluster:
                key = cluster.value
                result.setdefault(
                    key, {"cluster": cluster, "count": 0, "event_ids": []}
                )
                result[key]["count"] += 1
                result[key]["event_ids"].append(event.id)
    return result


def extract_technique_id(cluster):
    """Extract the ATT&CK technique ID from a MISP galaxy cluster.

    Args:
        cluster (MISPGalaxyCluster): The galaxy cluster to inspect.

    Returns:
        str or None: The technique ID as found in the cluster's meta,
            or None if not present.
    """
    external_ids = cluster.meta.get("external_id")

    if not external_ids:
        return None

    return external_ids[0]


def compute_score(count, max_count):
    """Normalize an occurrence count into a Navigator score (0-100).

    Args:
        count (int): Number of occurrences of the technique.
        max_count (int): Highest occurrence count observed in this run,
            used as the normalization reference.

    Returns:
        int: Normalized score between 0 and 100.
    """
    if max_count == 0:
        return 0

    return round((count / max_count) * 100)


def build_navigator_layer(technique_counts, layer_name, domain="enterprise-attack"):
    """Build the ATT&CK Navigator layer dict from aggregated technique counts.

    Args:
        technique_counts (dict): Output of aggregate_attack_tags(), i.e.
            {cluster.value: {"cluster": MISPGalaxyCluster, "count": int,
            "event_ids": [int, ...]}}.
        layer_name (str): Name of the Navigator layer.
        domain (str): ATT&CK domain (e.g. "enterprise-attack").

    Returns:
        dict: Layer structure ready for json.dumps()
    """

    max_count = max(data["count"] for data in technique_counts.values())

    techniques = []
    for cluster_value, data in technique_counts.items():
        technique_id = extract_technique_id(data["cluster"])

        if technique_id is None:
            print(
                f"Warning: Could not extract technique ID for cluster: {cluster_value}, skipping"
            )
            continue

        score = compute_score(data["count"], max_count)
        event_ids_str = ", ".join(str(eid) for eid in data["event_ids"])

        techniques.append(
            {
                "techniqueID": technique_id,
                "score": score,
                "comment": f"Seen in events: {event_ids_str}",
            }
        )

    return {
        "name": layer_name,
        "versions": {"attack": "19", "navigator": "4.9.1", "layer": "4.5"},
        "domain": domain,
        "techniques": techniques,
    }
