import json
from tabulate import tabulate
from collections import Counter
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# --- Enrichment type constants (ioc_enrich.py) ---
# ---------------------------------------------------------------------------

HASH_TYPES = {"md5", "sha1", "sha256"}
IP_TYPES = {"ip-src", "ip-dst"}

COMPOSITE_HASH_TYPES = {"filename|md5", "filename|sha1", "filename|sha256"}
COMPOSITE_IP_TYPES = {"ip-src|port", "ip-dst|port"}

# Position of the actual IOC value within a composite type's "part1|part2".
# True = IOC is the first segment, False = IOC is the second segment.
COMPOSITE_IOC_POSITION = {
    "filename|md5": False,
    "filename|sha1": False,
    "filename|sha256": False,
    "ip-src|port": True,
    "ip-dst|port": True,
}

# ---------------------------------------------------------------------------
# --- Classification thresholds ---
# ---------------------------------------------------------------------------

VT_THRESHOLDS = [
    (5, "malicious"),
    (1, "suspicious"),
    (0, "clean"),
]

ABUSEIPDB_THRESHOLDS = [
    (75, "high-risk"),
    (25, "suspicious"),
    (0, "low-risk"),
]

# ---------------------------------------------------------------------------
# --- helper ---
# ---------------------------------------------------------------------------


def extract_ioc_value(attribute_type, attribute_value):
    """Extract the actual hash/IP value from a (possibly composite) attribute.

    Args:
        attribute_type (str): The MISP attribute type (e.g. "md5", "filename|md5").
        attribute_value (str): The raw attribute value.

    Returns:
        str: The hash/IP portion to use for lookups and caching.

    Raises:
        ValueError: If attribute_type is composite but not a recognized
            composite type (position unknown).
    """
    if "|" not in attribute_type:
        return attribute_value

    if attribute_type not in COMPOSITE_IOC_POSITION:
        raise ValueError(f"Unknown composite type, cannot locate IOC: {attribute_type}")

    parts = attribute_value.split("|", 1)
    ioc_is_first = COMPOSITE_IOC_POSITION[attribute_type]
    return parts[0] if ioc_is_first else parts[1]


def get_age(timestamp):
    """Compute the age (in days) of a MISP epoch timestamp.

    Args:
        timestamp (str, int, or datetime): A MISP-style Unix epoch
            timestamp, or an already-resolved datetime.

    Returns:
        int or None: Age in days, or None if timestamp could not be
            parsed (caller must treat this as "unknown", not "ok").
    """
    if isinstance(timestamp, datetime):
        dt = timestamp
    else:
        try:
            dt = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
        except (TypeError, ValueError):
            return None

    return (datetime.now(timezone.utc) - dt).days


# ---------------------------------------------------------------------------
# --- Event summary helpers (event_search.py) ---
# ---------------------------------------------------------------------------


def _get_tlp(event):
    """Extract the TLP tag from a MISP event, if present.

    Args:
        event (MISPEvent): The event to inspect.

    Returns:
        str or None: The TLP tag name or None if not set.
    """
    for tag in event.Tag:
        if tag.name.startswith("tlp:"):
            return tag.name
    return None


def _get_attack_tags(event):
    """Extract MITRE ATT&CK cluster values attached to a MISP event.

    Args:
        event (MISPEvent): The event to inspect.

    Returns:
        list[str]: A list of ATT&CK cluster values.
    """
    tags = []
    for galaxy in event.Galaxy:
        if galaxy.namespace == "mitre-attack":
            for cluster in galaxy.GalaxyCluster:
                tags.append(cluster.value)
    return tags


def extract_summary(event):
    """Build a readable summary of key fields from a MISP event.

    Args:
        event (MISPEvent): The event to summarize.

    Returns:
        dict: Summary containing event_id, event_info, attribute_count,
            attribute_types, org, tlp, and attack_tags.
    """
    summary = {}
    summary["event_id"] = event.id
    summary["event_info"] = event.info
    summary["attribute_count"] = len(event.Attribute)
    summary["attribute_types"] = dict(Counter(attr.type for attr in event.Attribute))
    summary["org"] = event.Orgc.name
    summary["tlp"] = _get_tlp(event)
    summary["attack_tags"] = _get_attack_tags(event)
    return summary


def format_output(summary, output_format):
    """Print a summary dict in the requested format.

    Args:
        summary (dict): The summary to display, as returned by extract_summary.
        output_format (str): The output format, either "table" or "json".

    Returns:
        None
    """
    if output_format == "json":
        print(json.dumps(summary, indent=2))
        return
    else:
        display = dict(summary)
        display["attribute_types"] = ", ".join(
            f"{k}: {v}" for k, v in summary["attribute_types"].items()
        )
        display["attack_tags"] = (
            ", ".join(summary["attack_tags"]) if summary["attack_tags"] else "None"
        )
        display["tlp"] = summary["tlp"] if summary["tlp"] else "Not set"

        rows = [[key, value] for key, value in display.items()]
        print(tabulate(rows, headers=["Field", "Value"], tablefmt="rounded_grid"))


# ---------------------------------------------------------------------------
# --- Enrichment classification helpers (ioc_enrich.py) ---
# ---------------------------------------------------------------------------


def _classify_by_threshold(value, thresholds):
    """Return the label of the first threshold the value meets or exceeds.

    Args:
        value (int): The raw score/count to classify.
        thresholds (list[tuple[int, str]]): (min_value, label) pairs,
            ordered from highest min_value to lowest.

    Returns:
        str: The matching label.
    """
    for min_value, label in thresholds:
        if value >= min_value:
            return label
    return thresholds[-1][1]


def classify_vt_result(stats):
    """Classify a VirusTotal analysis result into a threat level.

    Args:
        stats (dict): VirusTotal `last_analysis_stats` dict, as returned by
            VTEnricher.lookup_hash.

    Returns:
        str: One of "malicious", "suspicious", or "clean".
    """
    return _classify_by_threshold(stats["malicious"], VT_THRESHOLDS)


def classify_abuseipdb_result(score):
    """Classify an AbuseIPDB confidence score into a risk level.

    Args:
        score (int): AbuseIPDB abuseConfidenceScore, 0-100.

    Returns:
        str: One of "high-risk", "suspicious", or "low-risk".
    """
    return _classify_by_threshold(score, ABUSEIPDB_THRESHOLDS)


# ---------------------------------------------------------------------------
# --- Enrichment formatting helpers (ioc_enrich.py) ---
# ---------------------------------------------------------------------------


def build_enrichment_comment(source, result):
    """Build a human-readable comment summarizing an enrichment result.

    Args:
        source (str): Enrichment source identifier, "vt" or "abuseipdb".
        result (dict or None): Normalized enrichment result from the
            corresponding enricher, or None if no result was found.

    Returns:
        str: A one-line comment to attach to the MISP attribute.
            Returns a "no result" message when result is None.

    Raises:
        ValueError: If source is not "vt" or "abuseipdb".
    """
    if source not in ("vt", "abuseipdb"):
        raise ValueError(f"Unknown enrichment source: {source}")

    if result is None:
        if source == "vt":
            return "[VT] no result (hash unknown to VirusTotal)"
        return "[AbuseIPDB] no result"

    if source == "vt":
        return (
            f"[VT] {result['malicious']}/{result['total']} malicious, "
            f"reputation {result['reputation']}"
        )
    return (
        f"[AbuseIPDB] score {result['abuse_score']}/100, "
        f"{result['total_reports']} reports, {result['country_code']}"
    )


def merge_enrichment_comment(existing_comment, new_comment, source):
    """Merge a new enrichment comment into an attribute's existing comment,
    replacing any previous comment line from the same source while
    preserving manual/unrelated comment lines.

    Args:
        existing_comment (str or None): The attribute's current comment,
            possibly containing prior enrichment lines and/or manual notes.
        new_comment (str): The freshly built enrichment comment line to add
            (as returned by build_enrichment_comment).
        source (str): Enrichment source identifier, "vt" or "abuseipdb",
            used to identify which prefix to strip ("[VT] " or
            "[AbuseIPDB] ").

    Returns:
        str: The merged comment, with any prior same-source enrichment
            line replaced by new_comment, and all other lines preserved.
    """
    prefix = "[VT] " if source == "vt" else "[AbuseIPDB] "

    if not existing_comment:
        return new_comment

    kept_lines = [
        line for line in existing_comment.split("\n") if not line.startswith(prefix)
    ]
    kept_lines.append(new_comment)

    return "\n".join(kept_lines)


def build_enrichment_tag(source, result):
    """Build a MISP enrichment tag string from a classified result.

    Args:
        source (str): Enrichment source identifier, "vt" or "abuseipdb".
        result (dict or None): Normalized enrichment result, or None if
            no result was found.

    Returns:
        str: A MISP tag string, e.g. 'enrich:vt="malicious"' or
            'enrich:abuseipdb="high-risk"'. Returns 'enrich:vt="unknown"'
            (or the abuseipdb equivalent) when result is None.

    Raises:
        ValueError: If source is not "vt" or "abuseipdb".
    """
    if source not in ("vt", "abuseipdb"):
        raise ValueError(f"Unknown enrichment source: {source}")

    if result is None:
        return f'enrich:{source}="unknown"'

    if source == "vt":
        label = classify_vt_result(result)
    else:
        label = classify_abuseipdb_result(result["abuse_score"])

    return f'enrich:{source}="{label}"'


def find_existing_enrichment_tag(attribute, source):
    """Find an existing enrich:{source}="..." tag already present on the
    attribute, if any.

    Args:
        attribute (MISPAttribute): The attribute to inspect.
        source (str): Enrichment source identifier, "vt" or "abuseipdb".

    Returns:
        str or None: The full tag name (e.g. 'enrich:vt="malicious"') if a
            matching enrichment tag is already present, or None otherwise.
    """
    prefix = f'enrich:{source}="'
    for tag in attribute.Tag:
        if tag.name.startswith(prefix):
            return tag.name
    return None


def build_tree_output(event_id, event_info, enrichment_results, skipped_count, dry_run):
    """Render enrichment results as a grouped tree for terminal display.

    Args:
        event_id (int): The MISP event ID being enriched.
        event_info (str): The event's info/title field.
        enrichment_results (dict): Mapping of attribute type (e.g. "md5",
            "ip-dst") to a list of (attribute_value, comment, tag) tuples,
            built by ioc_enrich.py while processing each attribute.
        skipped_count (int): Number of attributes skipped (unsupported
            type, or missing API key for that source).
        dry_run (bool): Whether the run is a dry run.

    Returns:
        None. Prints the formatted tree directly to stdout.
    """
    print(f'Event #{event_id} — "{event_info}"')
    print()

    types = list(enrichment_results.keys())
    total_processed = 0
    total_enriched = 0
    total_no_result = 0

    for type_index, attr_type in enumerate(types):
        attributes = enrichment_results[attr_type]
        is_last_type = type_index == len(types) - 1
        type_branch = "└──" if is_last_type else "├──"
        count_label = (
            f"{len(attributes)} attribute{'s' if len(attributes) != 1 else ''}"
        )
        print(f"{type_branch} {attr_type} ({count_label})")

        child_indent = "    " if is_last_type else "│   "

        for attr_index, (value, comment, tag) in enumerate(attributes):
            is_last_attr = attr_index == len(attributes) - 1
            attr_branch = "└──" if is_last_attr else "├──"
            print(f"{child_indent}{attr_branch} {value}")

            result_indent = child_indent + ("    " if is_last_attr else "│   ")
            is_no_result = tag is not None and tag.endswith('="unknown"')
            suffix = "" if is_no_result else f" → {tag}"
            print(f"{result_indent}└── {comment}{suffix}")

            total_processed += 1
            if is_no_result:
                total_no_result += 1
            else:
                total_enriched += 1

        print()

    summary = (
        f"Summary: {total_processed} attributes processed · "
        f"{total_enriched} enriched · {total_no_result} no-result · "
        f"{skipped_count} skipped"
    )
    print(summary)

    if dry_run:
        print("[DRY-RUN] No changes written to MISP")


# ---------------------------------------------------------------------------
# --- Feed report formatting helpers (feed_health.py) ---
# ---------------------------------------------------------------------------


def build_feed_report(results):
    """Render feed health results as a table.

    Args:
        results (list[dict]): Per-feed results, as returned by
            feeds.build_result.

    Returns:
        None. Prints the formatted report directly to stdout.
    """
    if not results:
        print("No results to display.")
        return

    columns = [
        ("feed_name", "Feed Name", lambda v: v or "Unnamed"),
        ("status", "Status", lambda v: v.upper() if v else "UNKNOWN"),
        (
            "last_sync",
            "Last Sync",
            lambda v: (
                v.strftime("%Y-%m-%d %H:%M:%S UTC")
                if isinstance(v, datetime)
                else "N/A"
            ),
        ),
        ("volume", "Matched Events (total)", lambda v: v if v is not None else "N/A"),
        ("provider", "Provider", lambda v: v or ""),
        ("feed_url", "Source URL", lambda v: v or ""),
        ("enabled", "Enabled", lambda v: "✓" if v else "✗"),
    ]

    rows = []
    for r in results:
        row = {label: formatter(r.get(key)) for key, label, formatter in columns}
        rows.append(row)

    print(tabulate(rows, headers="keys", tablefmt="rounded_grid"))
