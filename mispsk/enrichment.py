import requests

from mispsk.ioc import (
    HASH_TYPES,
    IP_TYPES,
    COMPOSITE_HASH_TYPES,
    COMPOSITE_IP_TYPES,
    extract_ioc_value,
)

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


def enrich_event(event, vt_enricher, abuseipdb_enricher, max_age_days, dry_run, misp):
    enrichment_results = {}
    cache = {}
    skipped_count = 0
    source = None
    stopped_early = False
    vt_warning_shown = False
    abuseipdb_warning_shown = False

    for attribute in event.Attribute:
        if attribute.type in HASH_TYPES or attribute.type in COMPOSITE_HASH_TYPES:
            source = "vt"
            if vt_enricher is None:
                if not vt_warning_shown:
                    print(
                        "Warning: VT_API_KEY missing: hash attributes will be skipped"
                    )
                    vt_warning_shown = True
                skipped_count += 1
                continue
        elif attribute.type in IP_TYPES or attribute.type in COMPOSITE_IP_TYPES:
            source = "abuseipdb"
            if abuseipdb_enricher is None:
                if not abuseipdb_warning_shown:
                    print(
                        "Warning: ABUSEIPDB_API_KEY missing: IP attributes will be skipped"
                    )
                    abuseipdb_warning_shown = True
                skipped_count += 1
                continue

        else:
            skipped_count += 1
            continue

        ioc_value = extract_ioc_value(attribute.type, attribute.value)
        key = (source, ioc_value)

        if key in cache:
            result = cache[key]
        else:
            try:
                if source == "vt":
                    result = vt_enricher.lookup_hash(ioc_value)
                else:
                    result = abuseipdb_enricher.lookup_ip(ioc_value, max_age_days)
                cache[key] = result
            except RuntimeError as e:
                print(f"Warning: {e} - stopping enrichment")
                stopped_early = True
                break
            except requests.HTTPError as e:
                print(f"Warning: API error ({e}) - stopping enrichment")
                stopped_early = True
                break

        comment = build_enrichment_comment(source, result)
        tag = build_enrichment_tag(source, result)

        enrichment_results.setdefault(attribute.type, []).append(
            (attribute.value, comment, tag)
        )

        if not dry_run:
            old_tag = find_existing_enrichment_tag(attribute, source)

            merged_comment = merge_enrichment_comment(
                attribute.comment, comment, source
            )

            if merged_comment != attribute.comment:
                attribute.comment = merged_comment
                misp.update_attribute(attribute)

            if old_tag is None or old_tag != tag:
                if old_tag:
                    misp.untag(attribute.uuid, old_tag)
                misp.tag(attribute.uuid, tag)

    return enrichment_results, skipped_count, stopped_early
