from mispsk.utils import (
    build_enrichment_comment,
    merge_enrichment_comment,
    build_enrichment_tag,
    find_existing_enrichment_tag,
    HASH_TYPES,
    IP_TYPES,
)


def enrich_event(event, vt_enricher, abuseipdb_enricher, max_age_days, dry_run, misp):

    enrichment_results = {}
    cache = {}
    skipped_count = 0
    source = None
    stopped_early = False
    vt_warning_shown = False
    abuseipdb_warning_shown = False

    for attribute in event.Attribute:
        if attribute.type in HASH_TYPES:
            source = "vt"
            if vt_enricher is None:
                if not vt_warning_shown:
                    print("VT_API_KEY absent, hash ignored")
                    vt_warning_shown = True
                skipped_count += 1
                continue
        elif attribute.type in IP_TYPES:
            source = "abuseipdb"
            if abuseipdb_enricher is None:
                if not abuseipdb_warning_shown:
                    print("ABUSEIPDB_API_KEY absent, IP ignored")
                    abuseipdb_warning_shown = True
                skipped_count += 1
                continue

        else:
            skipped_count += 1
            continue

        key = (source, attribute.value)

        if key in cache:
            result = cache[key]
        else:
            try:
                if source == "vt":
                    result = vt_enricher.lookup_hash(attribute.value)
                else:
                    result = abuseipdb_enricher.lookup_ip(attribute.value, max_age_days)
                cache[key] = result
            except RuntimeError as e:
                print(f"⚠ {e} — arrêt de l'enrichissement")
                stopped_early = True
                break

        comment = build_enrichment_comment(source, result)
        tag = build_enrichment_tag(source, result)

        enrichment_results.setdefault(attribute.type, []).append(
            (attribute.value, comment, tag)
        )

        if not dry_run:
            old_tag = find_existing_enrichment_tag(attribute, source)
            if old_tag and old_tag != tag:
                misp.untag(attribute.uuid, old_tag)

            merged_comment = merge_enrichment_comment(
                attribute.comment, comment, source
            )

            if merged_comment != attribute.comment or (
                old_tag is None or old_tag != tag
            ):
                attribute.comment = merged_comment
                misp.update_attribute(attribute)
                misp.tag(attribute.uuid, tag)

    return enrichment_results, skipped_count, stopped_early
