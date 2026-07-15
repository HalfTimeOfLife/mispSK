import argparse
import sys

from mispsk.client import MispClient
from mispsk.enrichers import VTEnricher, AbuseIPDBEnricher
from mispsk.utils import build_tree_output
from mispsk.enrichment import enrich_event


def main():
    parser = argparse.ArgumentParser(
        prog="ioc_enrich.py",
        description="Enrich a MISP event's hash/IP attributes via VirusTotal and AbuseIPDB.",
        epilog="Example: python scripts/ioc_enrich.py --id 1234 --dry-run",
    )
    parser.add_argument("--id", type=int, required=True, help="MISP event ID to enrich")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview changes without writing to MISP"
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=90,
        help="Max age (days) for AbuseIPDB reports (default: 90)",
    )
    args = parser.parse_args()

    client = MispClient()
    misp = client.get_client()

    event = client.get_event_by_id(args.id)
    if event is None:
        print(f"No event was found for the ID {args.id}")
        sys.exit(1)

    try:
        vt_enricher = VTEnricher()
    except ValueError:
        vt_enricher = None

    try:
        abuseipdb_enricher = AbuseIPDBEnricher()
    except ValueError:
        abuseipdb_enricher = None

    if vt_enricher is None and abuseipdb_enricher is None:
        print(
            "No API key configured (VT_API_KEY / ABUSEIPDB_API_KEY), nothing to enrich..."
        )
        sys.exit(1)

    enrichment_results, skipped_count, stopped_early = enrich_event(
        event, vt_enricher, abuseipdb_enricher, args.max_age_days, args.dry_run, misp
    )

    build_tree_output(
        event_id=event.id,
        event_info=event.info,
        enrichment_results=enrichment_results,
        skipped_count=skipped_count,
        dry_run=args.dry_run,
    )

    if stopped_early:
        sys.exit(1)


if __name__ == "__main__":
    main()
