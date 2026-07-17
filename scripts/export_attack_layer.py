import argparse
import json
import sys

from mispsk.client import MispClient
from mispsk.attack_layer import aggregate_attack_tags, build_navigator_layer


def main():
    parser = argparse.ArgumentParser(
        prog="export_attack_layer.py",
        description="Export one or more MISP events' ATT&CK tags to a Navigator layer JSON.",
        epilog="Example: python scripts/export_attack_layer.py --ids 1234 5678 --output layer.json",
    )
    parser.add_argument(
        "--ids", nargs="+", type=int, required=True, help="MISP event IDs to include"
    )
    parser.add_argument(
        "--output", required=True, help="Output path for the Navigator layer JSON file"
    )
    parser.add_argument(
        "--name", default="mispSK export", help="Name of the Navigator layer"
    )
    parser.add_argument(
        "--domain",
        default="enterprise-attack",
        help="ATT&CK domain (default: enterprise-attack)",
    )
    args = parser.parse_args()

    client = MispClient()

    events = client.get_events_by_ids(args.ids)

    if not events:
        print("No valid event was found.")
        sys.exit(1)

    technique_counts = aggregate_attack_tags(events)

    if not technique_counts:
        print("No ATT&CK tags were found for the selected events.")
        sys.exit(1)

    layer = build_navigator_layer(technique_counts, args.name, args.domain)

    if not layer["techniques"]:
        print("No technique could be mapped to an ATT&CK ID, aborting.")
        sys.exit(1)

    with open(args.output, "w") as f:
        json.dump(layer, f, indent=4)

    print(f"Layer exported to {args.output} ({len(layer['techniques'])} techniques)")


if __name__ == "__main__":
    main()
