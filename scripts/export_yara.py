import argparse
import sys

from mispsk.client import MispClient
from mispsk.yara import (
    build_yara_rule,
    extract_analyst_rule,
    filter_yara_candidates,
    classify_confidence_tier,
)


def main():
    parser = argparse.ArgumentParser(
        prog="export_yara.py",
        description="Export a MISP event's static IOCs (hashes, patterns, ...) to a YARA rule.",
        epilog="Example: python scripts/export_yara.py --id 1234 --output-file rules/event_1234.yar",
    )
    parser.add_argument("--id", type=int, required=True, help="MISP event ID to export")
    parser.add_argument(
        "--output-file",
        help="Path to write the generated .yar file (default: print to stdout)",
    )
    args = parser.parse_args()

    client = MispClient()

    event = client.get_event_by_id(args.id)
    if event is None:
        print(f"No event was found for the ID {args.id}")
        sys.exit(1)

    skipped_types = set()
    yara_attributes = []

    for attribute in event.Attribute:
        tier = classify_confidence_tier(attribute.type)
        if attribute.type == "yara":
            yara_attributes.append(attribute)
        elif tier is None:
            skipped_types.add(attribute.type)

    if skipped_types:
        print(
            f"[SKIP] {len(skipped_types)} attribute type(s) skipped "
            f"(no static YARA representation): {', '.join(sorted(skipped_types))}"
        )

    candidates = filter_yara_candidates(event)

    if not candidates and not yara_attributes:
        print(f"[SKIP] No YARA-compatible attributes found on event #{event.id}")
        sys.exit(1)

    rule_blocks = []

    if candidates:
        rule_blocks.append(build_yara_rule(event, candidates))

    for index, attribute in enumerate(yara_attributes, start=1):
        analyst_rule = extract_analyst_rule(attribute, event.id, index)
        if analyst_rule is None:
            print(
                f"[SKIP] Analyst-authored YARA attribute #{attribute.id} could not be "
                f"parsed (no rule name found), skipping it"
            )
            continue
        rule_blocks.append(analyst_rule)

    yara_file_text = "\n\n".join(rule_blocks)

    try:
        import yara

        try:
            yara.compile(source=yara_file_text)
            print(
                f"[SUCCESS] Syntax validated with yara-python ({len(rule_blocks)} rule(s))"
            )
        except yara.SyntaxError as e:
            print(f"[ERROR] Generated YARA file failed syntax validation: {e}")
            print("Aborting: nothing was printed or written.")
            sys.exit(1)
    except ImportError:
        print("[SKIP] yara-python not installed, skipping syntax validation")

    print()

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(yara_file_text + "\n")
        print(f"YARA rule(s) for event #{event.id} written to {args.output_file}")
    else:
        print(yara_file_text)


if __name__ == "__main__":
    main()
