import argparse
from mispsk.client import MispClient
from mispsk.utils import extract_summary, format_output

def main():
    parser = argparse.ArgumentParser(
        prog="event_search.py",
        description="Look up a MISP event by ID or IOC value and print a readable summary.",
        epilog="Example: python scripts/event_search.py --id 1234 --output json"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--id", type=int, help="MISP event ID")
    group.add_argument("--ioc", help="IOC value to search for")
    parser.add_argument("--output", choices=["table", "json"], default="table")
    args = parser.parse_args()

    client = MispClient()
    misp = client.get_client()
    
    events = []
    
    if args.id:
        event = client.get_event_by_id(args.id)
        events = [event] if event else []
    else:
        events = client.get_events_by_ioc(args.ioc)
        
    if not events:
        if args.id:
            print(f"No event was found for the ID {args.id}")
        else:
            print(f"No event was found with the IOC {args.ioc}")
    else:
        for event in events:
            summary = extract_summary(event)
            summary["sightings"] = len(misp.sightings(event.id))
            
            format_output(summary, args.output)  
    
if __name__ == "__main__":
    main()