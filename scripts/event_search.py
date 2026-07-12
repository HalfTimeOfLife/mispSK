import argparse
from mispsk.client import MispClient
from mispsk.utils import extract_summary, format_output

from pymisp import MISPEvent
    
def get_event_by_id(misp, event_id):
    """Retrieve a single MISP event by its ID.

    Args:
        misp (PyMISP): The connected PyMISP client.
        event_id (int): The event ID to look up.

    Returns:
        list[MISPEvent]: A list containing the matching event, or an empty
            list if no event was found.
    """
    event = misp.get_event(event_id, pythonify=True)
    if not isinstance(event, MISPEvent):
        return []
    return [event]

def get_events_by_ioc(misp, ioc_value):
    """Search for MISP events containing a given IOC value.

    Args:
        misp (PyMISP): The connected PyMISP client.
        ioc_value (str): The IOC value to search for.

    Returns:
        list[MISPEvent]: A list of matching events (possibly empty).
    """
    events = misp.search(value=ioc_value, controller='events', pythonify=True)
    return events
    


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
        events = get_event_by_id(misp, args.id)
    else:
        events = get_events_by_ioc(misp, args.ioc)
        
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