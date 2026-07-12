import json
from tabulate import tabulate
from collections import Counter

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
        display["attribute_types"] = ", ".join(f"{k}: {v}" for k, v in summary["attribute_types"].items())
        display["attack_tags"] = ", ".join(summary["attack_tags"]) if summary["attack_tags"] else "None"
        display["tlp"] = summary["tlp"] if summary["tlp"] else "Not set"
        
        rows = [[key, value] for key, value in display.items()]
        print(tabulate(rows, headers=["Field", "Value"], tablefmt="github"))