from datetime import datetime, timezone
from tabulate import tabulate


def resolve_last_sync(feed, misp):
    """Determine the timestamp of a feed's last successful sync.

    Only resolvable for fixed_event feeds. Returns None for all other
    feeds (no reliable signal available - see CHANGELOG).

    Args:
        feed (MISPFeed): The feed to inspect.
        misp (PyMISP): Active PyMISP client, used for event lookups.

    Returns:
        datetime or None: Last sync time, or None if not resolvable.
    """
    fixed_event = getattr(feed, "fixed_event", False)
    event_id = getattr(feed, "event_id", None)

    # MISP normalizes an absent/never-populated event_id to the string
    # "0" rather than None.
    if not fixed_event or not event_id or str(event_id) == "0":
        return None

    try:
        event = misp.get_event(event_id, pythonify=True)
    except Exception:
        return None

    if not event or not hasattr(event, "timestamp"):
        return None

    timestamp = event.timestamp
    if isinstance(timestamp, datetime):
        return timestamp
    return datetime.fromtimestamp(int(timestamp), tz=timezone.utc)


def resolve_recent_volume(feed, misp):
    """Count events matched to a feed by provider.

    Args:
        feed (MISPFeed): The feed to inspect.
        misp (PyMISP): Active PyMISP client, used for event search.

    Returns:
        int or None: Total matched event count, or None if not
            resolvable (fixed_event feed, or no usable provider).
    """
    if getattr(feed, "fixed_event", False):
        return None

    provider = getattr(feed, "provider", None)
    if not provider:
        return None

    try:
        events = misp.search(controller="events", pythonify=True)
    except Exception:
        return None

    matched = [e for e in events if hasattr(e, "Orgc") and e.Orgc.name == provider]
    return len(matched)


def build_result(feed, last_sync=None, volume=None, status="unknown"):
    """Build a normalized per-feed health result.

    Args:
        feed (MISPFeed): The feed being reported on.
        last_sync (datetime or None): Resolved last-sync time, if known.
        volume (int or None): Matched event volume, if known.
        status (str): One of "ok", "stale", "disabled", "unknown".

    Returns:
        dict: Normalized result.
    """
    return {
        "feed_id": getattr(feed, "id", None),
        "feed_name": getattr(feed, "name", "Unnamed"),
        "feed_url": getattr(feed, "url", None),
        "provider": getattr(feed, "provider", None),
        "enabled": getattr(feed, "enabled", False),
        "fixed_event": getattr(feed, "fixed_event", False),
        "last_sync": last_sync,
        "volume": volume,
        "status": status,
    }


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

    max_col_widths = [None, None, None, None, None, 50, None]

    print(
        tabulate(
            rows,
            headers="keys",
            tablefmt="rounded_grid",
            maxcolwidths=max_col_widths,
        )
    )
