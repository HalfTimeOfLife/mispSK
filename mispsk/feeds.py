"""Feed health resolution logic (feed_health.py).

Handles last-sync resolution, event volume counting, and per-feed
result construction.
"""

from datetime import datetime, timezone


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
    if not (getattr(feed, "fixed_event", False) and getattr(feed, "event_id", None)):
        return None

    try:
        event = misp.get_event(feed.event_id, pythonify=True)
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
