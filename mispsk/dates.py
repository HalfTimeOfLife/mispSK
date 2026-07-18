from datetime import datetime, timezone


def get_age(timestamp):
    """Compute the age (in days) of a MISP epoch timestamp.

    Args:
        timestamp (str, int, or datetime): A MISP-style Unix epoch
            timestamp, or an already-resolved datetime.

    Returns:
        int or None: Age in days, or None if timestamp could not be
            parsed (caller must treat this as "unknown", not "ok").
    """
    if isinstance(timestamp, datetime):
        dt = timestamp
    else:
        try:
            dt = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
        except (TypeError, ValueError):
            return None

    return (datetime.now(timezone.utc) - dt).days
