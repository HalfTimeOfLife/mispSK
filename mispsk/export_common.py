import re

# ---------------------------------------------------------------------------
# --- Generic helpers shared across export scripts ---
# ---------------------------------------------------------------------------


def filter_attributes_by_type(event, allowed_types):
    """Select attributes from a MISP event matching a given set of types.

    Args:
        event (MISPEvent): The event to filter.
        allowed_types (set[str]): Attribute types to keep (e.g. HASH_TYPES,
            or a custom set passed by the caller).

    Returns:
        list[MISPAttribute]: Attributes whose type is in allowed_types,
            in their original order.
    """
    return [
        attribute for attribute in event.Attribute if attribute.type in allowed_types
    ]


def sanitize_identifier(text):
    """Sanitize a free-text string into a safe identifier for use in
    generated rule/field names.

    Args:
        text (str): The raw text to sanitize (e.g. event.info).

    Returns:
        str: A sanitized identifier containing only characters valid
            across supported export formats.
    """
    if not text:
        return "unnamed"

    sanitized = re.sub(r"[^A-Za-z0-9_]+", "_", text.strip())
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")

    if not sanitized:
        return "unnamed"

    if sanitized[0].isdigit():
        sanitized = f"_{sanitized}"

    return sanitized
