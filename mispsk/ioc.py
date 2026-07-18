# ---------------------------------------------------------------------------
# --- Enrichment type constants (ioc_enrich.py) ---
# ---------------------------------------------------------------------------

HASH_TYPES = {"md5", "sha1", "sha256"}
IP_TYPES = {"ip-src", "ip-dst"}

COMPOSITE_HASH_TYPES = {"filename|md5", "filename|sha1", "filename|sha256"}
COMPOSITE_IP_TYPES = {"ip-src|port", "ip-dst|port"}

# Position of the actual IOC value within a composite type's "part1|part2".
# True = IOC is the first segment, False = IOC is the second segment.
COMPOSITE_IOC_POSITION = {
    "filename|md5": False,
    "filename|sha1": False,
    "filename|sha256": False,
    "ip-src|port": True,
    "ip-dst|port": True,
}


def extract_ioc_value(attribute_type, attribute_value):
    """Extract the actual hash/IP value from a (possibly composite) attribute.

    Args:
        attribute_type (str): The MISP attribute type (e.g. "md5", "filename|md5").
        attribute_value (str): The raw attribute value.

    Returns:
        str: The hash/IP portion to use for lookups and caching.

    Raises:
        ValueError: If attribute_type is composite but not a recognized
            composite type (position unknown).
    """
    if "|" not in attribute_type:
        return attribute_value

    if attribute_type not in COMPOSITE_IOC_POSITION:
        raise ValueError(f"Unknown composite type, cannot locate IOC: {attribute_type}")

    parts = attribute_value.split("|", 1)
    ioc_is_first = COMPOSITE_IOC_POSITION[attribute_type]
    return parts[0] if ioc_is_first else parts[1]
