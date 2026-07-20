import re

from mispsk.export_common import filter_attributes_by_type
from mispsk.ioc import extract_ioc_value

# ---------------------------------------------------------------------------
# --- Confidence tier type tables ---
# ---------------------------------------------------------------------------

STRONG_HASH_TYPES = {"md5", "sha1", "sha256"}
STRONG_COMPOSITE_TYPES = {"filename|md5", "filename|sha1", "filename|sha256"}

MEDIUM_TYPES = {
    "filename",
    "filename-pattern",
    "pattern-in-file",
    "pattern-in-memory",
    "regkey",
    "regkey|value",
    "mutex",
    "named pipe",
    "pdb",
    "mime-type",
}

WEAK_TYPES = {
    "ip-src",
    "ip-dst",
    "ip-src|port",
    "ip-dst|port",
    "domain",
    "domain|ip",
    "hostname",
    "hostname|port",
    "url",
    "uri",
    "user-agent",
}

ALL_YARA_TYPES = STRONG_HASH_TYPES | STRONG_COMPOSITE_TYPES | MEDIUM_TYPES | WEAK_TYPES
WEAK_TIER_MIN_MATCHES = 2

_INDENT = "    "
_RULE_NAME_PATTERN = re.compile(r"rule\s+([A-Za-z_]\w*)")


# ---------------------------------------------------------------------------
# --- Confidence tier classification ---
# ---------------------------------------------------------------------------


def classify_confidence_tier(attribute_type):
    """Classify a MISP attribute type into a YARA confidence tier.

    Args:
        attribute_type (str): The MISP attribute type.

    Returns:
        str or None: One of "strong", "medium", "weak", or None if the
            type has no static YARA representation.
    """
    if attribute_type in STRONG_HASH_TYPES or attribute_type in STRONG_COMPOSITE_TYPES:
        return "strong"
    if attribute_type in MEDIUM_TYPES:
        return "medium"
    if attribute_type in WEAK_TYPES:
        return "weak"
    return None


def filter_yara_candidates(event):
    """Select the subset of an event's attributes usable for YARA export,
    excluding the "yara" type (handled separately by extract_analyst_rule).

    Args:
        event (MISPEvent): The event to filter.

    Returns:
        list[MISPAttribute]: Attributes with a non-None confidence tier,
            per classify_confidence_tier.
    """
    return filter_attributes_by_type(event, ALL_YARA_TYPES)


# ---------------------------------------------------------------------------
# --- String / condition builders ---
# ---------------------------------------------------------------------------


def escape_yara_string(value):
    """Escape a raw attribute value for safe inclusion in a YARA string.

    Args:
        value (str): The raw value to escape (e.g. a pattern-in-file value).

    Returns:
        str: The value with YARA-reserved characters escaped.
    """
    escaped = value.replace("\\", "\\\\")
    escaped = escaped.replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n")
    escaped = escaped.replace("\r", "\\r")
    escaped = escaped.replace("\t", "\\t")
    return escaped


def build_hash_condition(hash_type, value):
    """Build a YARA condition expression for a "strong" tier hash match.

    Args:
        hash_type (str): The MISP hash type. Must be one YARA's hash
            module can natively compute ("md5", "sha1", "sha256").
        value (str): The hash value.

    Returns:
        str: A YARA condition string using the hash module.

    Raises:
        ValueError: If hash_type is not "md5", "sha1", or "sha256".
    """
    if hash_type not in STRONG_HASH_TYPES:
        raise ValueError(f"Unsupported hash type for YARA hash module: {hash_type}")

    return f'hash.{hash_type}(0, filesize) == "{value.lower()}"'


# ---------------------------------------------------------------------------
# --- Analyst-authored YARA rule extraction ("yara" attribute type) ---
# ---------------------------------------------------------------------------


def extract_analyst_rule(attribute, event_id, index):
    """Extract and rename a pre-existing analyst-authored YARA rule stored
    in a MISP attribute of type "yara".

    Args:
        attribute (MISPAttribute): The attribute of type "yara" containing
            a full rule definition as its value.
        event_id (int): The MISP event ID (used to build the new rule name).
        index (int): Position of this analyst rule among others in the
            same event (used to build a unique rule name when an event
            has multiple "yara" attributes).

    Returns:
        str or None: The rule text with its internal rule name rewritten
            to "mispSK_event_{event_id}_analyst_{index}", or None if the
            attribute's value could not be parsed as a rule definition.
    """
    match = _RULE_NAME_PATTERN.search(attribute.value)
    if match is None:
        return None

    new_name = f"mispSK_event_{event_id}_analyst_{index}"
    return (
        attribute.value[: match.start(1)] + new_name + attribute.value[match.end(1) :]
    )


# ---------------------------------------------------------------------------
# --- Rule assembly ---
# ---------------------------------------------------------------------------


def build_yara_rule(event, attributes):
    rule_name = f"mispSK_event_{event.id}"
    strong = []
    medium = {}
    weak = {}

    for attribute in attributes:
        tier = classify_confidence_tier(attribute.type)

        if tier == "strong":
            hash_type = (
                attribute.type.split("|")[-1]
                if "|" in attribute.type
                else attribute.type
            )
            hash_value = extract_ioc_value(attribute.type, attribute.value)
            condition = build_hash_condition(hash_type, hash_value)
            strong.append(condition)
        elif tier == "medium":
            var_name = f"$medium_{len(medium) + 1}"
            medium[var_name] = escape_yara_string(attribute.value)
        elif tier == "weak":
            var_name = f"$weak_{len(weak) + 1}"
            weak[var_name] = escape_yara_string(attribute.value)

    strings_lines = []
    for var_name, value in medium.items():
        strings_lines.append(f'{_INDENT * 3}{var_name} = "{value}" ascii wide')
    for var_name, value in weak.items():
        strings_lines.append(
            f'{_INDENT * 3}{var_name} = "{value}" ascii // static string match only'
        )

    strings_block = "\n".join(strings_lines)

    condition_clauses = []
    if strong:
        condition_clauses.append("(" + " or ".join(strong) + ")")
    if medium:
        condition_clauses.append("any of ($medium_*)")
    if weak:
        condition_clauses.append("2 of ($weak_*)")

    condition_block = f"{_INDENT * 3}" + f"\n{_INDENT * 3}or ".join(condition_clauses)

    import_block = 'import "hash"\n\n' if strong else ""

    rule_text = f'''{import_block}rule {rule_name} {{
        meta:
            description = "{event.info}"
            misp_event_id = "{event.id}"
            source = "mispSK export_yara.py"

        strings:
{strings_block}

        condition:
{condition_block}
    }}'''

    return rule_text
