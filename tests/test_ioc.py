import pytest

from mispsk.ioc import (
    extract_ioc_value,
    COMPOSITE_HASH_TYPES,
    COMPOSITE_IP_TYPES,
    COMPOSITE_IOC_POSITION,
)

# ---------------------------------------------------------------------------
# --- extract_ioc_value ---
# ---------------------------------------------------------------------------


def test_extract_ioc_value_returns_value_unchanged_for_simple_hash_type():
    """A simple type (no '|') should return the value as-is."""
    result = extract_ioc_value("md5", "d41d8cd98f00b204e9800998ecf8427e")

    assert result == "d41d8cd98f00b204e9800998ecf8427e"


def test_extract_ioc_value_returns_value_unchanged_for_simple_ip_type():
    """A simple IP type should return the value as-is."""
    result = extract_ioc_value("ip-src", "8.8.8.8")

    assert result == "8.8.8.8"


def test_extract_ioc_value_extracts_hash_from_composite_filename_type():
    """A 'filename|md5' type should return only the hash portion."""
    result = extract_ioc_value(
        "filename|md5", "malware.exe|d41d8cd98f00b204e9800998ecf8427e"
    )

    assert result == "d41d8cd98f00b204e9800998ecf8427e"


def test_extract_ioc_value_extracts_ip_from_composite_port_type():
    """An 'ip-src|port' type should return the IP (first segment), not the port."""
    result = extract_ioc_value("ip-src|port", "203.0.113.42|8080")

    assert result == "203.0.113.42"


def test_extract_ioc_value_raises_on_unknown_composite_type():
    """A composite type not in COMPOSITE_IOC_POSITION should raise ValueError
    rather than silently guessing a position."""
    with pytest.raises(ValueError, match="Unknown composite type"):
        extract_ioc_value("md5|sha1", "abc|def")


def test_extract_ioc_value_handles_value_containing_extra_pipe():
    """If the value itself contains a '|', only the first split should be
    used to separate filename/IP from the actual IOC (split with maxsplit=1)."""
    result = extract_ioc_value(
        "filename|md5", "weird|name.exe|d41d8cd98f00b204e9800998ecf8427e"
    )

    assert result == "name.exe|d41d8cd98f00b204e9800998ecf8427e"


@pytest.mark.parametrize(
    "attribute_type,attribute_value,expected",
    [
        (
            "filename|md5",
            "a.exe|d41d8cd98f00b204e9800998ecf8427e",
            "d41d8cd98f00b204e9800998ecf8427e",
        ),
        (
            "filename|sha1",
            "a.exe|3395856ce81f2b7382dee72602f798b642f14140",
            "3395856ce81f2b7382dee72602f798b642f14140",
        ),
        (
            "filename|sha256",
            "a.exe|3a4348327da5b72b70e265b2c1205e030d6828bc893322deff9c001890600fff",
            "3a4348327da5b72b70e265b2c1205e030d6828bc893322deff9c001890600fff",
        ),
    ],
)
def test_extract_ioc_value_handles_all_composite_hash_variants(
    attribute_type, attribute_value, expected
):
    """All declared composite hash types (md5/sha1/sha256) should extract
    the hash portion correctly, not just filename|md5."""
    result = extract_ioc_value(attribute_type, attribute_value)

    assert result == expected


# ---------------------------------------------------------------------------
# --- Composite type table consistency ---
# ---------------------------------------------------------------------------


def test_composite_type_sets_match_position_table():
    """Every composite hash/IP type must have a corresponding entry in
    COMPOSITE_IOC_POSITION, and vice versa - prevents silently mis-parsing
    a newly added composite type that was forgotten in one of the tables."""

    declared_types = COMPOSITE_HASH_TYPES | COMPOSITE_IP_TYPES
    position_keys = set(COMPOSITE_IOC_POSITION.keys())

    assert declared_types == position_keys
