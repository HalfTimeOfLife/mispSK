from datetime import datetime, timedelta, timezone

from mispsk.dates import get_age

# ---------------------------------------------------------------------------
# --- get_age ---
# ---------------------------------------------------------------------------


def test_get_age_computes_days_from_datetime():
    """A datetime object 5 days in the past should return an age of 5."""
    five_days_ago = datetime.now(timezone.utc) - timedelta(days=5)

    result = get_age(five_days_ago)

    assert result == 5


def test_get_age_computes_days_from_epoch_string():
    """A raw epoch string should be converted before computing age."""
    five_days_ago = datetime.now(timezone.utc) - timedelta(days=5)
    epoch_string = str(int(five_days_ago.timestamp()))

    result = get_age(epoch_string)

    assert result == 5


def test_get_age_computes_days_from_epoch_int():
    """A raw epoch int should be converted before computing age."""
    five_days_ago = datetime.now(timezone.utc) - timedelta(days=5)
    epoch_int = int(five_days_ago.timestamp())

    result = get_age(epoch_int)

    assert result == 5


def test_get_age_returns_none_on_unparseable_timestamp():
    """A malformed timestamp should return None."""
    result = get_age("not-a-timestamp")

    assert result is None


def test_get_age_returns_none_on_none_input():
    """Passing None directly should return None."""
    result = get_age(None)

    assert result is None
