import pytest
from datetime import datetime, timedelta, timezone

from mispsk.feeds import resolve_last_sync, resolve_recent_volume, build_result


# ---------------------------------------------------------------------------
# --- fixtures/helpers ---
# ---------------------------------------------------------------------------


class FakeFeed:
    """Minimal fake MISP feed."""

    def __init__(
        self,
        feed_id=1,
        name="Test Feed",
        url="https://example.com/feed",
        provider="TestProvider",
        enabled=True,
        fixed_event=False,
        event_id=None,
    ):
        self.id = feed_id
        self.name = name
        self.url = url
        self.provider = provider
        self.enabled = enabled
        self.fixed_event = fixed_event
        self.event_id = event_id


class FakeEvent:
    """Minimal fake MISP event."""

    def __init__(self, timestamp, orgc_name=None):
        self.timestamp = timestamp
        if orgc_name is not None:
            self.Orgc = type("FakeOrgc", (), {"name": orgc_name})()


class FakeMisp:
    """Fake PyMISP client.."""

    def __init__(
        self,
        event=None,
        search_results=None,
        raise_on_get_event=False,
        raise_on_search=False,
    ):
        self._event = event
        self._search_results = search_results if search_results is not None else []
        self._raise_on_get_event = raise_on_get_event
        self._raise_on_search = raise_on_search

    def get_event(self, event_id, pythonify):
        if self._raise_on_get_event:
            raise RuntimeError("MISP unreachable")
        return self._event

    def search(self, controller, pythonify):
        if self._raise_on_search:
            raise RuntimeError("MISP unreachable")
        return self._search_results


# ---------------------------------------------------------------------------
# --- resolve_last_sync ---
# ---------------------------------------------------------------------------


def test_resolve_last_sync_returns_none_for_non_fixed_event_feed():
    """A feed with fixed_event=False should return None."""
    feed = FakeFeed(fixed_event=False, event_id=42)
    misp = FakeMisp()

    result = resolve_last_sync(feed, misp)

    assert result is None


def test_resolve_last_sync_returns_none_when_event_id_missing():
    """A fixed_event feed without an event_id should return None."""
    feed = FakeFeed(fixed_event=True, event_id=None)
    misp = FakeMisp()

    result = resolve_last_sync(feed, misp)

    assert result is None


def test_resolve_last_sync_returns_datetime_directly_when_already_datetime():
    """When event.timestamp is already a datetime it should be returned
    as-is without conversion."""
    ts = datetime(2026, 7, 16, 22, 51, 25, tzinfo=timezone.utc)
    feed = FakeFeed(fixed_event=True, event_id=42)
    misp = FakeMisp(event=FakeEvent(timestamp=ts))

    result = resolve_last_sync(feed, misp)

    assert result == ts


def test_resolve_last_sync_converts_epoch_string_timestamp():
    """When event.timestamp is a raw epoch string, it should be
    converted to a UTC datetime."""
    feed = FakeFeed(fixed_event=True, event_id=42)
    misp = FakeMisp(event=FakeEvent(timestamp="1752706285"))

    result = resolve_last_sync(feed, misp)

    assert result == datetime.fromtimestamp(1752706285, tz=timezone.utc)


def test_resolve_last_sync_returns_none_when_event_is_none():
    """If misp.get_event returns None, return None."""
    feed = FakeFeed(fixed_event=True, event_id=42)
    misp = FakeMisp(event=None)

    result = resolve_last_sync(feed, misp)

    assert result is None


def test_resolve_last_sync_returns_none_when_event_has_no_timestamp():
    """If the fetched event has no timestamp attribute, return None."""
    feed = FakeFeed(fixed_event=True, event_id=42)

    class EventWithoutTimestamp:
        pass

    misp = FakeMisp(event=EventWithoutTimestamp())

    result = resolve_last_sync(feed, misp)

    assert result is None


def test_resolve_last_sync_returns_none_on_get_event_failure():
    """A connection/API error during get_event should be caught and
    return None."""
    feed = FakeFeed(fixed_event=True, event_id=42)
    misp = FakeMisp(raise_on_get_event=True)

    result = resolve_last_sync(feed, misp)

    assert result is None


# ---------------------------------------------------------------------------
# --- resolve_recent_volume ---
# ---------------------------------------------------------------------------


def test_resolve_recent_volume_returns_none_for_fixed_event_feed():
    """fixed_event feeds should return None."""
    feed = FakeFeed(fixed_event=True, provider="CIRCL")
    misp = FakeMisp()

    result = resolve_recent_volume(feed, misp)

    assert result is None


def test_resolve_recent_volume_returns_none_when_no_provider():
    """A feed with no provider set should return None."""
    feed = FakeFeed(fixed_event=False, provider=None)
    misp = FakeMisp()

    result = resolve_recent_volume(feed, misp)

    assert result is None


def test_resolve_recent_volume_counts_only_matching_provider_events():
    """Only events whose Orgc.name matches feed.provider should be
    counted."""
    feed = FakeFeed(fixed_event=False, provider="CIRCL")
    events = [
        FakeEvent(timestamp=datetime.now(timezone.utc), orgc_name="CIRCL"),
        FakeEvent(timestamp=datetime.now(timezone.utc), orgc_name="CIRCL"),
        FakeEvent(timestamp=datetime.now(timezone.utc), orgc_name="Botvrij.eu"),
    ]
    misp = FakeMisp(search_results=events)

    result = resolve_recent_volume(feed, misp)

    assert result == 2


def test_resolve_recent_volume_excludes_events_without_orgc():
    """Events lacking an Orgc attribute entirely should not be
    counted."""
    feed = FakeFeed(fixed_event=False, provider="CIRCL")
    event_without_orgc = FakeEvent(timestamp=datetime.now(timezone.utc))
    misp = FakeMisp(search_results=[event_without_orgc])

    result = resolve_recent_volume(feed, misp)

    assert result == 0


def test_resolve_recent_volume_returns_none_on_search_failure():
    """A connection/API error during search should be caught and
    return None."""
    feed = FakeFeed(fixed_event=False, provider="CIRCL")
    misp = FakeMisp(raise_on_search=True)

    result = resolve_recent_volume(feed, misp)

    assert result is None


# ---------------------------------------------------------------------------
# --- build_result ---
# ---------------------------------------------------------------------------


def test_build_result_returns_expected_fields_for_disabled_feed():
    """Calling build_result with only status='disabled' should
    still produce a complete dict."""
    feed = FakeFeed(feed_id=2, name="Botvrij", enabled=False)

    result = build_result(feed, status="disabled")

    assert result == {
        "feed_id": 2,
        "feed_name": "Botvrij",
        "feed_url": "https://example.com/feed",
        "provider": "TestProvider",
        "enabled": False,
        "fixed_event": False,
        "last_sync": None,
        "volume": None,
        "status": "disabled",
    }


def test_build_result_returns_expected_fields_for_full_result():
    """Calling build_result with all fields populated should return
    them unchanged in the result dict."""
    feed = FakeFeed(feed_id=1, name="CIRCL OSINT Feed", provider="CIRCL")
    last_sync = datetime(2026, 7, 16, 22, 51, 25, tzinfo=timezone.utc)

    result = build_result(feed, last_sync=last_sync, volume=803, status="unknown")

    assert result["last_sync"] == last_sync
    assert result["volume"] == 803
    assert result["status"] == "unknown"
    assert result["provider"] == "CIRCL"
