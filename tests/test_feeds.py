import pytest
from datetime import datetime, timedelta, timezone

from mispsk.feeds import (
    resolve_last_sync,
    resolve_recent_volume,
    build_result,
    build_feed_report,
)


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


# ---------------------------------------------------------------------------
# --- build_feed_report ---
# ---------------------------------------------------------------------------


def test_build_feed_report_prints_message_when_no_results(capsys):
    """An empty results list should print a clear message."""
    build_feed_report([])
    captured = capsys.readouterr()

    assert "No results to display" in captured.out


def test_build_feed_report_shows_unknown_status_and_na_fields(capsys):
    """A feed with no resolved last_sync/volume should display 'N/A'."""
    results = [
        {
            "feed_id": 1,
            "feed_name": "CIRCL OSINT Feed",
            "feed_url": "https://www.circl.lu/doc/misp/feed-osint",
            "provider": "CIRCL",
            "enabled": True,
            "fixed_event": False,
            "last_sync": None,
            "volume": 803,
            "status": "unknown",
        }
    ]

    build_feed_report(results)
    captured = capsys.readouterr()

    assert "UNKNOWN" in captured.out
    assert "N/A" in captured.out
    assert "803" in captured.out
    assert "CIRCL" in captured.out


def test_build_feed_report_formats_last_sync_datetime(capsys):
    """A resolved last_sync datetime should be formatted as a
    readable UTC timestamp string."""
    results = [
        {
            "feed_id": 3,
            "feed_name": "Test Fixed Event Feed",
            "feed_url": "https://example.com/feed",
            "provider": "TestProvider",
            "enabled": True,
            "fixed_event": True,
            "last_sync": datetime(2026, 7, 16, 22, 51, 25, tzinfo=timezone.utc),
            "volume": None,
            "status": "ok",
        }
    ]

    build_feed_report(results)
    captured = capsys.readouterr()

    assert "2026-07-16 22:51:25 UTC" in captured.out
    assert "OK" in captured.out


def test_build_feed_report_shows_disabled_status(capsys):
    """A disabled feed should render its status and enabled marker
    consistently."""
    results = [
        {
            "feed_id": 2,
            "feed_name": "The Botvrij.eu Data",
            "feed_url": "https://www.botvrij.eu/data/feed-osint",
            "provider": "Botvrij.eu",
            "enabled": False,
            "fixed_event": False,
            "last_sync": None,
            "volume": None,
            "status": "disabled",
        }
    ]

    build_feed_report(results)
    captured = capsys.readouterr()

    assert "DISABLED" in captured.out
    assert "✗" in captured.out


def test_build_feed_report_wraps_long_source_url(capsys):
    """A Source URL longer than the max column width should be wrapped
    onto multiple lines within the same cell"""
    long_url = "https://example.com/" + "a" * 80

    results = [
        {
            "feed_id": 1,
            "feed_name": "Long URL Feed",
            "feed_url": long_url,
            "provider": "TestProvider",
            "enabled": True,
            "fixed_event": False,
            "last_sync": None,
            "volume": None,
            "status": "ok",
        }
    ]

    build_feed_report(results)
    captured = capsys.readouterr()

    assert long_url not in captured.out
    assert "a" * 40 in captured.out
