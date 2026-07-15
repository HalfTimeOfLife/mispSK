import pytest
from pymisp import MISPEvent

from mispsk.client import MispClient

# ---------------------------------------------------------------------------
# --- fixtures ---
# ---------------------------------------------------------------------------


@pytest.fixture
def client(monkeypatch):
    """Create a MispClient with a mocked PyMISP connection."""

    monkeypatch.setenv("MISP_URL", "https://misp.test")
    monkeypatch.setenv("MISP_API_KEY", "fake-key")

    client = MispClient.__new__(MispClient)

    client.misp = None

    return client


# ---------------------------------------------------------------------------
# --- MispClient.get_event_by_id ---
# ---------------------------------------------------------------------------


def test_get_event_by_id_returns_event_when_found(client):
    """A valid event ID should return the corresponding MISPEvent."""

    event = MISPEvent()
    event.id = 1234

    class FakeMisp:
        def get_event(self, event_id, pythonify):
            assert event_id == 1234
            assert pythonify is True
            return event

    client.misp = FakeMisp()

    result = client.get_event_by_id(1234)

    assert result == event


def test_get_event_by_id_returns_none_when_not_found(client):
    """An event ID with no match should return None."""

    class FakeMisp:
        def get_event(self, event_id, pythonify):
            return {}

    client.misp = FakeMisp()

    result = client.get_event_by_id(9999)

    assert result is None


# ---------------------------------------------------------------------------
# --- MispClient.get_events_by_ioc ---
# ---------------------------------------------------------------------------


def test_get_events_by_ioc_returns_matching_events(client):
    """An IOC value with matches should return a list of MISPEvents."""

    events = [
        MISPEvent(),
        MISPEvent(),
    ]

    class FakeMisp:
        def search(self, value, controller, pythonify):
            assert value == "8.8.8.8"
            assert controller == "events"
            assert pythonify is True
            return events

    client.misp = FakeMisp()

    result = client.get_events_by_ioc("8.8.8.8")

    assert result == events


def test_get_events_by_ioc_returns_empty_list_when_no_match(client):
    """An IOC value with no matches should return an empty list."""

    class FakeMisp:
        def search(self, value, controller, pythonify):
            return []

    client.misp = FakeMisp()

    result = client.get_events_by_ioc("192.0.2.1")

    assert result == []
