import pytest


@pytest.fixture(autouse=True)
def fake_env(monkeypatch):
    """Ensure tests never depend on real API keys or .env content."""
    monkeypatch.setenv("VT_API_KEY", "fake-vt-key-for-tests")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake-abuseipdb-key-for-tests")
    monkeypatch.setenv("VT_RATE_LIMIT_DELAY", "0")
