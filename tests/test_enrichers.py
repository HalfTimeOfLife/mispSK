import pytest
import requests_mock
import requests

from mispsk.enrichers import VTEnricher, AbuseIPDBEnricher


# ---------------------------------------------------------------------------
# --- VirusTotal fixtures ---
# ---------------------------------------------------------------------------

VT_RESPONSE_MALICIOUS = {
    "data": {
        "id": "44d88612fea8a8f36de82e1278abb02f",
        "type": "file",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 65,
                "suspicious": 0,
                "undetected": 9,
                "harmless": 0,
                "timeout": 0,
            },
            "reputation": 3787,
        },
    }
}

VT_RESPONSE_SUSPICIOUS = {
    "data": {
        "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "type": "file",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 2,
                "suspicious": 3,
                "undetected": 65,
                "harmless": 4,
                "timeout": 0,
            },
            "reputation": -5,
        },
    }
}

VT_RESPONSE_CLEAN = {
    "data": {
        "id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "type": "file",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "undetected": 70,
                "harmless": 4,
                "timeout": 0,
            },
            "reputation": 0,
        },
    }
}

VT_RESPONSE_MALICIOUS_EXACT_THRESHOLD = {
    "data": {
        "id": "cccccccccccccccccccccccccccccccc",
        "type": "file",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 5,
                "suspicious": 0,
                "undetected": 65,
                "harmless": 4,
                "timeout": 0,
            },
            "reputation": -1,
        },
    }
}


# ---------------------------------------------------------------------------
# --- AbuseIPDB fixtures ---
# ---------------------------------------------------------------------------

ABUSEIPDB_RESPONSE_HIGH_RISK = {
    "data": {
        "ipAddress": "185.220.101.1",
        "abuseConfidenceScore": 100,
        "totalReports": 166,
        "countryCode": "DE",
        "isp": "Example Hosting LLC",
    }
}

ABUSEIPDB_RESPONSE_SUSPICIOUS = {
    "data": {
        "ipAddress": "203.0.113.42",
        "abuseConfidenceScore": 42,
        "totalReports": 8,
        "countryCode": "RU",
        "isp": "Example ISP",
    }
}

ABUSEIPDB_RESPONSE_LOW_RISK = {
    "data": {
        "ipAddress": "8.8.8.8",
        "abuseConfidenceScore": 0,
        "totalReports": 121,
        "countryCode": "US",
        "isp": "Google LLC",
    }
}

# ---------------------------------------------------------------------------
# --- VTEnricher.lookup_hash ---
# ---------------------------------------------------------------------------


def test_lookup_hash_returns_normalized_result_for_malicious_hash():
    """A malicious hash should return a normalized dict with correct stats."""
    with requests_mock.Mocker() as m:
        m.get(
            "https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f",
            json=VT_RESPONSE_MALICIOUS,
            status_code=200,
        )
        enricher = VTEnricher()
        result = enricher.lookup_hash("44d88612fea8a8f36de82e1278abb02f")

    assert result == {
        "malicious": 65,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 9,
        "total": 74,
        "reputation": 3787,
    }


def test_lookup_hash_returns_none_on_404():
    """An unknown hash (404 from VT) should return None, not raise."""
    with requests_mock.Mocker() as m:
        m.get(
            "https://www.virustotal.com/api/v3/files/deadbeefdeadbeefdeadbeefdeadbeef",
            status_code=404,
        )
        enricher = VTEnricher()
        result = enricher.lookup_hash("deadbeefdeadbeefdeadbeefdeadbeef")

    assert result is None


def test_lookup_hash_raises_runtime_error_on_429():
    """A 429 response should raise RuntimeError with a clear message."""
    with requests_mock.Mocker() as m:
        m.get(
            "https://www.virustotal.com/api/v3/files/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            status_code=429,
        )
        enricher = VTEnricher()

        with pytest.raises(RuntimeError, match="rate limit exceeded"):
            enricher.lookup_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


def test_lookup_hash_raises_http_error_on_500():
    """A 500 (or other unexpected) response should raise requests.HTTPError."""
    with requests_mock.Mocker() as m:
        m.get(
            "https://www.virustotal.com/api/v3/files/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            status_code=500,
        )
        enricher = VTEnricher()

        with pytest.raises(requests.HTTPError):
            enricher.lookup_hash("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")


def test_lookup_hash_sleeps_rate_delay_after_call(monkeypatch):
    """lookup_hash should sleep for self.rate_delay seconds after each call,
    even when the call raises (via the finally block)."""
    monkeypatch.setenv("VT_RATE_LIMIT_DELAY", "15")

    sleep_calls = []
    monkeypatch.setattr(
        "mispsk.enrichers.time.sleep", lambda seconds: sleep_calls.append(seconds)
    )

    with requests_mock.Mocker() as m:
        m.get(
            "https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f",
            json=VT_RESPONSE_MALICIOUS,
            status_code=200,
        )
        enricher = VTEnricher()
        enricher.lookup_hash("44d88612fea8a8f36de82e1278abb02f")

    assert sleep_calls == [15]


# ---------------------------------------------------------------------------
# --- AbuseIPDBEnricher.lookup_ip ---
# ---------------------------------------------------------------------------


def test_lookup_ip_returns_normalized_result_for_high_risk_ip():
    """A high-risk IP should return a normalized dict with correct fields."""
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.abuseipdb.com/api/v2/check",
            json=ABUSEIPDB_RESPONSE_HIGH_RISK,
            status_code=200,
        )
        enricher = AbuseIPDBEnricher()
        result = enricher.lookup_ip("185.220.101.1")

    assert result == {
        "abuse_score": 100,
        "total_reports": 166,
        "country_code": "DE",
        "isp": "Example Hosting LLC",
    }


def test_lookup_ip_raises_runtime_error_on_429():
    """A 429 response should raise RuntimeError with a clear message."""
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.abuseipdb.com/api/v2/check",
            status_code=429,
        )
        enricher = AbuseIPDBEnricher()

        with pytest.raises(RuntimeError, match="daily quota exceeded"):
            enricher.lookup_ip("185.220.101.1")


def test_lookup_ip_raises_http_error_on_other_error():
    """A non-200/429 response should raise requests.HTTPError."""
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.abuseipdb.com/api/v2/check",
            status_code=500,
        )
        enricher = AbuseIPDBEnricher()

        with pytest.raises(requests.HTTPError):
            enricher.lookup_ip("185.220.101.1")


def test_lookup_ip_passes_max_age_days_param():
    """max_age_days should be forwarded as the maxAgeInDays query param,
    alongside the correct ipAddress."""
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.abuseipdb.com/api/v2/check",
            json=ABUSEIPDB_RESPONSE_LOW_RISK,
            status_code=200,
        )
        enricher = AbuseIPDBEnricher()
        enricher.lookup_ip("8.8.8.8", max_age_days=30)

    assert m.last_request.qs["maxageindays"] == ["30"]
    assert m.last_request.qs["ipaddress"] == ["8.8.8.8"]
