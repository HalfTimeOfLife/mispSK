import os
import time
import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# --- VirusTotal enricher ---
# ---------------------------------------------------------------------------


class VTEnricher:
    """Wrapper around the VirusTotal v3 API for file/hash lookups.

    Attributes:
        api_key (str): The VirusTotal API key, loaded from .env.
    """

    BASE_URL = "https://www.virustotal.com/api/v3/files/"

    def __init__(self):
        """Load and validate the VT_API_KEY from environment."""
        self._load_config()

    def _load_config(self):
        """Load VT_API_KEY from .env.

        Raises:
            ValueError: If VT_API_KEY is not set.
        """
        load_dotenv()
        self.api_key = os.getenv("VT_API_KEY")
        if not self.api_key:
            raise ValueError("VT_API_KEY is not set")
        self.rate_delay = int(os.getenv("VT_RATE_LIMIT_DELAY", 15))

    def lookup_hash(self, hash_value):
        """Look up a file hash on VirusTotal.

        Args:
            hash_value (str): The MD5/SHA1/SHA256 hash to look up.

        Returns:
            dict or None: Normalized result {malicious, suspicious,
                harmless, undetected, total, reputation}, or None if VT
                returns 404 (hash unknown).

        Raises:
            RuntimeError: If VT returns 429 (rate limit exceeded).
            requests.HTTPError: For any other non-200/404 response.
        """
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}

        url = f"{self.BASE_URL}{hash_value}"

        try:
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 404:
                return None

            if response.status_code == 429:
                raise RuntimeError("VirusTotal rate limit exceeded (429).")

            response.raise_for_status()
            data = response.json()["data"]["attributes"]
            stats = data["last_analysis_stats"]
            result = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "reputation": data.get("reputation", 0),
            }
            return result
        finally:
            time.sleep(self.rate_delay)


# ---------------------------------------------------------------------------
# --- AbuseIPDB enricher ---
# ---------------------------------------------------------------------------


class AbuseIPDBEnricher:
    """Wrapper around the AbuseIPDB v2 API for IP reputation lookups.

    Attributes:
        api_key (str): The AbuseIPDB API key, loaded from .env.
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self):
        """Load and validate the ABUSEIPDB_API_KEY from environment."""
        self._load_config()

    def _load_config(self):
        """Load ABUSEIPDB_API_KEY from .env.

        Raises:
            ValueError: If ABUSEIPDB_API_KEY is not set.
        """
        load_dotenv()
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not self.api_key:
            raise ValueError("ABUSEIPDB_API_KEY is not set")

    def lookup_ip(self, ip_value, max_age_days=90):
        """Look up an IP address on AbuseIPDB.

        Args:
            ip_value (str): The IP address to look up.
            max_age_days (int): Max age of reports to consider.

        Returns:
            dict: Normalized result {abuse_score, total_reports,
                country_code, isp}.

        Raises:
            RuntimeError: If AbuseIPDB returns 429 (daily quota exceeded).
            requests.HTTPError: For any other non-200 response.
        """
        headers = {"Accept": "application/json", "Key": self.api_key}

        params = {"ipAddress": ip_value, "maxAgeInDays": max_age_days}

        response = requests.get(
            self.BASE_URL, headers=headers, params=params, timeout=10
        )

        if response.status_code == 429:
            raise RuntimeError(
                "AbuseIPDB daily quota exceeded (429). "
                "Free tier allows 1000 lookups/day."
            )

        response.raise_for_status()

        data = response.json()["data"]

        return {
            "abuse_score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "country_code": data["countryCode"],
            "isp": data["isp"],
        }
