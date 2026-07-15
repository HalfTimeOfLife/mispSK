from pymisp import PyMISP, PyMISPError, MISPEvent
import os
from dotenv import load_dotenv


class MispClient:
    """Wrapper around PyMISP that handles configuration loading, validation,
    and connection to a MISP instance.

    Attributes:
        url (str): The MISP instance URL.
        api_key (str): The MISP API authentication key.
        verify_ssl (bool): Whether to verify the instance's SSL certificate.
        misp (PyMISP): The connected PyMISP client instance.
    """

    def __init__(self):
        """Initialize the client by loading config, validating it, and connecting to MISP."""
        self._load_config()
        self._validate_config()
        self.misp = self._connect()

    def _load_config(self):
        """Load MISP connection settings from environment variables (.env).

        Sets self.url, self.api_key, and self.verify_ssl.
        """
        load_dotenv()

        self.url = os.getenv("MISP_URL")
        self.api_key = os.getenv("MISP_API_KEY")
        self.verify_ssl = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"

    def _validate_config(self):
        """Validate that required configuration values are present.

        Raises:
            ValueError: If MISP_URL or MISP_API_KEY is missing.
        """
        if not self.url:
            raise ValueError("MISP_URL is not set")

        if not self.api_key:
            raise ValueError("MISP_API_KEY is not set")

    def _connect(self):
        """Establish a connection to the MISP instance via PyMISP.

        Returns:
            PyMISP: A connected PyMISP client instance.

        Raises:
            ConnectionError: If the connection to MISP fails.
        """
        if not self.verify_ssl:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            return PyMISP(self.url, self.api_key, self.verify_ssl)
        except PyMISPError as e:
            raise ConnectionError(f"Unable to connect to MISP: {e}")

    def get_client(self):
        """Return the connected PyMISP client.

        Returns:
            PyMISP: The active PyMISP client instance.
        """
        return self.misp

    def get_event_by_id(self, event_id):
        """Retrieve a single MISP event by its ID.

        Args:
            event_id (int): The event ID to look up.

        Returns:
            MISPEvent or None: The matching event, or None if no event
                was found for that ID.
        """
        event = self.misp.get_event(event_id, pythonify=True)
        if not isinstance(event, MISPEvent):
            return None
        return event

    def get_events_by_ioc(self, ioc_value):
        """Search for MISP events containing a given IOC value.

        Args:
            ioc_value (str): The IOC value to search for.

        Returns:
            list[MISPEvent]: A list of matching events (possibly empty).
        """
        return self.misp.search(value=ioc_value, controller="events", pythonify=True)
