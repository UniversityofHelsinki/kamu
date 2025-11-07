import json
import logging
from urllib.parse import urljoin

import requests
from django.conf import settings

from kamu.connectors import ApiConfigurationError, ApiTemporaryError

logger = logging.getLogger(__name__)


class OrganisationApiConnector:
    """
    Connector for loading organisation structure.
    """

    def __init__(self) -> None:
        """
        Initialize connection and set setting values.
        """
        self.url = getattr(settings, "ORGANISATION_API_URL", "")
        authorization_header = getattr(settings, "ORGANISATION_AUTH_HEADER", "apikey")
        api_key = getattr(settings, "ORGANISATION_API_KEY", None)
        self.timeout = getattr(settings, "ORGANISATION_API_TIMEOUT", 3)
        self.verify_ssl = getattr(settings, "ORGANISATION_API_VERIFY_SSL", True)
        cert_file_path = getattr(settings, "ORGANISATION_API_CERT_FILE_PATH", None)
        key_file_path = getattr(settings, "ORGANISATION_API_KEY_FILE_PATH", None)
        self.cert = (cert_file_path, key_file_path) if cert_file_path and key_file_path else None
        if not self.url or api_key is None or authorization_header is None:
            logger.error("Organisation API missing parameters.")
            raise ApiConfigurationError("Incorrect organisation API settings.")
        self.headers = {authorization_header: api_key, "Content-Type": "application/json"}

    def api_call_get(self, url: str, headers: dict | None = None) -> requests.Response:
        """
        Makes a GET request to the API.
        """
        headers = self.headers if headers is None else self.headers | headers
        return requests.get(
            url,
            headers=headers,
            timeout=self.timeout,
            cert=self.cert,
            verify=self.verify_ssl,
        )

    def api_call(self, http_method: str, path: str, headers: dict | None = None) -> list:
        """
        Makes a call to the API and returns either response content or raises an exception.
        """
        url = urljoin(self.url, path)
        try:
            if http_method == "get":
                response = self.api_call_get(url, headers)
            else:
                logger.error("Organisation API unknown HTTP method.")
                raise ApiConfigurationError
        # Handle exceptions
        except OSError as e:
            logger.error(f"Organisation API OS Error: {e}")
            raise ApiConfigurationError from e
        except requests.exceptions.SSLError as e:
            logger.error(f"Organisation API SSL Error: {e}")
            raise ApiConfigurationError from e
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Organisation API connection Error: {e}")
            raise ApiTemporaryError from e
        except requests.exceptions.Timeout as e:
            logger.error(f"Organisation API timeout: {e}")
            raise ApiTemporaryError from e
        # Handle response codes
        if response.status_code in getattr(settings, "ORGANISATION_API_SUCCESS_CODES", [200]):
            content = json.loads(response.content)
            return content
        elif response.status_code == 400:
            logger.error(f"Organisation API status 400: {response.text}")
            raise ApiTemporaryError(f"API error, status {response.status_code}")
        elif response.status_code == 403:
            logger.error("Organisation API status 403: Incorrect settings.")
            raise ApiConfigurationError(f"API error, status {response.status_code}")
        elif response.status_code == 404:
            logger.error("Organisation API status 404: Not found.")
            raise ApiConfigurationError(f"API error, status {response.status_code}")
        else:
            error_msg = "Organisation API Error"
            logger.error(f"Organisation API status {response.status_code} : {error_msg}")
            raise ApiTemporaryError(f"API error, status {response.status_code}")

    def get_organisation_data(self, path: str) -> list:
        """
        Loads organisation data from a specific path.
        """
        response = self.api_call(path=path, http_method="get")
        return response
