import json
import logging
from typing import Any
from urllib.parse import urljoin

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class ApiError(Exception):
    """
    Generic API exception
    """

    pass


class ApiConfigurationError(ApiError):
    """
    Configuration error in either the API or the settings.
    """

    pass


class ApiTemporaryError(ApiError):
    """
    Likely temporary error in the API.
    """

    pass


class ApiConnector:
    """
    Generic API connector using request.
    """

    api_name: str = "Base API"
    settings_dict_name: str = ""
    success_codes = [200, 201, 204]
    configuration_error_codes = [400, 403, 500]
    response_is_json = True

    def __init__(self) -> None:
        """
        Initialize connection and set setting values.
        """
        self.api_settings = getattr(settings, self.settings_dict_name, None)
        if not self.api_settings:
            logger.error(f"{self.api_name} settings not found.")
            raise ApiConfigurationError(f"Incorrect {self.api_name} API settings.")
        self.url = self.api_settings.get("URL", "")
        authorization_header = self.api_settings.get("AUTH_HEADER", "X-Api-Key")
        api_key = self.api_settings.get("API_KEY", None)
        self.timeout = self.api_settings.get("TIMEOUT", 3)
        self.verify_ssl = self.api_settings.get("VERIFY_SSL", True)
        cert_file_path = self.api_settings.get("CERT_FILE_PATH", None)
        key_file_path = self.api_settings.get("KEY_FILE_PATH", None)
        self.success_codes = self.api_settings.get("SUCCESS_CODES", self.success_codes)
        self.configuration_error_codes = self.api_settings.get(
            "CONFIGURATION_ERROR_CODES", self.configuration_error_codes
        )
        self.cert = (cert_file_path, key_file_path) if cert_file_path and key_file_path else None
        if not self.url or api_key is None or authorization_header is None:
            logger.error(f"{self.api_name} missing parameters.")
            raise ApiConfigurationError(f"Incorrect {self.api_name} API settings.")
        self.headers = {authorization_header: api_key, "Content-Type": "application/json"}
        if self.response_is_json:
            self.headers["Accept"] = "application/json"

    def _self_get_path(self, setting: str, default: str) -> str:
        """
        Returns the API path for the given setting.
        """
        if self.api_settings:
            return self.api_settings.get(setting, default)
        return default

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

    def api_call_post(
        self, url: str, data: dict | str | bytes | None = None, headers: dict | None = None
    ) -> requests.Response:
        """
        Makes a POST request to the API.
        """
        headers = self.headers if headers is None else self.headers | headers
        return requests.post(
            url,
            headers=headers,
            timeout=self.timeout,
            cert=self.cert,
            verify=self.verify_ssl,
            data=json.dumps(data) if isinstance(data, dict) else data,
        )

    def api_call(
        self, http_method: str, path: str, data: dict | str | bytes | None = None, headers: dict | None = None
    ) -> Any:
        """
        Makes a call to the API and returns either response content or raises an exception.

        Decodes response JSON if response_is_json is True (default), otherwise returns raw content.
        """
        url = urljoin(self.url, path)
        try:
            if http_method == "get":
                response = self.api_call_get(url, headers)
            elif http_method == "post":
                response = self.api_call_post(url, data, headers)
            else:
                logger.error(f"{self.api_name} unknown HTTP method.")
                raise ApiConfigurationError
        # Handle exceptions
        except OSError as e:
            logger.error(f"{self.api_name} OS Error: {e}")
            raise ApiConfigurationError from e
        except requests.exceptions.SSLError as e:
            logger.error(f"{self.api_name} SSL Error: {e}")
            raise ApiConfigurationError from e
        except requests.exceptions.ConnectionError as e:
            logger.error(f"{self.api_name} connection Error: {e}")
            raise ApiTemporaryError from e
        except requests.exceptions.Timeout as e:
            logger.error(f"{self.api_name} timeout: {e}")
            raise ApiTemporaryError from e
        # Handle response codes
        if response.status_code in self.success_codes:
            if self.response_is_json:
                try:
                    return json.loads(response.content)
                except json.JSONDecodeError as e:
                    logger.error(f"{self.api_name} returned invalid JSON.")
                    logger.debug(f"Invalid JSON content: {response.content!r}")
                    raise ApiError(f"{self.api_name} returned invalid JSON.") from e
            else:
                return response.content
        elif response.status_code in self.configuration_error_codes:
            logger.error(f"{self.api_name}, error status: {response.status_code}")
            raise ApiConfigurationError(f"{self.api_name} error, status: {response.status_code}")
        else:
            logger.error(f"{self.api_name}, error status: {response.status_code}")
            raise ApiTemporaryError(f"{self.api_name} error, status: {response.status_code}")
