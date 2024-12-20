import json
import logging
from urllib.parse import urljoin

import requests
from django.conf import settings
from django.utils import timezone

from kamu.models.account import Account
from kamu.models.identity import Identity
from kamu.utils.account import get_account_data

logger = logging.getLogger(__name__)


class AccountApiConfigurationError(Exception):
    """
    Configuration error in either the API or the settings.
    """

    pass


class AccountApiTryAgainError(Exception):
    """
    Temporary or configuration error in the API.
    """

    pass


class AccountApiConnector:
    """
    Connector for managing user accounts.
    """

    def __init__(self) -> None:
        """
        Initialize connection and set setting values.
        """
        self.url = getattr(settings, "ACCOUNT_API_URL", "")
        authorization_header = getattr(settings, "ACCOUNT_AUTH_HEADER", "apikey")
        api_key = getattr(settings, "ACCOUNT_API_KEY", None)
        self.timeout = getattr(settings, "ACCOUNT_API_TIMEOUT", 3)
        self.verify_ssl = getattr(settings, "ACCOUNT_API_VERIFY_SSL", True)
        cert_file_path = getattr(settings, "ACCOUNT_API_CERT_FILE_PATH", None)
        key_file_path = getattr(settings, "ACCOUNT_API_KEY_FILE_PATH", None)
        self.cert = (cert_file_path, key_file_path) if cert_file_path and key_file_path else None
        if not self.url or api_key is None or authorization_header is None:
            logger.error("Account API missing parameters.")
            raise AccountApiConfigurationError("Incorrect account API settings.")
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

    def api_call_post(self, url: str, data: dict | None = None, headers: dict | None = None) -> requests.Response:
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
            data=json.dumps(data),
        )

    def api_call(self, http_method: str, path: str, data: dict | None = None, headers: dict | None = None) -> dict:
        """
        Makes a call to the API and returns either response content or raises an exception.
        """
        url = urljoin(self.url, path)
        try:
            if http_method == "get":
                response = self.api_call_get(url, headers)
            elif http_method == "post":
                response = self.api_call_post(url, data, headers)
            else:
                logger.error("Account API unknown HTTP method.")
                raise AccountApiConfigurationError
        # Handle exceptions
        except OSError as e:
            logger.error(f"Account API OS Error: {e}")
            raise AccountApiConfigurationError from e
        except requests.exceptions.SSLError as e:
            logger.error(f"Account API SSL Error: {e}")
            raise AccountApiConfigurationError from e
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Account API connection Error: {e}")
            raise AccountApiTryAgainError from e
        except requests.exceptions.Timeout as e:
            logger.error(f"Account API timeout: {e}")
            raise AccountApiTryAgainError from e
        # Handle response codes
        if response.status_code in getattr(settings, "ACCOUNT_API_SUCCESS_CODES", [200]):
            content = json.loads(response.content)
            return content
        elif response.status_code == 400:
            logger.error(f"Account API status 400: {response.text}")
            raise AccountApiTryAgainError(f"API error, status {response.status_code}")
        elif response.status_code == 403:
            logger.error("Account API status 403: Incorrect settings.")
            raise AccountApiConfigurationError(f"API error, status {response.status_code}")
        elif response.status_code == 404:
            logger.error("Account API status 404: Not found.")
            raise AccountApiConfigurationError(f"API error, status {response.status_code}")
        else:
            error_msg = "Account API Error"
            logger.error(f"Account API status {response.status_code} : {error_msg}")
            raise AccountApiTryAgainError(f"API error, status {response.status_code}")

    def create_account(self, identity: Identity, password: str, account_type: Account.Type) -> Account:
        """
        Creates an account.
        """
        data = get_account_data(identity, account_type=account_type)
        data["userPassword"] = password
        response = self.api_call(
            path=getattr(settings, "ACCOUNT_API_CREATE_PATH", "create"), http_method="post", data=data
        )
        uid = response.get("uid")
        if not uid or not isinstance(uid, str) or not uid.replace("_", "").isalnum():
            raise AccountApiConfigurationError
        account = Account._default_manager.create(identity=identity, uid=uid, type=account_type)
        return account

    def disable_account(self, account: Account) -> None:
        """
        Disables the account.
        """
        data = {"uid": account.uid}
        self.api_call(path=getattr(settings, "ACCOUNT_API_DISABLE_PATH", "disable"), http_method="post", data=data)
        account.deactivated_at = timezone.now()
        account.status = Account.Status.DISABLED
        account.save()

    def enable_account(self, account: Account) -> None:
        """
        Enables the account.
        """
        data = {"uid": account.uid}
        self.api_call(path=getattr(settings, "ACCOUNT_API_ENABLE_PATH", "enable"), http_method="post", data=data)
        account.status = Account.Status.ENABLED
        account.deactivated_at = None
        account.save()

    def set_account_password(self, account: Account, password: str) -> None:
        """
        Sets the account password.
        """
        data = {"userPassword": password, "uid": account.uid}
        self.api_call(
            path=getattr(settings, "ACCOUNT_API_CHANGE_PASSWORD_PATH", "changePassword"), http_method="post", data=data
        )

    def update_account(self, account: Account) -> None:
        """
        Updates the account.
        """
        data = get_account_data(account.identity, account_type=Account.Type(account.type))
        data["uid"] = account.uid
        self.api_call(path=getattr(settings, "ACCOUNT_API_UPDATE_PATH", "update"), http_method="post", data=data)
        account.save()
