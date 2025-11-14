import logging

from django.utils import timezone

from kamu.connectors import ApiConfigurationError, ApiConnector
from kamu.models.account import Account
from kamu.models.identity import Identity
from kamu.utils.account import get_account_data

logger = logging.getLogger(__name__)


class AccountApiConnector(ApiConnector):
    """
    Connector for managing user accounts.
    """

    api_name: str = "Account API"
    settings_dict_name: str = "ACCOUNT_API"

    def create_account(self, identity: Identity, uid: str, password: str, account_type: Account.Type) -> Account:
        """
        Creates an account.
        """
        data = get_account_data(identity, account_type=account_type)
        data["uid"] = uid
        data["userPassword"] = password
        response = self.api_call(
            path=self._self_get_path("CREATE_PATH", "create"),
            http_method="post",
            data=data,
        )
        if not isinstance(response, dict):
            raise ApiConfigurationError
        r_uid = response.get("uid")
        if r_uid != uid:
            raise ApiConfigurationError
        account = Account._default_manager.create(identity=identity, uid=uid, type=account_type)
        return account

    def disable_account(self, account: Account) -> None:
        """
        Disables the account.

        Set account status to DISABLED if it was ENABLED. This leaves EXPIRED accounts as they are.
        """
        data = {"uid": account.uid}
        self.api_call(path=self._self_get_path("DISABLE_PATH", "disable"), http_method="post", data=data)
        if account.status == Account.Status.ENABLED:
            account.deactivated_at = timezone.now()
            account.status = Account.Status.DISABLED
            account.save()

    def enable_account(self, account: Account) -> None:
        """
        Enables the account.
        """
        data = {"uid": account.uid}
        self.api_call(path=self._self_get_path("ENABLE_PATH", "enable"), http_method="post", data=data)
        account.status = Account.Status.ENABLED
        account.deactivated_at = None
        account.save()

    def set_account_password(self, account: Account, password: str) -> None:
        """
        Sets the account password.
        """
        data = {"userPassword": password, "uid": account.uid}
        self.api_call(
            path=self._self_get_path("CHANGE_PASSWORD_PATH", "changePassword"), http_method="post", data=data
        )

    def update_account(self, account: Account) -> None:
        """
        Updates the account.
        """
        data = get_account_data(account.identity, account_type=Account.Type(account.type))
        data["uid"] = account.uid
        self.api_call(path=self._self_get_path("UPDATE_PATH", "update"), http_method="post", data=data)
        account.save()

    def get_uid_choices(self, number: int = 5, exclude_chars: str = "", exclude_string: str = "") -> list:
        """
        Gets the account uid choices.
        """
        headers = {"amount": str(number), "exclude": exclude_chars, "ssnExclude": exclude_string}
        uid_choices = self.api_call(
            path=self._self_get_path("UID_CHOICES_PATH", "generateUids"), http_method="get", headers=headers
        )
        if not isinstance(uid_choices, list):
            raise ApiConfigurationError
        return uid_choices
