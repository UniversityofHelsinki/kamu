import hashlib
import hmac
import json
import logging
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.utils import timezone

from kamu.connectors import ApiConfigurationError, ApiConnector, ApiTemporaryError
from kamu.models.identity import Identity

logger = logging.getLogger(__name__)


class CandourApiConnector(ApiConnector):
    """
    Connector for a person database.
    """

    api_name: str = "Candour API"
    settings_dict_name: str = "CANDOUR_API"

    def __init__(self) -> None:
        """
        Add API specific settings.
        """

        super().__init__()
        self.candour_settings = getattr(settings, self.settings_dict_name, None)
        if not self.candour_settings:
            logger.error(f"{self.api_name} settings not found.")
            raise ApiConfigurationError(f"Incorrect {self.api_name} API settings.")
        self.secret_key = self.candour_settings.get("API_KEY", "")
        self.public_key = self.candour_settings.get("API_PUBLIC_KEY", "")
        self.timeout = self.candour_settings.get("TIMEOUT", 15)
        self.callback_url = self.candour_settings.get("CALLBACK_URL", "")
        self.candour_session_timeout = self.candour_settings.get("SESSION_TIMEOUT_HOURS", 24)
        if not self.url or not self.public_key or not self.secret_key:
            logger.error(f"{self.api_name} missing parameters.")
            raise ApiConfigurationError(f"Incorrect {self.api_name} API settings.")
        self.headers = {"X-AUTH-CLIENT": self.public_key, "Content-Type": "application/json"}

    def create_hmac_sha256(self, payload: bytes) -> str:
        """
        Create HMAC SHA256 hash of the payload using the secret key.
        """
        key_bytes = self.secret_key.encode()
        hmac_hash = hmac.new(key_bytes, payload, hashlib.sha256)
        return hmac_hash.hexdigest()

    def _create_candour_session(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Sends a POST request to create a Candour session.
        """
        data = json.dumps(payload, sort_keys=False, separators=(",", ":"))
        hmac_signature = self.create_hmac_sha256(data.encode("utf-8"))
        headers = self.headers | {"X-HMAC-SIGNATURE": hmac_signature}
        return self.api_call(http_method="post", path="", data=data, headers=headers)

    def _get_candour_result(self, invitation_id: str) -> dict[str, Any]:
        """
        GET request to get the result of a Candour session.
        """
        hmac_signature = self.create_hmac_sha256(invitation_id.encode("utf-8"))
        headers = self.headers | {"X-HMAC-SIGNATURE": hmac_signature}
        return self.api_call(http_method="get", path=invitation_id, headers=headers)

    def _get_result_properties(self) -> dict[str, bool]:
        return {
            "name": True,
            "dateOfBirth": True,
            "idDocumentType": True,
            "idExpiration": True,
            "idIssuer": True,
            "idNumber": True,
            "nationality": True,
            "nationalIdentificationNumber": True,
            "sex": True,
        }

    def _get_allowed_verification_methods(self, verification_methods: list[str]) -> dict[str, bool]:
        return {
            "rfidApp": "rfidApp" in verification_methods,
            "idApp": "idApp" in verification_methods,
            "idWeb": "idWeb" in verification_methods,
        }

    def _get_allowed_verification_documents(self) -> dict[str, bool]:
        return {
            "passport": True,
            "idCard": True,
        }

    def _get_user(self, identity: Identity) -> dict[str, Any]:
        user = {}
        attr = {
            "given_names": "firstName",
            "surname": "lastName",
            "date_of_birth": "dateOfBirth",
        }
        for key, value in attr.items():
            if getattr(identity, key, ""):
                user[value] = getattr(identity, key).isoformat() if key == "date_of_birth" else getattr(identity, key)
        return user

    def _get_enforce_values(self, user: dict[str, Any]) -> dict[str, Any]:
        enforce = {}
        if "firstName" in user or "lastName" in user:
            enforce["nameScore"] = getattr(settings.CANDOUR_API, "REQUIRED_NAME_SCORE", 90)
        if "dateOfBirth" in user:
            enforce["dateOfBirth"] = True
        return enforce

    def _build_candour_session_payload(
        self,
        identity: Identity,
        valid_hours: int,
        verification_methods: list[str],
    ) -> dict[str, Any]:
        timestamp = timezone.now()
        user = self._get_user(identity)
        payload = {
            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            "validUntil": (timestamp + timedelta(hours=valid_hours)).isoformat().replace("+00:00", "Z"),
            "callbackUrl": self.callback_url,
            "tries": getattr(settings.CANDOUR_API, "TRIES", 5),
            "allowedVerificationMethods": self._get_allowed_verification_methods(verification_methods),
            "allowedVerificationDocuments": self._get_allowed_verification_documents(),
            "resultProperties": self._get_result_properties(),
            "user": user,
            "enforceValues": self._get_enforce_values(user),
        }
        return payload

    def create_candour_session(
        self, identity: Identity, valid_hours: int | None = None, verification_methods: list | None = None
    ) -> dict[str, Any]:
        """
        Create a Candour session for identity verification.
        """
        if verification_methods is None:
            verification_methods = ["rfidApp"]
        session_timeout = valid_hours if valid_hours else self.candour_session_timeout
        payload = self._build_candour_session_payload(identity, session_timeout, verification_methods)
        try:
            response_data = self._create_candour_session(payload)
            return response_data
        except Exception as e:
            logger.error("Error creating Candour session: %s", str(e))
            raise ApiTemporaryError("Failed to create Candour session, please try again later.") from e

    def get_candour_result(self, verification_session_id: str) -> dict[str, Any]:
        """
        Get the result of a Candour verification session.
        """
        try:
            response_data = self._get_candour_result(verification_session_id)
            return response_data
        except Exception as e:
            logger.error("Error creating Candour session: %s", str(e))
            raise ApiTemporaryError("Failed to verify Candour session, please try again later.") from e
