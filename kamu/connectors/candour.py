import hashlib
import hmac
import json
import logging
from datetime import timedelta
from typing import Any

import requests
from django.conf import settings
from django.utils import timezone

from kamu.models.identity import Identity

logger = logging.getLogger(__name__)


class CandourApiConfigurationError(Exception):
    """
    Configuration error in either the API or the settings.
    """

    pass


class CandourApiTryAgainError(Exception):
    """
    Temporary or configuration error in the API.
    """

    pass


class CandourApiConnector:
    """
    Connector for a person database.
    """

    def __init__(self) -> None:
        """
        Initialize connection and set setting values.
        """
        self.candour_settings = getattr(settings, "CANDOUR_API", None)
        if not self.candour_settings:
            logger.error("Candour API settings not found.")
            raise CandourApiConfigurationError("Incorrect Candour API settings.")
        self.url = self.candour_settings.get("URL", "")
        self.public_key = self.candour_settings.get("PUBLIC_KEY", "")
        self.secret_key = self.candour_settings.get("SECRET_KEY", "")
        self.timeout = self.candour_settings.get("TIMEOUT", 15)
        self.verify_ssl = self.candour_settings.get("VERIFY_SSL", True)
        self.callback_url = self.candour_settings.get("CALLBACK_URL", "")
        self.candour_session_timeout = self.candour_settings.get("SESSION_TIMEOUT_HOURS", 24)
        if not self.url or not self.public_key or not self.secret_key:
            logger.error("Candour API missing parameters.")
            raise CandourApiConfigurationError("Incorrect Candour database API settings.")
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
        self.headers["X-HMAC-SIGNATURE"] = hmac_signature
        response = requests.post(
            self.url,
            headers=self.headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
            data=data,
        )
        response.raise_for_status()
        return response.json()

    def _get_candour_result(self, invitation_id: str) -> dict[str, Any]:
        """
        GET request to get the result of a Candour session.
        """
        hmac_signature = self.create_hmac_sha256(invitation_id.encode("utf-8"))
        self.headers["X-HMAC-SIGNATURE"] = hmac_signature
        response = requests.get(
            self.url + "/" + invitation_id,
            headers=self.headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        return response.json()

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
            raise CandourApiTryAgainError("Failed to create Candour session, please try again later.") from e

    def get_candour_result(self, verification_session_id: str) -> dict[str, Any]:
        """
        Get the result of a Candour verification session.
        """
        try:
            response_data = self._get_candour_result(verification_session_id)
            return response_data
        except Exception as e:
            logger.error("Error creating Candour session: %s", str(e))
            raise CandourApiTryAgainError("Failed to create Candour session, please try again later.") from e
