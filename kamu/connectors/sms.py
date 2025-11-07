import json
import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class SmsConnector:
    """
    Connector for sending SMS messages.
    """

    def __init__(self) -> None:
        """
        Initialize connection and set setting values.
        """
        self.url = getattr(settings, "SMS_API_URL", None)
        self.authorization_header = getattr(settings, "SMS_AUTH_HEADER", "X-Api-Key")
        self.api_key = getattr(settings, "SMS_API_KEY", None)
        self.timeout = getattr(settings, "SMS_API_TIMEOUT", 3)

    def send_sms(self, number: str, message: str) -> bool:
        """
        Send an SMS message.
        """
        if self.url is None or self.api_key is None or self.authorization_header is None:
            logger.error("SMS API is missing setting parameters.")
            return False
        headers = {self.authorization_header: self.api_key, "Content-Type": "application/json"}
        data = {"mobileNumber": number, "message": message}
        if getattr(settings, "SMS_DEBUG", False):
            logger.debug(f"SMS DEBUG: {data}")
            return True
        response = requests.post(self.url, headers=headers, timeout=self.timeout, data=json.dumps(data))
        if response.status_code == 200:
            return True
        else:
            logger.error(f"SMS API error: {response.status_code}.")
            return False
