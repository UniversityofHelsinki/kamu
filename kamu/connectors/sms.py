import logging

from django.conf import settings

from kamu.connectors import ApiConnector

logger = logging.getLogger(__name__)


class SmsConnector(ApiConnector):
    """
    Connector for sending SMS messages.
    """

    api_name: str = "SMS API"
    settings_dict_name: str = "SMS_API"

    def send_sms(self, number: str, message: str) -> None:
        """
        Send an SMS message.

        Raises ApiError on failure.
        """
        data = {"mobileNumber": number, "message": message}
        if getattr(settings, "SMS_DEBUG", False):
            logger.debug(f"SMS DEBUG: {data}")
            return
        self.api_call(http_method="post", path="", data=data, headers=self.headers)
