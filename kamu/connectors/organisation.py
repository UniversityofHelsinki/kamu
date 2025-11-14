import logging

from kamu.connectors import ApiConnector

logger = logging.getLogger(__name__)


class OrganisationApiConnector(ApiConnector):
    """
    Connector for loading organisation structure.
    """

    api_name: str = "Organisation API"
    settings_dict_name: str = "ORGANISATION_API"

    def get_organisation_data(self, path: str) -> list:
        """
        Loads organisation data from a specific path.
        """
        response = self.api_call(path=path, http_method="get")
        return response
