import datetime
from unittest import mock

from django.test import TestCase
from requests.models import Response

from kamu.connectors import ApiError
from kamu.connectors.candour import CandourApiConnector
from kamu.connectors.organisation import OrganisationApiConnector
from kamu.models.identity import Identity


class GenericConnectorTests(TestCase):

    @mock.patch("requests.get", return_value=mock.MagicMock(status_code=200))
    @mock.patch("kamu.connectors.logger")
    def test_creating_candour_session(self, mock_logger, mock_post):
        connector = OrganisationApiConnector()
        response = Response()
        response.status_code = 200
        response._content = b'{"content": "invalid_json": {"invalid", "json"}}'
        mock_post.return_value = response
        with self.assertRaises(ApiError):
            connector.get_organisation_data(path="invalid_path")
        mock_logger.error.assert_called_once()
        mock_logger.debug.assert_called_once()


class CandourConnectorTests(TestCase):
    def setUp(self):
        self.identity = Identity.objects.create(
            given_names="Test", surname="User", date_of_birth=datetime.date(1999, 1, 1)
        )

    @mock.patch("requests.post", return_value=mock.MagicMock(status_code=200))
    def test_creating_candour_session(self, mock_post):
        response = Response()
        response.status_code = 200
        response._content = b'{"verificationSessionId": "1234"}'
        mock_post.return_value = response
        connector = CandourApiConnector()
        connector.create_candour_session(self.identity)
        call_kwargs = mock_post.call_args.kwargs
        self.assertIn("X-HMAC-SIGNATURE", call_kwargs["headers"])
        self.assertIn('"dateOfBirth":"1999-01-01"', call_kwargs["data"])

    @mock.patch("requests.get", return_value=mock.MagicMock(status_code=200))
    def test_get_candour_result(self, mock_get):
        response = Response()
        response.status_code = 200
        response._content = b'{"status": "pending"}'
        mock_get.return_value = response
        connector = CandourApiConnector()
        connector.get_candour_result("1234")
        self.assertEqual(mock_get.call_args.args[0], "https://rest-test.candour.fi/v1/1234")
