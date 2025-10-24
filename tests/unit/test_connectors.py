import datetime
from unittest import mock

from django.test import TestCase

from kamu.connectors.candour import CandourApiConnector
from kamu.models.identity import Identity


class CandourConnectorTests(TestCase):
    def setUp(self):
        self.identity = Identity.objects.create(
            given_names="Test", surname="User", date_of_birth=datetime.date(1999, 1, 1)
        )

    @mock.patch("requests.post", return_value=mock.MagicMock(status_code=200))
    def test_creating_candour_session(self, mock_post):
        connector = CandourApiConnector()
        connector.create_candour_session(self.identity)
        call_kwargs = mock_post.call_args.kwargs
        self.assertIn("X-HMAC-SIGNATURE", call_kwargs["headers"])
        self.assertIn('"dateOfBirth":"1999-01-01"', call_kwargs["data"])

    @mock.patch("requests.get", return_value=mock.MagicMock(status_code=200))
    def test_get_candour_result(self, mock_get):
        connector = CandourApiConnector()
        connector.get_candour_result("1234")
        self.assertEqual(mock_get.call_args.args[0], "https://rest-test.candour.fi/v1/1234")
