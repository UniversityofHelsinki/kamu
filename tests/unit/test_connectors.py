import dataclasses
import datetime
from unittest import mock

from django.core import mail
from django.test import TestCase, override_settings
from django.utils import timezone
from requests.models import Response

from kamu.connectors import ApiError
from kamu.connectors.candour import CandourApiConnector
from kamu.connectors.email import send_add_email
from kamu.connectors.organisation import OrganisationApiConnector
from kamu.connectors.persondb import PersonDBApiConnector
from kamu.models.identity import Country, Identity
from tests.data import PERSONS
from tests.setup import BaseTestCase


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
        self.assertIn('"dateOfBirth":"1999-01-01"', call_kwargs["data"].decode("utf-8"))

    @mock.patch("requests.get", return_value=mock.MagicMock(status_code=200))
    def test_get_candour_result(self, mock_get):
        response = Response()
        response.status_code = 200
        response._content = b'{"status": "pending"}'
        mock_get.return_value = response
        connector = CandourApiConnector()
        connector.get_candour_result("1234")
        self.assertEqual(mock_get.call_args.args[0], "https://rest-test.candour.fi/v1/1234")


class PersonDBConnectorTests(TestCase):
    def setUp(self):
        self.person_uuid = "12345678-1234-1234-1234-123456789012"

    @override_settings(ALLOW_TEST_FPIC=True)
    @mock.patch("requests.get", return_value=mock.MagicMock(status_code=200))
    def test_importing_persondb_data(self, mock_get):
        response = Response()
        response.status_code = 200
        response._content = b"""[{
            "personUuid": "12345678-1234-1234-1234-123456789012",
            "dateOfBirth": "1981-01-01",
            "dateOfBirthTl": 10,
            "officialGivenNames": "Tester",
            "officialGivenNamesTl": 30,
            "officialSurnames": "Mr. User",
            "officialSurnamesTl": 30,
            "preferredGivenName": "Test",
            "preferredSurname": "User",
            "preferredLanguage": "fi",
            "nationality": null,
            "extEmail": "tester@example.com",
            "extEmailTl": 10,
            "mobilePhonePersonal": "+358501234567",
            "mobilePhonePersonalTl": 20,
            "mobilePhoneWork": "+358401234567",
            "mobilePhoneWorkTl": 30,
            "email": "tester@example.org",
            "emailTl": 30,
            "personIdentifiers": [
              {
                "identifierName": "ssn",
                "identifierValue": "010181-900C",
                "trustLevel": 50
              }
            ],
            "accounts": [
              {
                "username": "testuser",
                "accountTypeId": 1,
                "accountSubtypeId": 1000
              },
              {
                "username": "adminuser",
                "accountTypeId": 8,
                "accountSubtypeId": 8000
              }
            ]
          }]"""
        mock_get.return_value = response
        connector = PersonDBApiConnector()
        person = connector.get_person(person_uuid=self.person_uuid)
        person_example = PERSONS.get("tester")
        self.assertEqual(person, person_example)

    @override_settings(ALLOW_TEST_FPIC=True)
    @mock.patch("requests.get", return_value=mock.MagicMock(status_code=200))
    def test_importing_empty_person(self, mock_get):
        Country.objects.create(code="FI", name_fi="Suomi", name_en="Finland", name_sv="Finland")
        response = Response()
        response.status_code = 200
        response._content = b"""[{
            "personUuid": "12345678-1234-1234-1234-123456789012"
          }]"""
        mock_get.return_value = response
        connector = PersonDBApiConnector()
        person = connector.get_person(person_uuid=self.person_uuid)
        for field in [f.name for f in dataclasses.fields(person)]:
            if field not in ["person_uuid", "preferred_language", "identifiers"]:
                self.assertIn(getattr(person, field), [None, frozenset(), "", Identity.VerificationMethod.UNVERIFIED])


class EmailConnectorTests(BaseTestCase):
    def setUp(self):
        role = self.create_role()
        self.identity = self.create_identity()
        self.membership = self.create_membership(role=role, identity=self.identity)

    def test_add_role_notification_email(self):
        send_add_email(self.membership)
        self.assertEqual(0, len(mail.outbox))
        self.identity.email_addresses.create(address="test@example.org")
        send_add_email(self.membership)
        self.assertEqual(1, len(mail.outbox))
        self.identity.email_addresses.create(address="test2@example.org", verified=timezone.now())
        mail.outbox = []
        send_add_email(self.membership)
        self.assertEqual(1, len(mail.outbox))
        self.assertEqual(mail.outbox[0].to, ["test2@example.org"])

    @override_settings(NEW_MEMBERSHIP_NOTIFICATION_RECIPIENTS="verified")
    def test_add_role_notification_email_to_verified(self):
        self.identity.email_addresses.create(address="test@example.org")
        send_add_email(self.membership)
        self.assertEqual(0, len(mail.outbox))
        self.identity.email_addresses.create(address="test2@example.org", verified=timezone.now())
        send_add_email(self.membership)
        self.assertEqual(1, len(mail.outbox))
        self.assertEqual(mail.outbox[0].to, ["test2@example.org"])

    @override_settings(NEW_MEMBERSHIP_NOTIFICATION_RECIPIENTS="all")
    def test_add_role_notification_email_to_all(self):
        self.identity.email_addresses.create(address="test@example.org")
        self.identity.email_addresses.create(address="test2@example.org", verified=timezone.now())
        send_add_email(self.membership)
        self.assertEqual(1, len(mail.outbox))
        self.assertEqual(2, len(mail.outbox[0].to))
