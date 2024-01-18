"""
Unit tests for base app.
"""

import datetime
from unittest.mock import patch

from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from base.models import TimeLimitError, Token
from base.utils import AuditLog, get_client_ip
from identity.models import EmailAddress, Identity, PhoneNumber
from role.models import Membership, Role
from tests.setup import BaseTestCase

audit_log = AuditLog()


class GetIPChecks(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.request = self.factory.get("/")
        self.request.META = {"REMOTE_ADDR": "10.1.2.3", "HTTP_X_FORWARDED_FOR": "10.0.0.1, 10.0.0.2"}

    def test_ip_without_forwarding_header(self):
        self.request.META = {"REMOTE_ADDR": "10.1.2.3"}
        response = get_client_ip(self.request)
        self.assertEqual(response, "10.1.2.3")

    def test_ip_forwarding(self):
        response = get_client_ip(self.request)
        self.assertEqual(response, "10.0.0.1")

    @override_settings(HTTP_FORWARDING_IP_FIRST=False)
    def test_ip_forwarding_get_last(self):
        response = get_client_ip(self.request)
        self.assertEqual(response, "10.0.0.2")

    @override_settings(HTTP_CHECK_FORWARDING_HEADER=False)
    def test_ip_no_forwarding_check(self):
        response = get_client_ip(self.request)
        self.assertEqual(response, "10.1.2.3")


class AuditLogTests(BaseTestCase):
    @patch("base.utils.logger_audit.log")
    def test_logging(self, mock_logger):
        audit_log.info("TestMsg", category="TestCat", action="TestAct", outcome="success", objects={self.identity})
        mock_logger.assert_called_with(
            20,
            "TestMsg",
            extra={
                "category": "TestCat",
                "action": "TestAct",
                "outcome": "success",
                "identity": "Test User",
                "identity_id": self.identity.pk,
                "user": "testuser",
                "user_id": self.user.pk,
            },
        )

    @patch("base.utils.logger_audit.log")
    def test_logging_request(self, mock_logger):
        headers = {"REMOTE_ADDR": "10.1.2.3", "HTTP_USER_AGENT": "TestAgent"}
        request = self.factory.get("/", **headers)
        request.user = self.superuser
        audit_log.debug(
            "TestMsg",
            category="TestCat",
            action="TestAct",
            outcome="success",
            request=request,
            objects={self.user},
            extra={"test": "test"},
        )
        mock_logger.assert_called_with(
            10,
            "TestMsg",
            extra={
                "category": "TestCat",
                "action": "TestAct",
                "outcome": "success",
                "identity": "Test User",
                "identity_id": self.identity.pk,
                "user": "testuser",
                "user_id": self.user.pk,
                "ip": "10.1.2.3",
                "user_agent": "TestAgent",
                "actor": "admin",
                "actor_id": self.superuser.pk,
                "test": "test",
            },
        )


class TokenModelTests(TestCase):
    def setUp(self):
        self.identity = self.identity = Identity.objects.create(given_names="Test User")
        self.role = Role.objects.create(identifier="Test Role", maximum_duration=30)
        self.email_address = EmailAddress.objects.create(identity=self.identity, address="test@example.org")
        self.phone_number = PhoneNumber.objects.create(identity=self.identity, number="+123456789")
        self.membership = Membership.objects.create(
            identity=self.identity,
            role=self.role,
            start_date=timezone.now().date(),
            expire_date=(timezone.now() + datetime.timedelta(days=30)).date(),
        )

    def test_email_verification_token(self):
        secret = Token.objects.create_email_object_verification_token(self.email_address)
        self.assertEqual(len(secret), 8)
        self.assertTrue(Token.objects.validate_email_object_verification_token(secret, self.email_address))
        self.assertEqual(Token.objects.filter(email_object=self.email_address).count(), 0)

    def test_sms_verification_token(self):
        secret = Token.objects.create_phone_object_verification_token(self.phone_number)
        self.assertEqual(len(secret), 8)
        self.assertTrue(Token.objects.validate_phone_object_verification_token(secret, self.phone_number))

    def test_email_login_token(self):
        secret = Token.objects.create_email_login_token(self.email_address)
        self.assertEqual(len(secret), 8)
        self.assertTrue(Token.objects.validate_email_login_token(secret, self.email_address))

    def test_sms_login_token(self):
        secret = Token.objects.create_phone_login_token(self.phone_number)
        self.assertEqual(len(secret), 8)
        self.assertTrue(Token.objects.validate_phone_login_token(secret, self.phone_number))

    def test_invite_token(self):
        secret = Token.objects.create_invite_token(self.membership)
        parts = secret.split(":")
        self.assertEqual(parts[0], str(self.membership.pk))
        self.assertEqual(len(parts[1]), 32)
        self.assertTrue(Token.objects.validate_invite_token(parts[1], int(parts[0])))

    def test_new_token(self):
        Token.objects.create_email_object_verification_token(self.email_address)
        with self.settings(TOKEN_TIME_LIMIT_NEW=0):
            Token.objects.create_email_object_verification_token(self.email_address)

    def test_new_token_too_early(self):
        Token.objects.create_email_object_verification_token(self.email_address)
        with self.assertRaises(TimeLimitError):
            Token.objects.create_email_object_verification_token(self.email_address)

    def test_too_many_verifications(self):
        with self.settings(TOKEN_VERIFICATION_TRIES=2):
            Token.objects.create_email_object_verification_token(self.email_address)
        secret = "?1234567"
        self.assertFalse(Token.objects.validate_email_object_verification_token(secret, self.email_address))
        self.assertEqual(Token.objects.filter(email_object=self.email_address).count(), 1)
        self.assertFalse(Token.objects.validate_email_object_verification_token(secret, self.email_address))
        self.assertEqual(Token.objects.filter(email_object=self.email_address).count(), 0)

    def test_expired_token(self):
        secret = Token.objects.create_email_object_verification_token(self.email_address)
        with self.settings(TOKEN_LIFETIME=0):
            self.assertFalse(Token.objects.validate_email_object_verification_token(secret, self.email_address))
