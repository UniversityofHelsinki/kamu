"""
Unit tests for base app.
"""

import datetime

from django.test import TestCase
from django.utils import timezone

from base.models import TimeLimitError, Token
from identity.models import EmailAddress, Identity, PhoneNumber
from role.models import Membership, Role


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
