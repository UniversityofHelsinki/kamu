"""
Unit tests for identities.
"""

from django.test import TestCase

from kamu.models.identity import EmailAddress, Identity, PhoneNumber
from kamu.utils.audit import AuditLog

audit_log = AuditLog()


class IdentityMethodTests(TestCase):
    def setUp(self):
        self.identity = Identity.objects.create(given_names="Test Identity")

    def test_identity_email_address(self):
        # Should return the lowest priority verified email address
        self.assertIsNone(self.identity.email_address())
        email_address1 = EmailAddress.objects.create(
            identity=self.identity, address="test@example.org", verified=False, priority=1
        )
        email_address2 = EmailAddress.objects.create(
            identity=self.identity, address="test@example.com", verified=False, priority=0
        )
        self.assertIsNone(self.identity.email_address())
        email_address1.verified = True
        email_address1.save()
        self.assertEqual("test@example.org", self.identity.email_address())
        email_address2.verified = True
        email_address2.save()
        self.assertEqual("test@example.com", self.identity.email_address())

    def test_identity_phone_number(self):
        # Should return the lowest priority verified phone number
        self.assertIsNone(self.identity.phone_number())
        phone_number1 = PhoneNumber.objects.create(
            identity=self.identity, number="+1234567890", verified=False, priority=1
        )
        phone_number2 = PhoneNumber.objects.create(
            identity=self.identity, number="+1234567891", verified=False, priority=0
        )
        self.assertIsNone(self.identity.phone_number())
        phone_number1.verified = True
        phone_number1.save()
        self.assertEqual("+1234567890", self.identity.phone_number())
        phone_number2.verified = True
        phone_number2.save()
        self.assertEqual("+1234567891", self.identity.phone_number())
