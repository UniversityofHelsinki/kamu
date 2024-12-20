"""
Unit tests for identities.
"""

import datetime

from django.test import TestCase
from django.utils import timezone

from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.models.membership import Membership
from kamu.models.role import Role
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


class IdentityUpdatedAtTests(TestCase):
    def setUp(self):
        self.identity = Identity.objects.create(given_names="Test Identity")

    def test_identity_updated_at(self):
        updated_at = self.identity.updated_at
        self.identity.save()
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)

    def test_identity_updated_at_identifier(self):
        updated_at = self.identity.updated_at
        identifier = Identifier.objects.create(identity=self.identity, type="eppn", value="test")
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)
        updated_at = self.identity.updated_at
        identifier.deactivated_at = timezone.now()
        identifier.save()
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)

    def test_identity_updated_at_email_address(self):
        updated_at = self.identity.updated_at
        email_address = EmailAddress.objects.create(identity=self.identity, address="test@example.org")
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)
        updated_at = self.identity.updated_at
        email_address.delete()
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)

    def test_identity_updated_at_phone_number(self):
        updated_at = self.identity.updated_at
        phone_number = PhoneNumber.objects.create(identity=self.identity, number="+123456789")
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)
        updated_at = self.identity.updated_at
        phone_number.delete()
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)

    def test_identity_updated_at_contract(self):
        updated_at = self.identity.updated_at
        template = ContractTemplate.objects.create(
            type="Test Template",
        )
        contract = Contract.objects.create(identity=self.identity, template=template)
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)
        updated_at = self.identity.updated_at
        contract.delete()
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)

    def test_identity_updated_at_membership(self):
        updated_at = self.identity.updated_at
        role = Role.objects.create(identifier="Test Role", maximum_duration=30)
        membership = Membership.objects.create(
            role=role,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        self.identity.refresh_from_db()
        self.assertEqual(self.identity.updated_at, updated_at)
        membership.identity = self.identity
        membership.save()
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)
        updated_at = self.identity.updated_at
        membership.expire_date = timezone.now().date()
        membership.save()
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)
