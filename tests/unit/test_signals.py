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
from tests.setup import BaseTestCase

audit_log = AuditLog()


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


class SignalUpdateTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.role = self.create_role("consultant")
        self.permission = self.create_permission("service")
        self.role.permissions.add(self.permission)
        self.identity = self.create_identity(user=True)
        self.membership = self.create_membership(role=self.role, identity=self.identity, approver=self.user)

    def test_role_updated_at_permission_change(self):
        updated_at = self.role.updated_at
        self.permission.value = "changedvalue"
        self.permission.save()
        self.role.refresh_from_db()
        self.assertGreater(self.role.updated_at, updated_at)

    def test_membership_updated_at_permission_change(self):
        updated_at = self.membership.updated_at
        self.permission.value = "changedvalue"
        self.permission.save()
        self.membership.refresh_from_db()
        self.assertGreater(self.membership.updated_at, updated_at)

    def test_identity_updated_at_permission_change(self):
        self.identity.refresh_from_db()
        updated_at = self.identity.updated_at
        self.permission.value = "changedvalue"
        self.permission.save()
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)

    def _requirement_change_test(self):
        self.identity.refresh_from_db()
        updated_at = self.identity.updated_at
        self.requirement.grace = 2
        self.requirement.save()
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)

    def test_identity_updated_at_role_requirement_change(self):
        self.requirement = self.create_requirement("contract_nda")
        self.role.requirements.add(self.requirement)
        self._requirement_change_test()

    def test_identity_updated_at_permission_requirement_change(self):
        self.requirement = self.create_requirement("contract_nda")
        self.permission.requirements.add(self.requirement)
        self._requirement_change_test()

    def test_identity_updated_at_permission_removal(self):
        self.identity.refresh_from_db()
        updated_at = self.identity.updated_at
        self.permission.delete()
        self.identity.refresh_from_db()
        self.assertGreater(self.identity.updated_at, updated_at)

    def test_membership_with_added_unfulfilled_requirement_deactivated(self):
        self.requirement = self.create_requirement("contract_nda")
        updated_at = self.membership.updated_at
        self.assertEqual(self.membership.status, Membership.Status.ACTIVE)
        self.permission.requirements.add(self.requirement)
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.status, Membership.Status.REQUIRE)
        self.assertGreater(self.membership.updated_at, updated_at)

    def test_membership_with_added_unfulfilled_requirement_with_grace(self):
        self.requirement = self.create_requirement("attribute_phone_number")
        updated_at = self.membership.updated_at
        self.assertEqual(self.membership.status, Membership.Status.ACTIVE)
        self.permission.requirements.add(self.requirement)
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.status, Membership.Status.ACTIVE)
        self.assertGreater(self.membership.updated_at, updated_at)

    def test_membership_status_updated_with_fulfilled_requirement(self):
        self.requirement = self.create_requirement("attribute_phone_number")
        self.requirement.grace = 0
        self.requirement.save()
        self.permission.requirements.add(self.requirement)
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.status, Membership.Status.REQUIRE)
        self.phone_number = PhoneNumber.objects.create(identity=self.identity, number="+1234567890", verified=True)
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.status, Membership.Status.ACTIVE)
