"""
Unit tests for role app.
"""

import datetime

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from identity.models import Contract, ContractTemplate, Identity
from role.models import Membership, Permission, Role

User = get_user_model()


class TestData(TestCase):
    def setUp(self):
        self.parent_role = Role.objects.create(identifier="parent", name_en="Parent Role", maximum_duration=20)
        self.role = Role.objects.create(
            identifier="testrole",
            name_en="Test Role",
            description_fi="Testirooli",
            maximum_duration=10,
            parent=self.parent_role,
        )
        self.account_permission = Permission.objects.create(identifier="account", name_en="Account permission", cost=5)
        self.licence_permission = Permission.objects.create(
            identifier="license", name_en="License permission", cost=15
        )
        self.parent_role.permissions.add(self.account_permission)
        self.role.permissions.add(self.licence_permission)


class RoleModelTests(TestData):

    def test_role_name(self):
        self.assertEqual(self.role.name(), "Test Role")

    def test_role_description(self):
        self.assertEqual(self.role.description(lang="fi"), "Testirooli")

    def test_role_hierarchy(self):
        self.assertEqual(self.parent_role.get_role_hierarchy().count(), 1)
        self.assertEqual(self.role.get_role_hierarchy().count(), 2)

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=1)
    def test_role_hierarchy_limit(self):
        self.assertEqual(self.role.get_role_hierarchy().count(), 1)

    def test_role_hierarchy_memberships(self):
        identity = Identity.objects.create(given_names="Test User")
        Membership.objects.create(
            role=self.parent_role,
            identity=identity,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        self.assertEqual(self.role.get_hierarchy_memberships().count(), 1)

    def test_role_cost(self):
        self.assertEqual(self.parent_role.get_cost(), 5)
        self.assertEqual(self.role.get_cost(), 20)

    def test_role_permissions(self):
        self.assertEqual(self.parent_role.get_permissions().count(), 1)
        self.assertEqual(self.parent_role.get_permissions().first().name(), "Account permission")
        self.assertEqual(self.role.get_permissions().count(), 2)


class RequirementsTests(TestData):
    def setUp(self):
        super().setUp()
        self.date_of_birth = self.role.requirements.create(
            name_en="Date of birth", type="attribute", value="date_of_birth", level=2, grace=0
        )
        self.nda = self.parent_role.requirements.create(name_en="nda", type="contract", value="nda", grace=0)
        self.assurance = self.account_permission.requirements.create(
            name_en="Assurance", type="assurance", level="3", grace=0
        )
        self.email = self.licence_permission.requirements.create(
            name_en="Email", type="attribute", value="email_address", grace=0
        )
        self.identity = Identity.objects.create(given_names="Test User")
        self.membership = Membership.objects.create(
            identity=self.identity,
            role=self.role,
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        self.user = User.objects.create_user(username="testuser")
        self.parent_membership = Membership.objects.create(
            identity=self.identity,
            role=self.parent_role,
            approver=self.user,
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=15),
        )

    def _create_contract(self):
        self.contract_template = ContractTemplate.objects.create(
            type="nda",
            version=1,
            name_en="NDA",
        )
        self.contract = Contract.objects.sign_contract(
            identity=self.identity,
            template=self.contract_template,
        )

    def test_get_requirements(self):
        self.assertEqual(self.role.get_requirements().count(), 4)
        self.assertEqual(self.parent_role.get_requirements().count(), 2)

    def test_contract_version(self):
        self.identity.assurance_level = 3
        self.identity.save()
        self._create_contract()
        self.nda.level = 2
        self.nda.save()
        self.assertFalse(self.parent_membership.test_requirements())
        self.contract_template.save()
        Contract.objects.sign_contract(
            identity=self.identity,
            template=self.contract_template,
        )
        self.assertTrue(self.parent_membership.test_requirements())

    def test_missing_requirements(self):
        self.assertFalse(self.membership.test_requirements())
        self.membership.refresh_from_db()
        self.assertIsNotNone(self.membership.requirements_failed_at)
        self.assertFalse(self.parent_membership.test_requirements())
        self.assertEqual(self.membership.get_missing_requirements().count(), 4)
        self.assertEqual(self.identity.get_missing_requirements().count(), 4)
        self.assertEqual(self.parent_membership.get_missing_requirements().count(), 2)
        email_address = self.identity.email_addresses.create(address="test@example.org")
        self.assertEqual(self.membership.get_missing_requirements().count(), 4)
        email_address.verified = True
        email_address.save()
        self.assertEqual(self.membership.get_missing_requirements().count(), 3)
        self.identity.date_of_birth = timezone.now().date() - datetime.timedelta(days=365 * 18)
        self.identity.save()
        self.assertEqual(self.membership.get_missing_requirements().count(), 3)
        self.identity.date_of_birth_verification = 2
        self.identity.save()
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.get_missing_requirements().count(), 2)
        self._create_contract()
        self.assertEqual(self.membership.get_missing_requirements().count(), 1)
        self.identity.assurance_level = 3
        self.identity.save()
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.get_missing_requirements().count(), 0)
        self.assertEqual(self.identity.get_missing_requirements().count(), 0)
        self.assertTrue(self.membership.test_requirements())
        self.assertIsNone(self.membership.requirements_failed_at)

    def test_missing_requirements_with_grace(self):
        self.assurance.grace = 2
        self.assurance.save()
        self.nda.grace = 1
        self.nda.save()
        self.parent_membership.set_status()
        self.assertEqual(self.parent_membership.status, "require")
        self.parent_membership.status = "active"
        self.parent_membership.requirements_failed_at = timezone.now() - datetime.timedelta(days=1, hours=-1)
        self.parent_membership.set_status()
        self.assertIsNotNone(self.parent_membership.requirements_failed_at)
        self.assertEqual(self.parent_membership.status, "active")
        self.parent_membership.requirements_failed_at = timezone.now() - datetime.timedelta(days=2, hours=-1)
        self.parent_membership.set_status()
        self.assertEqual(self.parent_membership.status, "require")
