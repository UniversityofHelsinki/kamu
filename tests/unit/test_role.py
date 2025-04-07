"""
Unit tests for roles.
"""

import datetime

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory, override_settings
from django.utils import timezone

from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import Identity
from kamu.models.membership import Membership
from kamu.models.role import Permission, Requirement
from kamu.utils.membership import add_missing_requirement_messages
from tests.data import ROLES
from tests.setup import BaseTestCase

User = get_user_model()


class BaseRoleTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.parent_role = self.create_role()
        self.role = self.create_role("consultant", parent=self.parent_role)
        self.account_permission = self.create_permission("lightaccount")
        self.service_permission = self.create_permission("service")
        self.parent_role.permissions.add(self.account_permission)
        self.role.permissions.add(self.service_permission)


class RoleModelTests(BaseRoleTestCase):

    def test_role_name(self):
        self.assertEqual(self.role.name(), ROLES["consultant"]["name_en"])

    def test_role_description(self):
        self.assertEqual(self.role.description(lang="fi"), ROLES["consultant"]["description_fi"])

    def test_role_hierarchy(self):
        self.assertEqual(self.parent_role.get_role_hierarchy().count(), 1)
        self.assertEqual(self.role.get_role_hierarchy().count(), 2)

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=1)
    def test_role_hierarchy_limit(self):
        self.assertEqual(self.role.get_role_hierarchy().count(), 1)

    def test_role_hierarchy_memberships(self):
        identity = self.create_identity(user=False)
        self.create_membership(self.parent_role, identity, start_delta_days=0, expire_delta_days=1)
        self.assertEqual(self.role.get_hierarchy_memberships().count(), 1)

    def test_role_cost(self):
        self.assertEqual(self.parent_role.get_cost(), 5)
        self.assertEqual(self.role.get_cost(), 7)

    def test_role_permissions(self):
        self.assertEqual(self.parent_role.get_permissions().count(), 1)
        self.assertEqual(self.parent_role.get_permissions().first().name(), "Lightaccount")
        self.assertEqual(self.role.get_permissions().count(), 2)


class PermissionTests(BaseRoleTestCase):
    def setUp(self):
        super().setUp()
        self.identity = self.create_identity(user=True)
        self.membership = self.create_membership(
            self.role, self.identity, start_delta_days=-2, expire_delta_days=1, approver=self.identity.user
        )

    def test_get_permissions(self):
        self.assertEqual(self.role.get_permissions().count(), 2)
        self.assertEqual(self.identity.get_permissions().count(), 2)
        self.assertEqual(self.identity.get_permissions(permission_type=Permission.Type.ACCOUNT).count(), 1)

    def test_get_permissions_expired(self):
        self.membership.expire_date = timezone.now().date() - datetime.timedelta(days=1)
        self.membership.save()
        self.assertEqual(self.role.get_permissions().count(), 2)
        self.assertEqual(self.identity.get_permissions().count(), 0)


class RequirementsTests(BaseRoleTestCase):
    def setUp(self):
        super().setUp()
        self.date_of_birth = self.role.requirements.create(
            name_en="Date of birth",
            type=Requirement.Type.ATTRIBUTE,
            value="date_of_birth",
            level=Identity.VerificationMethod.EXTERNAL,
            grace=0,
        )
        self.nda = self.parent_role.requirements.create(
            name_en="nda", type=Requirement.Type.CONTRACT, value="nda", grace=0
        )
        self.assurance = self.account_permission.requirements.create(
            name_en="Assurance", type=Requirement.Type.ASSURANCE, level=Identity.AssuranceLevel.HIGH, grace=0
        )
        self.email = self.service_permission.requirements.create(
            name_en="Email", type=Requirement.Type.ATTRIBUTE, value="email_address", grace=0
        )
        self.identity = self.create_identity(user=True)
        self.membership = self.create_membership(self.role, self.identity, start_delta_days=-2, expire_delta_days=1)
        self.parent_membership = self.create_membership(
            self.parent_role, self.identity, start_delta_days=0, expire_delta_days=15, approver=self.user
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
        self.assertEqual(self.identity.get_requirements().count(), 4)

    def test_get_requirements_ignore_expired(self):
        self.membership.expire_date = timezone.now().date() - datetime.timedelta(days=1)
        self.membership.save()
        self.assertEqual(self.identity.get_requirements().count(), 2)

    def test_contract_version(self):
        self.identity.assurance_level = Identity.AssuranceLevel.HIGH
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
        self.identity.date_of_birth_verification = Identity.VerificationMethod.EXTERNAL
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
        self.assertEqual(self.parent_membership.status, Membership.Status.REQUIRE)
        self.parent_membership.status = Membership.Status.ACTIVE
        self.parent_membership.requirements_failed_at = timezone.now() - datetime.timedelta(days=1, hours=-1)
        self.parent_membership.set_status()
        self.assertIsNotNone(self.parent_membership.requirements_failed_at)
        self.assertEqual(self.parent_membership.status, Membership.Status.ACTIVE)
        self.parent_membership.requirements_failed_at = timezone.now() - datetime.timedelta(days=2, hours=-1)
        self.parent_membership.set_status()
        self.assertEqual(self.parent_membership.status, Membership.Status.REQUIRE)

    def test_message_generation(self):
        factory = RequestFactory()
        request = factory.get("/")
        request.user = AnonymousUser()
        setattr(request, "session", "session")
        messages = FallbackStorage(request)
        setattr(request, "_messages", messages)
        missing = self.membership.get_missing_requirements()
        add_missing_requirement_messages(request, missing, self.identity)
        self.assertEqual(
            f"Role requires higher assurance level: {Identity.AssuranceLevel.HIGH} "
            "(High, eIDAS substantial level or similar).",
            messages._queued_messages[0].message,
        )
        self.assertEqual(
            'Role requires an attribute "date of birth" of at least verification level: '
            f"{Identity.VerificationMethod.EXTERNAL} (External source).",
            messages._queued_messages[1].message,
        )
        self.assertNotIn(
            "Add here",
            messages._queued_messages[1].message,
        )
        self.assertIn(
            "Role requires a verified email address.",
            messages._queued_messages[2].message,
        )
        self.assertEqual(
            "Role requires a contract you cannot currently sign.",
            messages._queued_messages[3].message,
        )

    def test_message_generation_with_user(self):
        template = ContractTemplate.objects.create(type="nda", name_en="NDA")
        template.save()
        self.nda.level = 2
        self.nda.save()
        factory = RequestFactory()
        request = factory.get("/")
        self.identity.user = self.user
        self.identity.save()
        request.user = self.user
        setattr(request, "session", "session")
        messages = FallbackStorage(request)
        setattr(request, "_messages", messages)
        missing = self.membership.get_missing_requirements()
        add_missing_requirement_messages(request, missing, self.identity)
        self.assertIn(
            "Add here",
            messages._queued_messages[2].message,
        )
        self.assertIn(
            'Role requires a contract "NDA", version 2 or higher.',
            messages._queued_messages[3].message,
        )
