"""
View tests for admin site.
"""

import datetime
from unittest.mock import ANY, call, patch

from django.contrib.auth.models import Group
from django.test import Client, override_settings
from django.utils import timezone

from kamu.models.identity import Identifier, PhoneNumber
from kamu.models.membership import Membership
from kamu.models.organisation import Organisation
from kamu.models.role import Role
from tests.data import ORGANISATIONS, ROLES
from tests.setup import BaseTestCase


class AdminSiteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_superidentity(user=True, email=True, phone=True)
        self.url = "/admin/kamu/"
        self.client = Client()
        self.client.force_login(user=self.superuser)
        self.created_at = {"created_at_0": timezone.now().date(), "created_at_1": timezone.now().time()}

    @patch("kamu.utils.audit.logger_audit.log")
    def test_view_admin_email_addresses(self, mock_audit_logger):
        response = self.client.get(f"{self.url}emailaddress/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("super_test@example.org", response.content.decode("utf-8"))
        mock_audit_logger.assert_has_calls([call(20, "Admin: Listed email_address", extra=ANY)])

    def test_view_admin_phone_numbers(self):
        response = self.client.get(f"{self.url}phonenumber/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("+1234000000", response.content.decode("utf-8"))

    def test_view_admin_identities(self):
        response = self.client.get(f"{self.url}identity/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Dr. Super", response.content.decode("utf-8"))

    @patch("kamu.utils.audit.logger_audit.log")
    def test_view_admin_identity(self, mock_audit_logger):
        response = self.client.get(f"{self.url}identity/{self.superidentity.pk}/change/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Dr. Super", response.content.decode("utf-8"))
        mock_audit_logger.assert_has_calls([call(20, "Admin: Read identity information", extra=ANY)])

    def test_view_admin_identifier(self):
        response = self.client.get(f"{self.url}identifier/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("0 Identifiers", response.content.decode("utf-8"))

    def test_view_admin_role(self):
        self.role = self.create_role()
        response = self.client.get(f"{self.url}role/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.role.name(), response.content.decode("utf-8"))

    def test_view_admin_membership(self):
        self.role = self.create_role()
        self.create_identity()
        Membership.objects.create(
            role=self.role,
            identity=self.identity,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        response = self.client.get(f"{self.url}membership/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.role.name(), response.content.decode("utf-8"))
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))

    def test_view_admin_permission(self):
        permission = self.create_permission()
        response = self.client.get(f"{self.url}permission/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(permission.name(), response.content.decode("utf-8"))

    def test_group_add_has_no_permissions(self):
        response = self.client.get("/admin/auth/group/add/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Can add group", response.content.decode("utf-8"))

    def test_group_edit_has_permissions(self):
        group = Group.objects.create(name="test")
        response = self.client.get(f"/admin/auth/group/{group.pk}/change/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Can add group", response.content.decode("utf-8"))

    def _test_add_phone_number(self, number: str):
        url = f"{self.url}phonenumber/add/"
        identity = self.create_identity()
        form_data = {
            "identity": identity.pk,
            "number": number,
            "priority": 1,
            "verified": False,
        }
        form_data.update(self.created_at)
        return self.client.post(url, form_data, follow=True)

    def test_add_invalid_phone_number(self):
        response = self._test_add_phone_number("050123456")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Phone number must start with a plus sign", response.content.decode("utf-8"))

    def test_add_phone_number(self):
        response = self._test_add_phone_number("+35850123456")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(PhoneNumber.objects.filter(number="+35850123456").exists())

    def _test_add_identifier(self, identifier_type: str, identifier_value: str):
        url = f"{self.url}identifier/add/"
        identity = self.create_identity()
        form_data = {
            "identity": identity.pk,
            "type": identifier_type,
            "value": identifier_value,
            "verified": False,
        }
        form_data.update(self.created_at)
        return self.client.post(url, form_data, follow=True)

    def test_add_invalid_eppn_identifier(self):
        response = self._test_add_identifier("eppn", "eppn")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid eduPersonPrincipalName format", response.content.decode("utf-8"))

    def test_add_eppn_identifier(self):
        response = self._test_add_identifier("eppn", "test@example.org")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Identifier.objects.filter(type="eppn", value="test@example.org").exists())

    @patch("kamu.utils.audit.logger_audit.log")
    def test_add_role(self, mock_audit_logger):
        url = f"{self.url}role/add/"
        role_data = ROLES["guest_student"]
        role_data.pop("organisation")
        role_data.update(self.created_at)
        response = self.client.post(url, role_data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(role_data["name_en"], response.content.decode("utf-8"))
        self.assertTrue(Role.objects.filter(identifier=role_data["identifier"]).exists())
        mock_audit_logger.assert_has_calls(
            [
                call(
                    20,
                    "Admin: Created role",
                    extra={
                        "category": "role",
                        "action": "create",
                        "outcome": "success",
                        "ip": ANY,
                        "user_agent": ANY,
                        "role_id": 1,
                        "role": "guest_student",
                        "actor": "superuser",
                        "actor_id": 1,
                    },
                ),
                call(20, "Admin: Listed role", extra=ANY),
            ]
        )

    @patch("kamu.utils.audit.logger_audit.log")
    def test_admin_logging_modify(self, mock_audit_logger):
        self.create_identity(email=True)
        url = f"{self.url}emailaddress/{self.email_address.pk}/change/"
        form_data = {
            "identity": self.identity.pk,
            "address": "modified@example.org",
            "priority": 1,
            "verified": False,
        }
        form_data.update(self.created_at)
        self.client.post(url, form_data, follow=True)
        mock_audit_logger.assert_has_calls(
            [
                call(
                    20,
                    "Admin: Updated email_address",
                    extra={
                        "category": "email_address",
                        "action": "update",
                        "outcome": "success",
                        "ip": ANY,
                        "user_agent": ANY,
                        "actor": "superuser",
                        "actor_id": 1,
                        "email_address_id": self.email_address.pk,
                        "email_address": "modified@example.org",
                        "identity_id": self.identity.pk,
                        "identity": ANY,
                    },
                ),
            ]
        )

    @patch("kamu.utils.audit.logger_audit.log")
    def test_admin_logging_delete(self, mock_audit_logger):
        self.create_identity(email=True)
        url = f"{self.url}emailaddress/{self.email_address.pk}/delete/"
        form_data = {"post": "yes"}
        self.client.post(url, form_data, follow=True)
        mock_audit_logger.assert_has_calls(
            [
                call(
                    20,
                    "Admin: Will delete email_address",
                    extra={
                        "category": "email_address",
                        "action": "delete",
                        "outcome": "success",
                        "ip": ANY,
                        "user_agent": ANY,
                        "actor": "superuser",
                        "actor_id": 1,
                        "email_address_id": self.email_address.pk,
                        "email_address": "test@example.org",
                        "identity_id": self.identity.pk,
                        "identity": ANY,
                    },
                ),
            ]
        )

    def _create_role_hierarchy(self):
        role = self.create_role()
        sub_role = self.create_role("consultant", parent=role)
        role_data = ROLES["guest_student"]
        role_data.pop("organisation", None)
        role_data.update(
            {"created_at_0": timezone.now().date(), "created_at_1": timezone.now().time(), "parent": sub_role.pk}
        )
        return role_data

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=3)
    def test_add_role_hierarchy_allowed_depth(self):
        url = f"{self.url}role/add/"
        role_data = self._create_role_hierarchy()
        response = self.client.post(url, role_data)
        self.assertNotIn("Role hierarchy cannot be more than maximum depth.", response.content.decode("utf-8"))
        self.assertTrue(Role.objects.filter(identifier=ROLES["guest_student"]["identifier"]).exists())

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=2)
    def test_add_role_hierarchy_too_deep(self):
        url = f"{self.url}role/add/"
        role_data = self._create_role_hierarchy()
        response = self.client.post(url, role_data)
        self.assertIn("Role hierarchy cannot be more than maximum depth", response.content.decode("utf-8"))
        self.assertFalse(Role.objects.filter(identifier=ROLES["guest_student"]["identifier"]).exists())

    def _create_organisation_hierarchy(self):
        organisation = self.create_organisation()
        organisation_data = ORGANISATIONS["research"]
        organisation_data.pop("parent", None)
        organisation_data.update(
            {"created_at_0": timezone.now().date(), "created_at_1": timezone.now().time(), "parent": organisation.pk}
        )
        return organisation_data

    @override_settings(ORGANISATION_HIERARCHY_MAXIMUM_DEPTH=2)
    def test_add_organisation_hierarchy_allowed_depth(self):
        url = f"{self.url}organisation/add/"
        organisation_data = self._create_organisation_hierarchy()
        response = self.client.post(url, organisation_data)
        self.assertNotIn("Organisation hierarchy cannot be more than maximum depth.", response.content.decode("utf-8"))
        self.assertTrue(Organisation.objects.filter(identifier=ORGANISATIONS["research"]["identifier"]).exists())

    @override_settings(ORGANISATION_HIERARCHY_MAXIMUM_DEPTH=1)
    def test_add_organisation_hierarchy_too_deep(self):
        url = f"{self.url}organisation/add/"
        organisation_data = self._create_organisation_hierarchy()
        response = self.client.post(url, organisation_data)
        self.assertIn("Organisation hierarchy cannot be deeper than maximum depth", response.content.decode("utf-8"))
        self.assertFalse(Organisation.objects.filter(identifier=ORGANISATIONS["research"]["identifier"]).exists())
