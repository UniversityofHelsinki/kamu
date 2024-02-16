"""
View tests for admin site.
"""

import datetime

from django.test import Client, override_settings
from django.utils import timezone

from kamu.models.identity import PhoneNumber
from kamu.models.membership import Membership
from kamu.models.role import Role
from tests.setup import BaseTestCase


class AdminSiteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/admin/kamu/"
        self.client = Client()
        self.client.force_login(user=self.superuser)
        self.role_data = {
            "identifier": "new_role",
            "name_en": "New Role",
            "name_fi": "New Role",
            "name_sv": "New Role",
            "description_en": "New Description",
            "description_fi": "New Description",
            "description_sv": "New Description",
            "organisation_unit": "Test unit",
            "reason": "Testing",
            "maximum_duration": 30,
            "created_at_0": timezone.now().date(),
            "created_at_1": timezone.now().time(),
        }

    def test_view_admin_email_addresses(self):
        response = self.client.get(f"{self.url}emailaddress/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("test@example.org", response.content.decode("utf-8"))

    def test_view_admin_phone_numbers(self):
        PhoneNumber.objects.create(
            identity=self.identity,
            number="+358123456789",
        )
        response = self.client.get(f"{self.url}phonenumber/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("+358123456789", response.content.decode("utf-8"))

    def test_view_admin_identity(self):
        response = self.client.get(f"{self.url}identity/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Me", response.content.decode("utf-8"))

    def test_view_admin_identifier(self):
        response = self.client.get(f"{self.url}identifier/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("0 Identifiers", response.content.decode("utf-8"))

    def test_view_admin_role(self):
        response = self.client.get(f"{self.url}role/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Role", response.content.decode("utf-8"))

    def test_view_admin_membership(self):
        Membership.objects.create(
            role=self.role,
            identity=self.identity,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        response = self.client.get(f"{self.url}membership/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Role", response.content.decode("utf-8"))
        self.assertIn("Test User", response.content.decode("utf-8"))

    def test_view_admin_permission(self):
        response = self.client.get(f"{self.url}permission/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Permission", response.content.decode("utf-8"))

    def test_add_role(self):
        url = f"{self.url}role/add/"
        response = self.client.post(url, self.role_data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("New Role", response.content.decode("utf-8"))
        self.assertTrue(Role.objects.filter(identifier="new_role").exists())

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=3)
    def test_add_role_hierarchy_allowed_depth(self):
        url = f"{self.url}role/add/"
        sub_role = Role.objects.create(identifier="subrole", name_en="Sub Role", maximum_duration=10, parent=self.role)
        self.role_data["parent"] = sub_role.pk
        response = self.client.post(url, self.role_data)
        self.assertNotIn("Role hierarchy cannot be more than maximum depth.", response.content.decode("utf-8"))
        self.assertTrue(Role.objects.filter(identifier="new_role").exists())

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=2)
    def test_add_role_hierarchy_too_deep(self):
        url = f"{self.url}role/add/"
        sub_role = Role.objects.create(identifier="subrole", name_en="Sub Role", maximum_duration=10, parent=self.role)
        self.role_data["parent"] = sub_role.pk
        response = self.client.post(url, self.role_data)
        self.assertIn("Role hierarchy cannot be more than maximum depth", response.content.decode("utf-8"))
        self.assertFalse(Role.objects.filter(identifier="new_role").exists())
