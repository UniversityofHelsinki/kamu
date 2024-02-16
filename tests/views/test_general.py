"""
Tests for general views.
"""

import datetime

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from kamu.models.membership import Membership
from kamu.utils.auth import set_default_permissions
from tests.setup import BaseTestCase

UserModel = get_user_model()


class FrontPageViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = reverse("front-page")

    def test_front_page_view(self):
        response = self.client.get(self.url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("register here", response.content.decode("utf-8"))

    def test_front_page_view_logged_in(self):
        self.client.force_login(self.user)
        response = self.client.get(self.url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Manage your own information", response.content.decode("utf-8"))

    def test_front_page_view_logged_in_with_role_permissions(self):
        self.client.force_login(self.user)
        set_default_permissions(self.user)
        response = self.client.get(self.url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Manage your own information", response.content.decode("utf-8"))
        self.assertIn("Role and membership management", response.content.decode("utf-8"))

    def test_front_page_view_logged_in_with_messages(self):
        self.client.force_login(self.superuser)
        Membership.objects.create(
            role=self.role,
            reason="Test",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=7),
        )
        response = self.client.get(self.url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("You have pending membership approvals", response.content.decode("utf-8"))
        self.assertIn(
            "Memberships are ending soon in roles you have approval rights", response.content.decode("utf-8")
        )

    @override_settings(EXPIRING_LIMIT_DAYS=6)
    def test_front_page_view_logged_in_without_messages(self):
        self.client.force_login(self.superuser)
        Membership.objects.create(
            role=self.role,
            reason="Test",
            approver=self.superuser,
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=7),
        )
        response = self.client.get(self.url, follow=True)
        self.assertNotIn("You have pending membership approvals", response.content.decode("utf-8"))
        self.assertNotIn(
            "Memberships are ending soon in roles you have approval rights", response.content.decode("utf-8")
        )


class ErrorViewTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_permission_denied_view(self):
        response = self.client.get(reverse("login-register-email-verify"))
        self.assertContains(response, "Permission denied", status_code=403)

    def test_page_not_found_view(self):
        response = self.client.get("/page_not_found")
        self.assertContains(response, "Page not found", status_code=404)
