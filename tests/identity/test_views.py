from django.contrib.auth.models import User
from django.test import Client, RequestFactory, TestCase

from identity.models import Identity
from tests.setup import BaseTestCase


class IdentityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/identity/"

    def test_anonymous_view_redirects_to_login(self):
        client = Client()
        response = client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["location"])

    def test_view_identity_without_identity(self):
        client = Client()
        self.identity.delete()
        client.force_login(self.user)
        response = client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("New identity created.", response.content.decode("utf-8"))

    def test_view_identity(self):
        client = Client()
        client.force_login(self.user)
        response = client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("alert", response.content.decode("utf-8"))
        self.assertIn("Name: Test User", response.content.decode("utf-8"))


class AdminSiteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/admin/identity/"
        self.client = Client()
        self.client.force_login(user=self.superuser)

    def test_view_admin_attributetype(self):
        response = self.client.get(f"{self.url}attributetype/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Attribute", response.content.decode("utf-8"))

    def test_view_admin_attribute(self):
        response = self.client.get(f"{self.url}attribute/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Attribute", response.content.decode("utf-8"))
        self.assertIn("Test User", response.content.decode("utf-8"))

    def test_view_admin_identity(self):
        response = self.client.get(f"{self.url}identity/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User", response.content.decode("utf-8"))

    def test_view_admin_identifier(self):
        response = self.client.get(f"{self.url}identifier/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("0 Identifiers", response.content.decode("utf-8"))
