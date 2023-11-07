from django.contrib.auth.models import User
from django.test import Client, RequestFactory, TestCase

from identity.models import Identity
from tests.setup import BaseTestCase


class IdentityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/identity/"
        self.client = Client()
        self.client.force_login(self.user)

    def test_anonymous_view_redirects_to_login(self):
        client = Client()
        response = client.get(f"{self.url}1/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["location"])

    def test_view_identity_without_identity(self):
        self.identity.delete()
        response = self.client.get(f"{self.url}me/", follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("New identity created.", response.content.decode("utf-8"))

    def test_view_identity(self):
        response = self.client.get(f"{self.url}{self.identity.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("alert", response.content.decode("utf-8"))
        self.assertIn("Identity: Test User", response.content.decode("utf-8"))

    def test_search_identity(self):
        url = f"{self.url}search/?first_name=nick&email=example.org"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User", response.content.decode("utf-8"))
        self.assertNotIn("Superuser", response.content.decode("utf-8"))


class AdminSiteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/admin/identity/"
        self.client = Client()
        self.client.force_login(user=self.superuser)

    def test_view_admin_attributetype(self):
        response = self.client.get(f"{self.url}attributetype/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("First name", response.content.decode("utf-8"))

    def test_view_admin_attribute(self):
        response = self.client.get(f"{self.url}attribute/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("First name", response.content.decode("utf-8"))
        self.assertIn("Test User", response.content.decode("utf-8"))

    def test_view_admin_identity(self):
        response = self.client.get(f"{self.url}identity/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User", response.content.decode("utf-8"))

    def test_view_admin_identifier(self):
        response = self.client.get(f"{self.url}identifier/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("0 Identifiers", response.content.decode("utf-8"))
