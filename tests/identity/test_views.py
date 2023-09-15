from django.contrib.auth.models import User
from django.test import Client, RequestFactory, TestCase

from identity.models import Identity


class IdentityTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username="testuser", first_name="Test", last_name="User", password="test_pass"
        )
        self.url = "/identity/"

    def test_anonymous_view_redirects_to_login(self):
        client = Client()
        response = client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["location"])

    def test_view_identity_without_identity(self):
        client = Client()
        client.force_login(self.user)
        response = client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("New identity created.", response.content.decode("utf-8"))

    def test_view_identity(self):
        Identity.objects.create(user=self.user)
        client = Client()
        client.force_login(self.user)
        response = client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("alert", response.content.decode("utf-8"))
        self.assertIn("Name: Test User", response.content.decode("utf-8"))
