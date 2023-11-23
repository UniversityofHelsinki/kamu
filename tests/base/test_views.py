"""
Tests for base views.
"""

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse

from identity.models import PhoneNumber
from tests.setup import BaseTestCase

UserModel = get_user_model()


class LoginViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()

    def test_local_login(self):
        url = reverse("login-local") + "?next=/identity/1/"
        response = self.client.post(
            url,
            {"username": "testuser", "password": "test_pass"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("<h1>Test User</h1>", response.content.decode("utf-8"))

    @override_settings(SAML_ATTR_USERNAME="HTTP_EPPN")
    def test_shibboleth_login(self):
        url = reverse("login-shibboleth")
        response = self.client.get(url, follow=True, headers={"EPPN": "newuser@example.org"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(UserModel.objects.filter(username="newuser@example.org").count(), 1)

    def test_email_login(self):
        phone_number = PhoneNumber.objects.create(identity=self.identity, number="+123456789", verified=True)
        self.email_address.verified = True
        self.email_address.save()
        url = reverse("login-email") + "?next=/identity/me/"
        response = self.client.post(
            url,
            {"email": self.email_address.address, "phone": phone_number.number},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("<h1>Test User</h1>", response.content.decode("utf-8"))
