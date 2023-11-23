"""
View tests for identity app.
"""

from django.test import Client

from identity.models import EmailAddress, PhoneNumber
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
        self.assertIn("<h1>Test User</h1>", response.content.decode("utf-8"))

    def test_search_identity(self):
        EmailAddress.objects.create(
            identity=self.superidentity,
            address="super@example.org",
        )
        url = f"{self.url}search/?given_names=test&email=example.org"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Me", response.content.decode("utf-8"))
        self.assertNotIn("Superuser", response.content.decode("utf-8"))


class IdentityEditTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/identity/1/change/"
        self.client = Client()
        self.data = {
            "given_names": self.identity.given_names,
            "surname": self.identity.surname,
            "given_name_display": self.identity.given_name_display,
            "surname_display": self.identity.surname_display,
            "preferred_language": self.identity.preferred_language,
            "date_of_birth": "1999-01-01",
            "gender": self.identity.gender,
            "fpic": self.identity.fpic,
            "nationality": 1,
            "given_names_verification": self.identity.given_names_verification,
            "surname_verification": self.identity.surname_verification,
            "date_of_birth_verification": self.identity.date_of_birth_verification,
            "fpic_verification": self.identity.fpic_verification,
            "nationality_verification": self.identity.nationality_verification,
        }

    def test_edit_own_information_listed_fields(self):
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Basic information", response.content.decode("utf-8"))
        self.assertIn("Restricted information", response.content.decode("utf-8"))
        self.assertNotIn("verification method", response.content.decode("utf-8"))

    def test_edit_own_information_disabled_fields(self):
        self.identity.given_names_verification = 4
        self.identity.save()
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('disabled id="id_given_names"', response.content.decode("utf-8"))

    def test_edit_own_information(self):
        self.client.force_login(self.user)
        response = self.client.post(self.url, self.data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("<h1>Test User</h1>", response.content.decode("utf-8"))
        self.assertIn("Jan. 1, 1999", response.content.decode("utf-8"))

    def test_edit_identity_view_with_superuser(self):
        self.client.force_login(self.superuser)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Restricted information", response.content.decode("utf-8"))
        self.assertIn("verification method", response.content.decode("utf-8"))

    def test_edit_strong_electrical_verification_error(self):
        self.identity.given_names_verification = 4
        self.identity.save()
        self.data["given_names"] = "New Name"
        self.data["given_names_verification"] = 4
        self.client.force_login(self.superuser)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Cannot set strong electrical verification by hand", response.content.decode("utf-8"))

    def test_edit_other_user(self):
        self.identity.given_names_verification = 4
        self.identity.save()
        self.data["given_names"] = "New Name"
        self.data["given_names_verification"] = 3
        self.client.force_login(self.superuser)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, 302)


class AdminSiteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/admin/identity/"
        self.client = Client()
        self.client.force_login(user=self.superuser)

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
