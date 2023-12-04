"""
View tests for identity app.
"""

from unittest import mock

from django.core import mail
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


class ContactTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = f"/identity/{self.identity.pk}/contacts/"
        self.number = PhoneNumber.objects.create(
            identity=self.identity,
            number="+1234567890",
            priority=0,
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_view_contacts(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("+1234567890", response.content.decode("utf-8"))
        self.assertIn("test@example.org", response.content.decode("utf-8"))

    def test_post_new_email_contact(self):
        data = {"contact": "test@example.com"}
        response = self.client.post(self.url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("test@example.org", response.content.decode("utf-8"))
        self.assertIn("test@example.com</th>", response.content.decode("utf-8"))

    def test_post_new_phone_contact(self):
        data = {"contact": "+358123456789"}
        response = self.client.post(self.url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("+1234567890</th>", response.content.decode("utf-8"))

    def test_post_incorrect_contact(self):
        data = {"contact": "incorrect"}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("Invalid e-mail address or phone number", response.content.decode("utf-8"))

    def test_post_contact_over_limit(self):
        data = {"contact": "test@example.com"}
        with self.settings(CONTACT_LIMIT=1):
            response = self.client.post(self.url, data, follow=True)
        self.assertIn("Maximum number of e-mail addresses reached", response.content.decode("utf-8"))

    def test_post_change_priority_up(self):
        new_number = PhoneNumber.objects.create(
            identity=self.identity,
            number="+3580123456789",
            priority=1,
        )
        data = {"phone_up": new_number.pk}
        self.client.post(self.url, data, follow=True)
        new_number.refresh_from_db()
        self.number.refresh_from_db()
        self.assertEqual(new_number.priority, 0)
        self.assertEqual(self.number.priority, 1)

    def test_post_change_priority_down(self):
        new_number = PhoneNumber.objects.create(
            identity=self.identity,
            number="+3580123456789",
            priority=1,
        )
        data = {"phone_down": self.number.pk}
        self.client.post(self.url, data, follow=True)
        new_number.refresh_from_db()
        self.number.refresh_from_db()
        self.assertEqual(new_number.priority, 0)
        self.assertEqual(self.number.priority, 1)

    def test_remove_phone(self):
        data = {"phone_remove": self.number.pk}
        response = self.client.post(self.url, data, follow=True)
        self.assertNotIn("+1234567890", response.content.decode("utf-8"))
        with self.assertRaises(PhoneNumber.DoesNotExist):
            self.number.refresh_from_db()


class VerificationTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = f"/email/{self.email_address.pk}/verify/"
        self.client = Client()
        self.client.force_login(self.user)

    def test_view_verification_page(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Verification code sent", response.content.decode("utf-8"))

    def test_verify_address(self):
        self.client.get(self.url)
        code = mail.outbox[0].body.split(" ")[-1]
        data = {"code": code}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("test@example.org", response.content.decode("utf-8"))
        self.assertIn("Verified", response.content.decode("utf-8"))
        self.email_address.refresh_from_db()
        self.assertTrue(self.email_address.verified)

    def test_verify_address_invalid_address(self):
        data = {"code": "invalid_code"}
        response = self.client.post(self.url, data, follow=True)
        self.assertIn("Invalid verification code", response.content.decode("utf-8"))

    @mock.patch("identity.views.SmsConnector")
    def test_verify_sms(self, mock_connector):
        number = PhoneNumber.objects.create(identity=self.identity, number="+1234567890", priority=0, verified=False)
        mock_connector.return_value.send_sms.return_value = True
        url = f"/phone/{number.pk}/verify/"
        self.client.get(url)
        code = mock_connector.return_value.send_sms.call_args.args[1].split(" ")[-1]
        data = {"code": code}
        self.client.post(url, data, follow=True)
        number.refresh_from_db()
        self.assertTrue(number.verified)


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
