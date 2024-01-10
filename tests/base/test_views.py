"""
Tests for base views.
"""
import datetime
from unittest import mock

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from base.models import Token
from identity.models import Identifier, Identity, PhoneNumber
from role.models import Membership, Role
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
        self.assertIn("Test User</h1>", response.content.decode("utf-8"))

    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    def test_shibboleth_login(self):
        url = reverse("login-shibboleth")
        response = self.client.get(url, follow=True, headers={"EPPN": "newuser@example.org"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(UserModel.objects.filter(username="newuser@example.org").count(), 1)

    @override_settings(OIDC_CLAIM_SUB="HTTP_SUB")
    def test_google_login(self):
        url = reverse("login-google")
        Identifier.objects.create(type="google", value="1234567890", identity=self.identity)
        response = self.client.get(f"{url}?next=/identity/me", follow=True, headers={"SUB": "1234567890"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User</h1>", response.content.decode("utf-8"))

    @override_settings(OIDC_CLAIM_SUB="HTTP_SUB")
    def test_google_login_without_account(self):
        url = reverse("login-google")
        response = self.client.get(url, follow=True, headers={"SUB": "1234567890"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login failed", response.content.decode("utf-8"))

    @override_settings(OIDC_MICROSOFT_IDENTIFIER="HTTP_OID")
    @override_settings(OIDC_MICROSOFT_ISSUER="HTTP_ISS")
    def _test_microsoft_login(self, iss, oid):
        url = reverse("login-microsoft")
        Identifier.objects.create(type="microsoft", value=oid, identity=self.identity)
        response = self.client.get(
            f"{url}?next=/identity/me",
            follow=True,
            headers={"OID": oid, "ISS": iss},
        )
        return response

    def test_microsoft_login(self):
        oid = "00000000-0000-0000-0123-456789abcdef"
        iss = "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0"
        response = self._test_microsoft_login(iss, oid)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User</h1>", response.content.decode("utf-8"))

    def test_microsoft_login_with_incorrect_issuer(self):
        oid = "00000000-0000-0000-0123-456789abcdef"
        iss = "https://login.example.org/"
        response = self._test_microsoft_login(iss, oid)
        self.assertIn("Login failed", response.content.decode("utf-8"))

    @override_settings(SMS_DEBUG=True)
    @mock.patch("base.connectors.sms.logger")
    def test_email_login(self, mock_logger):
        phone_number = PhoneNumber.objects.create(identity=self.identity, number="+123456789", verified=True)
        self.email_address.verified = True
        self.email_address.save()
        url = reverse("login-email") + "?next=/identity/me/"
        response = self.client.post(
            url,
            {"email_address": self.email_address.address, "phone_number": phone_number.number},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login verification", response.content.decode("utf-8"))
        self.assertEqual("Kamu login verification", mail.outbox[0].subject)
        mock_logger.debug.assert_called_once()

    def test_email_login_duplicate_number(self):
        phone_number = PhoneNumber.objects.create(identity=self.identity, number="+123456789", verified=True)
        PhoneNumber.objects.create(identity=self.superidentity, number="+123456789", verified=True)
        self.email_address.verified = True
        self.email_address.save()
        url = reverse("login-email") + "?next=/identity/me/"
        response = self.client.post(
            url,
            {"email_address": self.email_address.address, "phone_number": phone_number.number},
            follow=True,
        )
        self.assertIn("This contact information cannot be used to login", response.content.decode("utf-8"))

    def _test_email_login_verification(self):
        self.url = reverse("login-email-verify") + "?next=/identity/me/"
        phone_number = PhoneNumber.objects.create(identity=self.identity, number="+123456789", verified=True)
        self.email_address.verified = True
        self.email_address.save()
        self.session = self.client.session
        self.session["login_email_address"] = self.email_address.address
        self.session["login_phone_number"] = phone_number.number
        self.session.save()
        email_secret = Token.objects.create_email_object_verification_token(self.email_address)
        phone_secret = Token.objects.create_phone_object_verification_token(phone_number)
        return email_secret, phone_secret

    def test_email_login_verification(self):
        email_secret, phone_secret = self._test_email_login_verification()
        response = self.client.post(
            self.url,
            {"email_verification_token": email_secret, "phone_verification_token": phone_secret},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User</h1>", response.content.decode("utf-8"))

    def test_email_login_verification_incorrect_token(self):
        email_secret, phone_secret = self._test_email_login_verification()
        response = self.client.post(
            self.url,
            {"email_verification_token": email_secret, "phone_verification_token": phone_secret + "a"},
            follow=True,
        )
        self.assertIn("Invalid verification code", response.content.decode("utf-8"))

    def test_email_login_verification_incorrect_user(self):
        email_secret, phone_secret = self._test_email_login_verification()
        self.email_address.identity = self.superidentity
        self.email_address.save()
        response = self.client.post(
            self.url,
            {"email_verification_token": email_secret, "phone_verification_token": phone_secret},
            follow=True,
        )
        self.assertIn("Error when logging in, please try again", response.content.decode("utf-8"))

    @override_settings(TOKEN_TIME_LIMIT_NEW=0)
    @override_settings(SMS_DEBUG=True)
    @mock.patch("base.connectors.sms.logger")
    def test_email_login_resend_phone_token(self, mock_logger):
        self._test_email_login_verification()
        self.client.post(
            self.url,
            {"resend_phone_code": True},
            follow=True,
        )
        mock_logger.debug.assert_called_once()

    @override_settings(TOKEN_TIME_LIMIT_NEW=0)
    def test_email_login_resend_email_token(self):
        self._test_email_login_verification()
        self.client.post(
            self.url,
            {"resend_email_code": True},
            follow=True,
        )
        self.assertEqual("Kamu login verification", mail.outbox[0].subject)

    @override_settings(TOKEN_TIME_LIMIT_NEW=60)
    def test_email_login_resend_email_token(self):
        self._test_email_login_verification()
        response = self.client.post(
            self.url,
            {"resend_email_code": True},
            follow=True,
        )
        self.assertIn("Tried to send a new code too soon", response.content.decode("utf-8"))
        self.assertEqual(0, len(mail.outbox))


class RegistrationViewTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        user = get_user_model()
        self.user = user.objects.create_user(username="testuser", password="test_pass")
        self.role = Role.objects.create(identifier="testrole", name_en="Test Role", maximum_duration=10)
        self.membership = Membership.objects.create(
            role=self.role,
            reason="Test",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=7),
        )
        self.secret = Token.objects.create_invite_token(self.membership)
        self.client = Client()
        self.session = self.client.session
        self.session["invitation_code"] = self.secret
        self.session["invitation_code_time"] = timezone.now().isoformat()
        self.session.save()

    def test_claim_membership_without_code(self):
        del self.session["invitation_code"]
        self.session.save()
        self.client.force_login(self.user)
        url = reverse("membership-claim")
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertIsNone(self.membership.identity)

    def test_claim_membership_without_code_time(self):
        del self.session["invitation_code_time"]
        self.session.save()
        self.client.force_login(self.user)
        url = reverse("membership-claim")
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertIsNone(self.membership.identity)

    def test_claim_membership_with_invalid_code_time(self):
        self.session["invitation_code_time"] += "x"
        self.session.save()
        self.client.force_login(self.user)
        url = reverse("membership-claim")
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertIsNone(self.membership.identity)

    def test_claim_membership(self):
        self.client.force_login(self.user)
        url = reverse("membership-claim")
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.membership.refresh_from_db()
        self.assertIsNotNone(self.membership.identity)
        self.assertEqual(self.membership.identity, self.user.identity)

    def test_claim_membership_with_expired_code_time(self):
        self.session["invitation_code_time"] = (timezone.now() - datetime.timedelta(seconds=600)).isoformat()
        self.session.save()
        self.client.force_login(self.user)
        url = reverse("membership-claim")
        with self.settings(INVITATION_PROCESS_TIME=500):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.membership.refresh_from_db()
        self.assertIsNone(self.membership.identity)
        self.assertEqual(response.url, reverse("front-page"))

    def test_invite_view(self):
        self.client.force_login(self.user)
        url = reverse("login-invite")
        response = self.client.post(url, data={"code": self.secret, "register": True})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("login-register"))

    def test_fill_registration_form(self):
        url = reverse("login-register")
        response = self.client.post(
            url,
            data={"email_address": "tester@example.org", "given_names": "Test Te", "surname": "Tester"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Your verification code is", mail.outbox[0].body)

    def test_verify_email_address(self):
        url = reverse("login-register-email-verify")
        email_address = "tester@example.org"
        self.session["register_email_address"] = email_address
        self.session.save()
        secret = Token.objects.create_email_address_verification_token(email_address)
        response = self.client.post(url, data={"code": secret})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("login-register-phone"))

    def test_registration_phone_number_without_verified_email(self):
        url = reverse("login-register-phone")
        response = self.client.post(url, data={"phone_number": "+123456789"}, follow=True)
        self.assertEqual(response.status_code, 403)

    @mock.patch("base.views.SmsConnector")
    def test_registration_phone_number(self, mock_connector):
        mock_connector.return_value.send_sms.return_value = True
        url = reverse("login-register-phone")
        self.session["verified_email_address"] = "tester@example.org"
        self.session.save()
        response = self.client.post(url, data={"phone_number": "+123456789"})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Token.objects.filter(phone_number="+123456789").exists())
        self.assertEqual(response.url, reverse("login-register-phone-verify"))

    def test_verify_phone_number_and_create_identity_and_user(self):
        url = reverse("login-register-phone-verify")
        phone_number = "+123456789"
        self.session["verified_email_address"] = "tester@example.org"
        self.session["register_phone_number"] = phone_number
        self.session["register_given_names"] = "New"
        self.session["register_surname"] = "User"
        self.session.save()
        secret = Token.objects.create_phone_number_verification_token(phone_number)
        response = self.client.post(url, data={"code": secret})
        identity = Identity.objects.filter(given_names="New", surname="User").first()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(hasattr(identity, "user"))
        self.assertEqual(response.url, reverse("identity-detail", kwargs={"pk": identity.pk}))

    @override_settings(OIDC_CLAIM_SUB="HTTP_SUB")
    def test_register_with_external_account(self):
        url = reverse("login-google") + "?next=" + reverse("membership-claim")
        response = self.client.get(url, follow=True, headers={"SUB": "1234567890"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Membership created", response.content.decode("utf-8"))


class ErrorViewTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_permission_denied_view(self):
        response = self.client.get(reverse("login-register-email-verify"))
        self.assertContains(response, "Permission denied", status_code=403)

    def test_page_not_found_view(self):
        response = self.client.get("/page_not_found")
        self.assertContains(response, "Page not found", status_code=404)
