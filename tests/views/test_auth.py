"""
Tests for login, logout and registration views.
"""

import datetime
from unittest import mock
from unittest.mock import ANY, call
from urllib.parse import unquote_plus

from django.contrib.admin.models import LogEntry
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone

from kamu.models.identity import Identifier, Identity, PhoneNumber
from kamu.models.membership import Membership
from kamu.models.token import Token
from tests.data import USERS
from tests.setup import BaseTestCase

UserModel = get_user_model()


class LoginViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.user_data = USERS["user"]
        self.superuser_data = USERS["superuser"]
        self.create_identity(user=True, email=True, phone=True)

    def test_redirect_admin_site_to_login(self):
        url = reverse("admin:login")
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login with the University", response.content.decode("utf-8"))

    def test_login_view(self):
        url = reverse("login")
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login with the University", response.content.decode("utf-8"))
        self.assertIn("Haka federation login", response.content.decode("utf-8"))
        self.assertIn("Login with a username and password", response.content.decode("utf-8"))

    @override_settings(AUTHENTICATION_BACKENDS=["kamu.backends.ShibbolethLocalBackend"])
    def test_login_view_disable_methods(self):
        url = reverse("login")
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login with the University", response.content.decode("utf-8"))
        self.assertNotIn("Haka federation login", response.content.decode("utf-8"))
        self.assertNotIn("Login with a username and password", response.content.decode("utf-8"))

    def test_local_login(self):
        url = reverse("login-local") + "?next=/identity/1/"
        response = self.client.post(
            url,
            {"username": self.user_data["username"], "password": self.user_data["password"]},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"{self.identity.display_name()} |", response.content.decode("utf-8"))

    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    def test_shibboleth_local_login(self):
        Identifier.objects.create(type=Identifier.Type.EPPN, value="testuser@example.org", identity=self.identity)
        url = reverse("login-shibboleth")
        response = self.client.get(url, follow=True, headers={"EPPN": "testuser@example.org"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.user.is_authenticated)
        self.assertEqual(self.user.user_permissions.count(), 0)
        self.assertEqual(self.client.session.get("login_backends"), "kamu.backends.ShibbolethLocalBackend;")

    @override_settings(AUTHENTICATION_BACKENDS=["kamu.backends.ShibbolethLocalBackend"])
    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    def test_shibboleth_local_login_with_owner_permissions(self):
        role = self.create_role()
        role.owner = self.user
        role.save()
        Identifier.objects.create(type=Identifier.Type.EPPN, value="testuser@example.org", identity=self.identity)
        url = reverse("login-shibboleth")
        self.client.get(url, follow=True, headers={"EPPN": "testuser@example.org"})
        self.assertEqual(self.user.user_permissions.count(), 2)
        self.assertTrue(self.user.has_perm("kamu.search_roles"))

    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    def test_shibboleth_local_login_create_user(self):
        url = reverse("login-shibboleth")
        response = self.client.get(url, follow=True, headers={"EPPN": "newuser@example.org"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(UserModel.objects.filter(username="newuser@example.org").count(), 1)

    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    def test_shibboleth_remote_login_no_user(self):
        url = reverse("login-haka")
        response = self.client.get(url, follow=True, headers={"EPPN": "newuser@example.org"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login failed", response.content.decode("utf-8"))
        self.assertFalse(Identifier.objects.filter(value="newuser@example.org").exists())

    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    def test_shibboleth_remote_login(self):
        url = reverse("login-edugain")
        Identifier.objects.create(type=Identifier.Type.EPPN, value="newuser@example.org", identity=self.identity)
        response = self.client.get(f"{url}?next=/identity/me", follow=True, headers={"EPPN": "newuser@example.org"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"{self.identity.display_name()} |", response.content.decode("utf-8"))

    @override_settings(OIDC_CLAIM_SUB="HTTP_SUB")
    def test_google_login(self):
        url = reverse("login-google")
        Identifier.objects.create(type=Identifier.Type.GOOGLE, value="1234567890", identity=self.identity)
        response = self.client.get(f"{url}?next=/identity/me", follow=True, headers={"SUB": "1234567890"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"{self.identity.display_name()} |", response.content.decode("utf-8"))

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
        Identifier.objects.create(type=Identifier.Type.MICROSOFT, value=oid, identity=self.identity)
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
        self.assertIn(f"{self.identity.display_name()} |", response.content.decode("utf-8"))

    def test_microsoft_login_with_incorrect_issuer(self):
        oid = "00000000-0000-0000-0123-456789abcdef"
        iss = "https://login.example.org/"
        response = self._test_microsoft_login(iss, oid)
        self.assertIn("Identity provider is not authorised", response.content.decode("utf-8"))

    @override_settings(SAML_SUOMIFI_SSN="HTTP_SSN")
    @override_settings(ALLOW_TEST_FPIC=True)
    def test_suomifi_login(self):
        url = reverse("login-suomifi")
        Identifier.objects.create(type=Identifier.Type.FPIC, value="010181-900C", identity=self.identity)
        response = self.client.get(f"{url}?next=/identity/me", follow=True, headers={"SSN": "010181-900C"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"{self.identity.display_name()} |", response.content.decode("utf-8"))

    @override_settings(SMS_DEBUG=True)
    @mock.patch("kamu.connectors.sms.logger")
    def test_email_login(self, mock_logger):
        phone_number = PhoneNumber.objects.create(identity=self.identity, number="+123456789", verified=True)

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

    def test_email_login_non_verified_number(self):
        self.phone_number.verified = False
        self.phone_number.save()
        url = reverse("login-email") + "?next=/identity/me/"
        response = self.client.post(
            url,
            {"email_address": self.email_address.address, "phone_number": self.phone_number.number},
            follow=True,
        )
        self.assertIn("This contact information cannot be used to login", response.content.decode("utf-8"))

    def _test_email_login_verification(self):
        self.url = reverse("login-email-verify") + "?next=/identity/me/"
        self.session = self.client.session
        self.session["login_email_address"] = self.email_address.address
        self.session["login_phone_number"] = self.phone_number.number
        self.session.save()
        email_secret = Token.objects.create_email_object_verification_token(self.email_address)
        phone_secret = Token.objects.create_phone_object_verification_token(self.phone_number)
        return email_secret, phone_secret

    def test_email_login_verification(self):
        email_secret, phone_secret = self._test_email_login_verification()
        response = self.client.post(
            self.url,
            {"email_verification_token": email_secret, "phone_verification_token": phone_secret},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"{self.identity.display_name()} |", response.content.decode("utf-8"))

    def test_email_login_verification_incorrect_token(self):
        email_secret, phone_secret = self._test_email_login_verification()
        response = self.client.post(
            self.url,
            {"email_verification_token": email_secret, "phone_verification_token": phone_secret + "a"},
            follow=True,
        )
        self.assertIn("Invalid verification code", response.content.decode("utf-8"))

    def test_email_login_verification_incorrect_user(self):
        self.create_superidentity()
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
    @mock.patch("kamu.connectors.sms.logger")
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
    def test_email_login_resend_email_token_time_limit(self):
        self._test_email_login_verification()
        response = self.client.post(
            self.url,
            {"resend_email_code": True},
            follow=True,
        )
        self.assertIn("Tried to send a new code too soon", response.content.decode("utf-8"))
        self.assertEqual(0, len(mail.outbox))

    @override_settings(AUTHENTICATION_BACKENDS=["django.contrib.auth.backends.ModelBackend"])
    def test_disabled_local_shibboleth_login(self):
        url = reverse("login-shibboleth")
        response = self.client.get(url, follow=True, headers={"EPPN": "testuser@example.org"})
        self.assertEqual(response.status_code, 404)

    @override_settings(AUTHENTICATION_BACKENDS=["kamu.backends.ShibbolethLocalBackend"])
    def test_disabled_password_login(self):
        url = reverse("login-local")
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 404)


class LogoutViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_user()
        self.url = reverse("logout")

    @override_settings(LOGOUT_REDIRECT_URL="/test/")
    def test_logout_without_login(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/test/", response.url)
        self.assertIsNone(self.client.session.get("_auth_user_id"))

    @override_settings(LOGOUT_REDIRECT_URL="/")
    def test_logout_default(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.session.get("_auth_user_id"), str(self.user.pk))
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/", response.url)
        self.assertIsNone(self.client.session.get("_auth_user_id"))

    @override_settings(LOGOUT_REDIRECT_URL="/")
    def test_logout_notification(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.session.get("_auth_user_backend"), "django.contrib.auth.backends.ModelBackend")
        self.session = self.client.session
        self.session["login_backends"] = (
            "kamu.backends.EmailSMSBackend;kamu.backends.GoogleBackend;kamu.backends.ShibbolethLocalBackend;"
        )
        self.session.save()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Logout warning", response.content.decode("utf-8"))
        self.assertEqual(self.client.session.get("_auth_user_id"), str(self.user.pk))
        self.assertEqual(self.client.session.get("_auth_user_backend"), "kamu.backends.ShibbolethLocalBackend")
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/", response.url)
        self.assertIsNone(self.client.session.get("_auth_user_id"))

    @override_settings(SERVICE_LINK_URL="https://example.org")
    @override_settings(SAML_LOGOUT_LOCAL_PATH="/saml-logout/")
    @override_settings(LOGOUT_REDIRECT_URL="/test/")
    def test_logout_saml(self):
        self.client.force_login(self.user)
        self.session = self.client.session
        self.session["_auth_user_backend"] = "kamu.backends.ShibbolethLocalBackend"
        self.session.save()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/saml-logout/?return=https://example.org/test/", response.url)
        self.assertIsNone(self.client.session.get("_auth_user_id"))

    @override_settings(SERVICE_LINK_URL="https://example.org")
    @override_settings(OIDC_LOGOUT_PATH="/login/redirecturi?logout=")
    @override_settings(LOGOUT_REDIRECT_URL="/test/")
    def test_logout_oidc(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))
        self.session = self.client.session
        self.session["_auth_user_backend"] = "kamu.backends.GoogleBackend"
        self.session.save()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/redirecturi?logout=https://example.org/test/", response.url)
        self.assertIsNone(self.client.session.get("_auth_user_id"))

    @override_settings(LOGOUT_REDIRECT_URL="/test/")
    def test_shibboleth_notify(self):
        self.client.force_login(self.user)
        self.assertIsNotNone(self.client.session.get("_auth_user_id"))
        response = self.client.get(self.url, {"action": "logout", "return": "/shibboleth/logout/"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/shibboleth/logout/", response.url)
        self.assertIsNone(self.client.session.get("_auth_user_id"))


class RegistrationViewTests(BaseTestCase):
    def setUp(self):
        self.create_user()
        self.role = self.create_role()
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

    def test_invite_view_without_login(self):
        url = reverse("login-invite")
        response = self.client.get(url)
        self.assertIn("Register identity", response.content.decode("utf-8"))

    def test_invite_view_with_login(self):
        url = reverse("login-invite")
        self.client.force_login(self.user)
        response = self.client.get(url)
        self.assertIn("Claim invite", response.content.decode("utf-8"))

    def test_invite_view_login(self):
        url = reverse("login-invite")
        response = self.client.post(url, data={"code": self.secret, "login": True})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("login"))

    def test_invite_view_register(self):
        url = reverse("login-invite")
        response = self.client.post(url, data={"code": self.secret, "register": True})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("login-register"))

    def test_invite_view_claim_invite(self):
        self.client.force_login(self.user)
        url = reverse("login-invite")
        response = self.client.post(url, data={"code": self.secret, "claim": True})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("membership-claim"))

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

    def test_verify_email_address_resend_code(self):
        url = reverse("login-register-email-verify")
        email_address = "tester@example.org"
        self.session["register_email_address"] = email_address
        self.session.save()
        response = self.client.post(url, data={"resend_email_code": True})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("login-register-email-verify"))
        self.assertTrue(Token.objects.filter(email_address=email_address).exists())

    def test_registration_phone_number_without_verified_email(self):
        url = reverse("login-register-phone")
        response = self.client.post(url, data={"phone_number": "+123456789"}, follow=True)
        self.assertEqual(response.status_code, 403)

    @mock.patch("kamu.utils.identity.SmsConnector")
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
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.identity, identity)

    @mock.patch("kamu.utils.identity.SmsConnector")
    def test_verify_phone_number_resend_code(self, mock_connector):
        mock_connector.return_value.send_sms.return_value = True
        url = reverse("login-register-phone-verify")
        phone_number = "+123456789"
        self.session["verified_email_address"] = "tester@example.org"
        self.session["register_phone_number"] = phone_number
        self.session["register_given_names"] = "New"
        self.session["register_surname"] = "User"
        self.session.save()
        response = self.client.post(url, data={"resend_phone_code": True})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("login-register-phone-verify"))
        self.assertTrue(Token.objects.filter(phone_number=phone_number).exists())

    @override_settings(OIDC_CLAIM_SUB="HTTP_SUB")
    @override_settings(OIDC_CLAIM_EMAIL="HTTP_EMAIL")
    def test_register_with_external_account(self):
        url = reverse("login-google")
        response = self.client.get(url, follow=True, headers={"SUB": "1234567890", "EMAIL": "test@example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Membership created", response.content.decode("utf-8"))
        self.assertTrue(Identifier.objects.filter(value="1234567890", name="test@example.com").exists())

    @override_settings(OIDC_MICROSOFT_ISSUER="HTTP_ISSUER")
    def test_register_fail_with_invalid_issuer(self):
        url = reverse("login-microsoft")
        response = self.client.get(url, follow=True, headers={"ISSUER": "invalid"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invitation claiming failed", response.content.decode("utf-8"))

    @override_settings(OIDC_CLAIM_SUB="HTTP_SUB")
    def test_register_redirect_to_membership_claim(self):
        url = reverse("login-google") + "?next=" + reverse("identity-me")
        response = self.client.get(url, follow=True, headers={"SUB": "1234567890"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Membership created", response.content.decode("utf-8"))
        self.assertTrue(Identifier.objects.filter(value="1234567890").exists())
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.identity, Identity.objects.get(identifiers__value="1234567890"))

    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    def test_register_with_haka_account(self):
        url = reverse("login-haka")
        response = self.client.get(url, follow=True, headers={"EPPN": "haka@example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Membership created", response.content.decode("utf-8"))
        identity = Identity.objects.get(identifiers__value="haka@example.com")
        self.assertEqual(identity.user.username, "haka@example.com")
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.identity, identity)

    @override_settings(SAML_EIDAS_IDENTIFIER="HTTP_IDENTIFIER")
    @override_settings(SAML_EIDAS_GIVEN_NAMES="HTTP_GIVEN_NAMES")
    @override_settings(SAML_EIDAS_SURNAME="HTTP_SURNAME")
    @override_settings(SAML_SUOMIFI_ASSURANCE="HTTP_ASSURANCE")
    def test_eidas_registration_login(self):
        url = reverse("login-suomifi")
        response = self.client.get(
            url,
            follow=True,
            headers={
                "IDENTIFIER": "ES/FI/abcdefg",
                "GIVEN_NAMES": "eIDAS",
                "SURNAME": "User",
                "ASSURANCE": "http://eidas.europa.eu/LoA/low",
            },
        )
        self.assertEqual(response.status_code, 200)
        identity = Identity.objects.get(identifiers__value="ES/FI/abcdefg")
        self.assertEqual(identity.assurance_level, 2)
        self.assertEqual(identity.given_names, "eIDAS")
        self.assertEqual(identity.surname, "User")
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.identity, identity)

    @override_settings(SAML_EIDAS_IDENTIFIER="HTTP_IDENTIFIER")
    @override_settings(SAML_EIDAS_SURNAME="HTTP_SURNAME")
    @override_settings(META_ENCODING="utf-8")
    def test_registration_encoding_invalid(self):
        url = reverse("login-suomifi")
        response = self.client.get(
            url,
            follow=True,
            headers={
                "IDENTIFIER": "ES/FI/abcdefg",
                "SURNAME": "Ääkköset".encode("utf-8").decode("latin"),
            },
        )
        self.assertEqual(response.status_code, 200)
        identity = Identity.objects.get(identifiers__value="ES/FI/abcdefg")
        self.assertEqual(identity.surname, "Ã\x84Ã¤kkÃ¶set")

    @override_settings(SAML_EIDAS_IDENTIFIER="HTTP_IDENTIFIER")
    @override_settings(SAML_EIDAS_SURNAME="HTTP_SURNAME")
    @override_settings(META_ENCODING="latin1")
    def test_registration_encoding_fixed(self):
        url = reverse("login-suomifi")
        response = self.client.get(
            url,
            follow=True,
            headers={
                "IDENTIFIER": "ES/FI/abcdefg",
                "SURNAME": "Ääkköset".encode("utf-8").decode("latin"),
            },
        )
        self.assertEqual(response.status_code, 200)
        identity = Identity.objects.get(identifiers__value="ES/FI/abcdefg")
        self.assertEqual(identity.surname, "Ääkköset")


class LinkIdentifierTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_identity(user=True)
        self.client = Client()
        self.session = self.client.session
        self.session["link_identifier"] = True
        self.session["link_identifier_time"] = timezone.now().isoformat()
        self.session.save()
        self.client.force_login(self.user)

    @override_settings(SERVICE_LINK_URL="https://example.org")
    @override_settings(OIDC_LOGOUT_PATH="/login/redirecturi?logout=")
    @override_settings(OIDC_VIEWS=["login-google"])
    def test_logout_redirect_before_linking_oidc(self):
        url = reverse("identity-identifier", kwargs={"pk": self.identity.pk})
        response = self.client.post(url, follow=False, data={"link_identifier": "google"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            unquote_plus(response.url),
            "/login/redirecturi?logout=https://example.org/login/google/?next=/identity/1/identifiers/",
        )

    @override_settings(SERVICE_LINK_URL=None)
    @override_settings(OIDC_LOGOUT_PATH="/login/redirecturi?logout=")
    @override_settings(OIDC_VIEWS=["login-google"])
    def test_logout_redirect_without_link_url_before_linking_oidc(self):
        url = reverse("identity-identifier", kwargs={"pk": self.identity.pk})
        response = self.client.post(url, follow=False, data={"link_identifier": "google"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            unquote_plus(response.url),
            "/login/redirecturi?logout=/login/google/?next=/identity/1/identifiers/",
        )

    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_link_haka_identifier(self, mock_logger):
        url = reverse("login-haka") + "?next=" + reverse("identity-identifier", kwargs={"pk": self.identity.pk})
        response = self.client.get(url, follow=True, headers={"EPPN": "haka@example.com"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Identifier.objects.filter(identity=self.identity, value="haka@example.com").exists())
        mock_logger.log.assert_has_calls(
            [
                call(20, "Started identifier linking process", extra=ANY),
                call(20, f"Linked eppn identifier to identity {self.identity.display_name()}", extra=ANY),
            ]
        )
        self.assertEqual(mock_logger.log.call_args_list[0][1]["extra"]["backend"], "ShibbolethHakaBackend")
        self.assertEqual(
            LogEntry.objects.filter(
                change_message=f"Linked eppn identifier to identity {self.identity.display_name()}"
            ).count(),
            1,
        )

    @override_settings(LINK_IDENTIFIER_TIME_LIMIT=-1)
    def test_link_identifier_with_expired_link_identifier(self):
        url = reverse("login-haka") + "?next=" + reverse("identity-identifier", kwargs={"pk": self.identity.pk})
        response = self.client.get(url, follow=True, headers={"EPPN": "haka@example.com"})
        self.assertIn("Identifier linking failed", response.content.decode("utf-8"))
        self.assertIn("Link identifier expired", response.content.decode("utf-8"))

    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    def test_link_local_shibboleth_identifier(self):
        url = reverse("login-shibboleth") + "?next=" + reverse("identity-identifier", kwargs={"pk": self.identity.pk})
        response = self.client.get(url, follow=True, headers={"EPPN": "localtest@example.org"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Identifier.objects.filter(identity=self.identity, value="localtest@example.org").exists())
        self.identity.refresh_from_db()
        self.assertEqual(self.identity.uid, "localtest")

    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    def test_link_existing_identifier(self):
        user = get_user_model()
        user2 = user.objects.create_user(username="testuser2", password="test_pass")
        identity2 = Identity.objects.create(user=user2, given_names="Test2", surname="User2")
        Identifier.objects.create(
            type=Identifier.Type.EPPN, value="localtest@example.org", identity=identity2, deactivated_at=None
        )
        url = reverse("login-shibboleth")
        response = self.client.get(url, follow=True, headers={"EPPN": "localtest@example.org"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Identifier is already linked to another user", response.content.decode("utf-8"))

    @override_settings(SAML_ATTR_EPPN="HTTP_EPPN")
    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    def test_link_local_shibboleth_uid_changed(self):
        url = reverse("login-shibboleth")
        self.identity.uid = "oldtest"
        self.identity.save()
        response = self.client.get(url, follow=True, headers={"EPPN": "localtest@example.org"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Suspected duplicate user. Identity already has a different username", response.content.decode("utf-8")
        )
        self.identity.refresh_from_db()
        self.assertEqual(self.identity.uid, "oldtest")
