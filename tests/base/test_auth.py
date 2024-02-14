"""
Tests for base views.
"""

from unittest.mock import ANY, call, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from base.auth import (
    AuthenticationError,
    GoogleBackend,
    ShibbolethEdugainBackend,
    ShibbolethHakaBackend,
    ShibbolethLocalBackend,
    SuomiFiBackend,
)
from identity.models import Identifier, Identity

UserModel = get_user_model()


class ShibbolethBackendTests(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create(username="testuser@example.org")
        self.identity = Identity.objects.create(user=self.user)
        self.identifier = Identifier.objects.create(
            identity=self.identity, type=Identifier.Type.EPPN, value="testuser@example.org"
        )
        self.factory = RequestFactory()
        self.request = self.factory.get(reverse("login-shibboleth"))
        self.request.user = AnonymousUser()

    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    def test_local_login_with_existing_user(self):
        self.request.META = {settings.SAML_ATTR_EPPN: "testuser@example.org"}
        backend = ShibbolethLocalBackend()
        user = backend.authenticate(request=self.request, create_user=True)
        self.assertEqual(user.username, "testuser@example.org")

    @override_settings(LOCAL_EPPN_SUFFIX="@example.com")
    def test_local_login_with_incorrect_suffix(self):
        self.request.META = {settings.SAML_ATTR_EPPN: "testuser@example.org"}
        backend = ShibbolethLocalBackend()
        with self.assertRaises(AuthenticationError) as e:
            backend.authenticate(request=self.request, create_user=True)
        self.assertEqual(str(e.exception), "Invalid identifier format.")

    def test_haka_local_login_with_existing_user(self):
        self.request.META = {settings.SAML_ATTR_EPPN: "testuser@example.org"}
        backend = ShibbolethHakaBackend()
        user = backend.authenticate(request=self.request, create_user=True)
        self.assertEqual(user.username, "testuser@example.org")

    def test_edugain_local_login_with_existing_user(self):
        self.request.META = {settings.SAML_ATTR_EPPN: "testuser@example.org"}
        backend = ShibbolethEdugainBackend()
        user = backend.authenticate(request=self.request, create_user=True)
        self.assertEqual(user.username, "testuser@example.org")

    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    @patch("base.utils.logger_audit")
    def test_login_create_user(self, mock_logger):
        self.request.META = {
            settings.SAML_ATTR_EPPN: "newuser@example.org",
            settings.SAML_ATTR_GIVEN_NAMES: "New",
            settings.SAML_ATTR_SURNAME: "User",
        }
        backend = ShibbolethLocalBackend()
        user = backend.authenticate(request=self.request, create_user=True)
        self.assertEqual(user.username, "newuser@example.org")
        self.assertEqual(user.identity.assurance_level, Identity.AssuranceLevel.LOW)
        self.assertEqual(
            Identifier.objects.get(type=Identifier.Type.EPPN, value="newuser@example.org").identity, user.identity
        )
        mock_logger.log.assert_has_calls(
            [
                call(20, "Created user newuser@example.org", extra=ANY),
                call(20, "Identity created for newuser@example.org", extra=ANY),
                call(20, "Linked eppn identifier to identity New User", extra=ANY),
            ]
        )

    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    def test_login_create_user_assurance(self):
        self.request.META = {
            settings.SAML_ATTR_EPPN: "newuser@example.org",
            settings.SAML_ATTR_ASSURANCE: "https://refeds.org/assurance/IAP/medium;https://refeds.org/assurance/IAP/high",
        }
        backend = ShibbolethLocalBackend()
        user = backend.authenticate(request=self.request, create_user=True)
        self.assertEqual(user.username, "newuser@example.org")
        self.assertEqual(user.identity.assurance_level, Identity.AssuranceLevel.HIGH)

    def test_login_create_incorrect_user_name(self):
        self.request.META = {settings.SAML_ATTR_EPPN: "newuser"}
        backend = ShibbolethLocalBackend()
        with self.assertRaises(AuthenticationError) as e:
            backend.authenticate(request=self.request, create_user=True)
        self.assertEqual(str(e.exception), "Invalid identifier format.")

    def test_login_no_user_creation(self):
        self.request.META = {settings.SAML_ATTR_EPPN: "newuser@example.org"}
        backend = ShibbolethHakaBackend()
        with self.assertRaises(AuthenticationError) as e:
            backend.authenticate(request=self.request, create_user=False)
        self.assertEqual(str(e.exception), "Identifier not found.")

    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    @override_settings(SAML_GROUP_PREFIXES=["saml_", "sso_"])
    @patch("base.utils.logger_audit")
    def test_login_update_groups(self, mock_logger):
        test_group = Group.objects.create(name="test_group")
        saml_group = Group.objects.create(name="saml_group")
        sso_group = Group.objects.create(name="sso_group")
        self.user.groups.add(test_group)
        self.user.groups.add(saml_group)
        self.request.META = {
            settings.SAML_ATTR_EPPN: "testuser@example.org",
            settings.SAML_ATTR_GROUPS: f"{sso_group.name};saml_nogroup",
        }
        backend = ShibbolethLocalBackend()
        user = backend.authenticate(request=self.request, create_user=True)
        self.assertEqual(user.groups.count(), 2)
        self.assertIn(test_group, user.groups.all())
        self.assertIn(sso_group, user.groups.all())
        mock_logger.log.assert_has_calls(
            [
                call(20, "Group saml_group removed from user testuser@example.org", extra=ANY),
                call(20, "Group sso_group added to user testuser@example.org", extra=ANY),
            ]
        )

    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    def test_uid_update(self):
        self.request.META = {
            settings.SAML_ATTR_EPPN: "testuser@example.org",
        }
        backend = ShibbolethLocalBackend()
        user = backend.authenticate(request=self.request, create_user=True)
        self.assertEqual(user.identity.uid, "testuser")

    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    @patch("base.utils.logger_audit")
    def test_update_uid_already_exists(self, mock_logger):
        user2 = UserModel.objects.create(username="testuser2@example.org")
        Identity.objects.create(user=user2, uid="testuser")
        self.request.META = {
            settings.SAML_ATTR_EPPN: "testuser@example.org",
        }
        backend = ShibbolethLocalBackend()
        setattr(self.request, "session", "session")
        messages = FallbackStorage(self.request)
        setattr(self.request, "_messages", messages)
        backend.authenticate(request=self.request, create_user=True)
        mock_logger.log.assert_has_calls(
            [
                call(30, "UID already exists in the database", extra=ANY),
            ]
        )
        self.assertIn(
            "Suspected duplicate user. Username already exists in the database: testuser",
            messages._queued_messages[0].message,
        )

    @override_settings(LOCAL_EPPN_SUFFIX="@example.org")
    @override_settings(LOCAL_UID_IGNORE_REGEX="^\dk\d{6}$")
    def test_uid_update_ignore_regex(self):
        self.request.META = {
            settings.SAML_ATTR_EPPN: "0k123456@example.org",
        }
        backend = ShibbolethLocalBackend()
        user = backend.authenticate(request=self.request, create_user=True)
        self.assertIsNone(user.identity.uid)


class GoogleBackendTests(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create(username="testuser@example.org")
        self.identity = Identity.objects.create(user=self.user)
        self.identifier = Identifier.objects.create(
            identity=self.identity, value="1234567890", type=Identifier.Type.GOOGLE
        )
        self.factory = RequestFactory()

    def test_login_google_with_existing_user(self):
        request = self.factory.get(reverse("login-google"))
        request.user = AnonymousUser()
        request.META = {settings.OIDC_CLAIM_SUB: "1234567890"}
        backend = GoogleBackend()
        user = backend.authenticate(request=request, create_user=False)
        self.assertEqual(user.username, "testuser@example.org")

    def test_login_google_create_user(self):
        request = self.factory.get(reverse("login-google"))
        request.user = AnonymousUser()
        request.META = {settings.OIDC_CLAIM_SUB: "0123456789"}
        backend = GoogleBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertEqual(user.username, f"0123456789{ settings.ACCOUNT_SUFFIX_GOOGLE }")
        self.assertEqual(Identifier.objects.get(value="0123456789").identity.user, user)

    def test_login_google_create_user_existing_identifier(self):
        request = self.factory.get(reverse("login-google"))
        identity = Identity.objects.create()
        Identifier.objects.create(identity=identity, value="0123456789", type=Identifier.Type.GOOGLE)
        request.user = AnonymousUser()
        request.META = {settings.OIDC_CLAIM_SUB: "0123456789"}
        backend = GoogleBackend()
        with self.assertRaises(AuthenticationError) as e:
            backend.authenticate(request=request, create_user=True)
        self.assertEqual(str(e.exception), "Unexpected error.")

    def test_login_google_create_user_with_logged_in_user(self):
        request = self.factory.get(reverse("login-google"))
        request.user = self.user
        request.META = {settings.OIDC_CLAIM_SUB: "0123456789"}
        backend = GoogleBackend()
        with self.assertRaises(AuthenticationError) as e:
            backend.authenticate(request=request, create_user=True)
        self.assertEqual(str(e.exception), "You are already logged in.")

    def test_login_google_link_user_anonymous(self):
        request = self.factory.get(reverse("login-google"))
        request.user = AnonymousUser()
        request.META = {settings.OIDC_CLAIM_SUB: "0123456789"}
        backend = GoogleBackend()
        with self.assertRaises(AuthenticationError) as e:
            backend.authenticate(request=request, link_identifier=True)
        self.assertEqual(str(e.exception), "User must be authenticated to link identifier.")
        self.assertEqual(Identifier.objects.filter(value="0123456789").count(), 0)

    def test_login_google_link_identifier(self):
        request = self.factory.get(reverse("login-google"))
        request.user = self.user
        request.META = {settings.OIDC_CLAIM_SUB: "0123456789"}
        backend = GoogleBackend()
        user = backend.authenticate(request=request, link_identifier=True)
        self.assertEqual(user.username, "testuser@example.org")
        self.assertEqual(Identifier.objects.get(value="0123456789").identity, self.identity)

    @patch("base.utils.logger_audit")
    def test_login_google_link_existing_identifier(self, mock_logger):
        request = self.factory.get(reverse("login-google"))
        request.user = self.user
        identity = Identity.objects.create()
        Identifier.objects.create(identity=identity, value="0123456789", type=Identifier.Type.GOOGLE)
        request.META = {settings.OIDC_CLAIM_SUB: "0123456789"}
        backend = GoogleBackend()
        with self.assertRaises(AuthenticationError) as e:
            backend.authenticate(request=request, link_identifier=True)
        self.assertEqual(str(e.exception), "Identifier is already linked to another user.")
        mock_logger.log.assert_has_calls(
            [
                call(30, "Suspected duplicate user. Identifier already exists for another identity.", extra=ANY),
            ]
        )


class SuomiFiBackendTests(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create(username="testuser@example.org")
        self.identity = Identity.objects.create(user=self.user)
        self.identifier = Identifier.objects.create(
            identity=self.identity, value="010181-900C", type=Identifier.Type.FPIC
        )
        self.factory = RequestFactory()

    @override_settings(ALLOW_TEST_FPIC=True)
    def test_login_suomifi_with_existing_user(self):
        request = self.factory.get(reverse("login-suomifi"))
        request.user = AnonymousUser()
        request.META = {settings.SAML_SUOMIFI_SSN: self.identifier.value}
        backend = SuomiFiBackend()
        user = backend.authenticate(request=request, create_user=False)
        self.assertEqual(user.username, "testuser@example.org")
        self.assertEqual(user.identity.fpic, self.identifier.value)
        self.assertEqual(user.identity.date_of_birth.strftime("%Y-%m-%d"), "1981-01-01")

    @override_settings(EIDAS_IDENTIFIER_REGEX="^[A-Z]{2}/FI/.+$")
    def test_login_with_eidas_identifier(self):
        request = self.factory.get(reverse("login-suomifi"))
        request.user = AnonymousUser()
        Identifier.objects.create(identity=self.identity, value="ES/FI/abcdefg", type=Identifier.Type.EIDAS)
        request.META = {settings.SAML_EIDAS_IDENTIFIER: "ES/FI/abcdefg", settings.SAML_EIDAS_DATEOFBIRTH: "1982-03-04"}
        backend = SuomiFiBackend()
        user = backend.authenticate(request=request, create_user=False)
        self.assertEqual(user.username, "testuser@example.org")
        self.assertEqual(user.identity.date_of_birth.strftime("%Y-%m-%d"), "1982-03-04")

    @override_settings(EIDAS_IDENTIFIER_REGEX="^[A-Z]{2}/FI/.+$")
    def test_login_eidas_with_invalid_identifier(self):
        request = self.factory.get(reverse("login-suomifi"))
        Identifier.objects.create(identity=self.identity, value="ES/ES/abcdefg", type=Identifier.Type.EIDAS)
        request.META = {settings.SAML_EIDAS_IDENTIFIER: "ES/ES/abcdefg"}
        backend = SuomiFiBackend()
        with self.assertRaises(AuthenticationError) as e:
            backend.authenticate(request=request, create_user=False)
        self.assertEqual(str(e.exception), "Invalid identifier format.")

    def test_login_suomifi_with_incorrect_eidas_identifier(self):
        request = self.factory.get(reverse("login-suomifi"))
        request.META = {settings.SAML_EIDAS_IDENTIFIER: "010181-900C"}
        backend = SuomiFiBackend()
        with self.assertRaises(AuthenticationError) as e:
            backend.authenticate(request=request, create_user=False)
        self.assertEqual(str(e.exception), "Invalid identifier format.")

    def test_login_suomifi_without_request_params(self):
        request = self.factory.get(reverse("login-suomifi"))
        backend = SuomiFiBackend()
        with self.assertRaises(AuthenticationError) as e:
            backend.authenticate(request=request, create_user=False)
        self.assertIn("Valid identifier not found.", str(e.exception))
