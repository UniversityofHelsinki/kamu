"""
Tests for base views.
"""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser, Group
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from base.auth import GoogleBackend, ShibbolethBackend
from identity.models import Identifier, Identity

UserModel = get_user_model()


class ShibbolethBackendTests(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create(username="testuser@example.org")
        self.test_group = Group.objects.create(name="test_group")
        self.saml_group = Group.objects.create(name="saml_group")
        self.sso_group = Group.objects.create(name="sso_group")
        self.user.groups.add(self.test_group)
        self.user.groups.add(self.saml_group)
        self.factory = RequestFactory()

    def test_login_with_existing_user(self):
        request = self.factory.get(reverse("login-shibboleth"))
        request.META = {settings.SAML_ATTR_EPPN: "testuser@example.org"}
        backend = ShibbolethBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertEqual(user.username, "testuser@example.org")

    def test_login_create_user(self):
        request = self.factory.get(reverse("login-shibboleth"))
        request.META = {settings.SAML_ATTR_EPPN: "newuser@example.org"}
        backend = ShibbolethBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertEqual(user.username, "newuser@example.org")

    def test_login_create_incorrect_user_name(self):
        request = self.factory.get(reverse("login-shibboleth"))
        request.META = {settings.SAML_ATTR_EPPN: "newuser"}
        backend = ShibbolethBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertEqual(user, None)

    def test_login_no_user_creation(self):
        request = self.factory.get(reverse("login-shibboleth"))
        request.META = {settings.SAML_ATTR_EPPN: "newuser@example.org"}
        backend = ShibbolethBackend()
        user = backend.authenticate(request=request, create_user=False)
        self.assertEqual(user, None)

    @override_settings(SAML_GROUP_PREFIXES=["saml_", "sso_"])
    def test_login_update_groups(self):
        request = self.factory.get(reverse("login-shibboleth"))
        request.META = {
            settings.SAML_ATTR_EPPN: "testuser@example.org",
            settings.SAML_ATTR_GROUPS: f"{self.sso_group.name};saml_nogroup",
        }
        backend = ShibbolethBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertEqual(user.groups.count(), 2)


class GoogleBackendTests(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create(username="testuser@example.org")
        self.identity = Identity.objects.create(user=self.user)
        self.identifier = Identifier.objects.create(identity=self.identity, value="1234567890", type="google")
        self.factory = RequestFactory()

    def test_login_google_with_existing_user(self):
        request = self.factory.get(reverse("login-google"))
        request.META = {settings.OIDC_GOOGLE_SUB: "1234567890"}
        backend = GoogleBackend()
        user = backend.authenticate(request=request, create_user=False)
        self.assertEqual(user.username, "testuser@example.org")

    def test_login_google_create_user(self):
        request = self.factory.get(reverse("login-google"))
        request.user = AnonymousUser()
        request.META = {settings.OIDC_GOOGLE_SUB: "0123456789"}
        backend = GoogleBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertEqual(user.username, "0123456789@accounts.google.com")
        self.assertEqual(Identifier.objects.get(value="0123456789").identity.user, user)

    def test_login_google_create_user_existing_identifier(self):
        request = self.factory.get(reverse("login-google"))
        identity = Identity.objects.create()
        identifier = Identifier.objects.create(identity=identity, value="0123456789", type="google")
        request.user = AnonymousUser()
        request.META = {settings.OIDC_GOOGLE_SUB: "0123456789"}
        backend = GoogleBackend()
        user = backend.authenticate(request=request, create_user=True)
        identifier.refresh_from_db()
        self.assertEqual(user.username, "0123456789@accounts.google.com")
        self.assertEqual(identifier.identity.user, user)

    def test_login_google_create_user_with_existing_user(self):
        request = self.factory.get(reverse("login-google"))
        request.user = self.user
        request.META = {settings.OIDC_GOOGLE_SUB: "0123456789"}
        backend = GoogleBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertIsNone(user)

    def test_login_google_link_user_anonymous(self):
        request = self.factory.get(reverse("login-google"))
        request.user = AnonymousUser()
        request.META = {settings.OIDC_GOOGLE_SUB: "0123456789"}
        backend = GoogleBackend()
        user = backend.authenticate(request=request, link_identifier=True)
        self.assertIsNone(user)
        self.assertEqual(Identifier.objects.filter(value="0123456789").count(), 0)

    def test_login_google_link_identifier(self):
        request = self.factory.get(reverse("login-google"))
        request.user = self.user
        request.META = {settings.OIDC_GOOGLE_SUB: "0123456789"}
        backend = GoogleBackend()
        user = backend.authenticate(request=request, link_identifier=True)
        self.assertEqual(user.username, "testuser@example.org")
        self.assertEqual(Identifier.objects.get(value="0123456789").identity, self.identity)

    def test_login_google_link_existing_identifier(self):
        request = self.factory.get(reverse("login-google"))
        request.user = self.user
        identity = Identity.objects.create()
        Identifier.objects.create(identity=identity, value="0123456789", type="google")
        request.META = {settings.OIDC_GOOGLE_SUB: "0123456789"}
        backend = GoogleBackend()
        user = backend.authenticate(request=request, link_identifier=True)
        self.assertIsNone(user)
