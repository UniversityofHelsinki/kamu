"""
Tests for base views.
"""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from base.auth import ShibbolethBackend

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
        request.META = {settings.SAML_ATTR_USERNAME: "testuser@example.org"}
        backend = ShibbolethBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertEqual(user.username, "testuser@example.org")

    def test_login_create_user(self):
        request = self.factory.get(reverse("login-shibboleth"))
        request.META = {settings.SAML_ATTR_USERNAME: "newuser@example.org"}
        backend = ShibbolethBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertEqual(user.username, "newuser@example.org")

    def test_login_create_incorrect_user_name(self):
        request = self.factory.get(reverse("login-shibboleth"))
        request.META = {settings.SAML_ATTR_USERNAME: "newuser"}
        backend = ShibbolethBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertEqual(user, None)

    def test_login_no_user_creation(self):
        request = self.factory.get(reverse("login-shibboleth"))
        request.META = {settings.SAML_ATTR_USERNAME: "newuser@example.org"}
        backend = ShibbolethBackend()
        user = backend.authenticate(request=request, create_user=False)
        self.assertEqual(user, None)

    @override_settings(SAML_GROUP_PREFIXES=["saml_", "sso_"])
    def test_login_update_groups(self):
        request = self.factory.get(reverse("login-shibboleth"))
        request.META = {
            settings.SAML_ATTR_USERNAME: "testuser@example.org",
            settings.SAML_ATTR_GROUPS: f"{self.sso_group.name};saml_nogroup",
        }
        backend = ShibbolethBackend()
        user = backend.authenticate(request=request, create_user=True)
        self.assertEqual(user.groups.count(), 2)
