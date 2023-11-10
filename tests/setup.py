"""
Test setup for all tests.
"""

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from rest_framework.test import APIRequestFactory, APITestCase

from identity.models import EmailAddress, Identity
from role.models import Permission, Role


class TestData(TestCase):
    """
    Base test data for all tests.
    """

    def setUp(self):
        super().setUp()
        user = get_user_model()
        self.user = user.objects.create_user(username="testuser", password="test_pass")
        self.superuser = user.objects.create_user(
            username="admin", password="test_pass", is_superuser=True, is_staff=True
        )
        self.identity = Identity.objects.create(user=self.user, given_names="Test Me", surname="User", nickname="Test")
        self.superidentity = Identity.objects.create(
            user=self.superuser, given_names="Super", surname="User", nickname="Super"
        )
        self.role = Role.objects.create(identifier="testrole", name_en="Test Role", maximum_duration=10)
        self.permission = Permission.objects.create(identifier="testpermission", name_en="Test Permission", cost=5)
        self.email_address = EmailAddress.objects.create(
            identity=self.identity,
            address="test@example.org",
        )
        self.role.permissions.add(self.permission)


class BaseTestCase(TestData):
    """
    TestCase class with test data.
    """

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()


class BaseAPITestCase(TestData, APITestCase):
    """
    APITestCase class with test data.
    """

    def setUp(self):
        super().setUp()
        self.factory = APIRequestFactory()
        self.url = "/api/v0/"
