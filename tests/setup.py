"""
Test setup for all tests.
"""

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from rest_framework.test import APIRequestFactory, APITestCase

from kamu.models.identity import EmailAddress, Identity, Nationality
from kamu.models.role import Permission, Role


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
        self.identity = Identity.objects.create(
            user=self.user, given_names="Test Me", surname="User", given_name_display="Test"
        )
        self.superidentity = Identity.objects.create(
            user=self.superuser, given_names="Super", surname="User", given_name_display="Super"
        )
        self.role = Role.objects.create(identifier="testrole", name_en="Test Role", maximum_duration=10)
        self.permission = Permission.objects.create(identifier="testpermission", name_en="Test Permission", cost=5)
        self.email_address = EmailAddress.objects.create(
            identity=self.identity,
            address="test@example.org",
        )
        self.role.permissions.add(self.permission)
        self.nationality = Nationality.objects.get_or_create(code="FI", name_en="Finland")[0]


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
