"""
Test setup for all tests.
"""

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from rest_framework.test import APIRequestFactory, APITestCase

from identity.models import Attribute, AttributeType, Identity
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
        self.identity = Identity.objects.create(user=self.user, name="Test User")
        self.superidentity = Identity.objects.create(user=self.superuser, name="Superuser Identity")
        self.attribute_type_first_name = AttributeType.objects.get_or_create(
            identifier="given_names", name_en="Given names", regex_pattern=".*"
        )[0]
        self.attribute_type_last_name = AttributeType.objects.get_or_create(
            identifier="last_names", name_en="Surname", regex_pattern=".*"
        )[0]
        self.attribute_type_email = AttributeType.objects.get_or_create(
            identifier="email", name_en="E-mail", regex_pattern=".*@.*"
        )[0]
        self.role = Role.objects.create(identifier="testrole", name_en="Test Role", maximum_duration=10)
        self.permission = Permission.objects.create(identifier="testpermission", name_en="Test Permission", cost=5)
        self.attribute = Attribute.objects.create(
            identity=self.identity,
            attribute_type=self.attribute_type_first_name,
            value="Nick",
            source="testsource",
        )
        self.attribute_email = Attribute.objects.create(
            identity=self.identity,
            attribute_type=self.attribute_type_email,
            value="test@example.org",
            source="testsource",
        )
        self.permission.requirements.add(self.attribute_type_email)
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
