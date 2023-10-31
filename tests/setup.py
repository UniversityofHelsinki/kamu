from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from rest_framework.test import APIRequestFactory, APITestCase

from identity.models import Attribute, AttributeType, Identity
from role.models import Permission, Role


class TestData(TestCase):
    def setUp(self):
        super().setUp()
        user = get_user_model()
        self.user = user.objects.create_user(username="testuser", password="test_pass")
        self.superuser = user.objects.create_user(
            username="admin", password="test_pass", is_superuser=True, is_staff=True
        )
        self.identity = Identity.objects.create(user=self.user, name="Test User")
        self.superidentity = Identity.objects.create(user=self.superuser, name="Test Superuser")
        self.attribute_type = AttributeType.objects.create(
            identifier="testattribute", name_en="Test Attribute", regex_pattern="^[a-z]*$"
        )
        self.role = Role.objects.create(identifier="testrole", name_en="Test Role", maximum_duration=10)
        self.permission = Permission.objects.create(identifier="testpermission", name_en="Test Permission", cost=5)
        self.attribute = Attribute.objects.create(
            identity=self.identity, attribute_type=self.attribute_type, value="testvalue", source="testsource"
        )
        self.permission.requirements.add(self.attribute_type)
        self.role.permissions.add(self.permission)


class BaseTestCase(TestData):
    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()


class BaseAPITestCase(TestData, APITestCase):
    def setUp(self):
        super().setUp()
        self.factory = APIRequestFactory()
        self.url = "/api/v0/"
