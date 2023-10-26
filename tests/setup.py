from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, APITestCase

from identity.models import Attribute, AttributeType, Identity
from role.models import Permission, Role


class BaseTestCase(APITestCase):
    def setUp(self):
        user = get_user_model()
        self.user = user.objects.create_user(username="testuser", password="test_pass")
        self.superuser = user.objects.create_user(username="admin", password="test_pass", is_superuser=True)
        self.identity = Identity.objects.create(user=self.user)
        self.superidentity = Identity.objects.create(user=self.superuser)
        self.attribute_type = AttributeType.objects.create(identifier="Test attribute", regex_pattern="^[a-z]*$")
        self.role = Role.objects.create(name="testrole", maximum_duration=10)
        self.permission = Permission.objects.create(name="testpermission", cost=5)
        self.attribute = Attribute.objects.create(
            identity=self.identity, attribute_type=self.attribute_type, value="testvalue", source="testsource"
        )
        self.permission.requirements.add(self.attribute_type)
        self.role.permissions.add(self.permission)
        self.factory = APIRequestFactory()
        self.url = "/api/v0/"
