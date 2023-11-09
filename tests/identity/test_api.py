"""
API tests for identity app.
"""

from rest_framework import status
from rest_framework.test import APIClient

from identity.models import Attribute, AttributeType
from tests.setup import BaseAPITestCase


class IdentityAPITests(BaseAPITestCase):
    def test_anonymous_list_identities(self):
        client = APIClient()
        client.force_authenticate(None)
        response = client.get(f"{self.url}identities/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_identities(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.get(f"{self.url}identities/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_list_identities_superuser(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        response = client.get(f"{self.url}identities/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)


class AttributeAPITests(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.attribute_type_multi_value = AttributeType.objects.create(
            identifier="multi_value", name_en="Multi-value attribute", multi_value=True, regex_pattern="^[a-z]*$"
        )
        self.attribute_type_unique = AttributeType.objects.create(
            identifier="unique", name_en="Unique attribute", unique=True, regex_pattern="^[a-z]*$"
        )
        self.url = f"{self.url}attributes/"
        self.data = {
            "identity": self.identity.pk,
            "attribute_type": self.attribute_type_multi_value.pk,
            "value": "test",
            "source": "testsource",
        }

    def test_create_attribute(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_update_attribute(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        data = {"value": "testnew"}
        response = client.patch(f"{self.url}{self.attribute.pk}/", data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create_attribute_missing_value(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        self.data.pop("attribute_type")
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("This field is required", response.data["attribute_type"][0])

    def test_create_attribute_incorrect_value(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        self.data["value"] = "["
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("does not match validation pattern", response.data["non_field_errors"][0])

    def test_create_existing_attribute(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        self.data["attribute_type"] = self.attribute_type_first_name.pk
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("already exists for this identity", response.data["non_field_errors"][0])

    def test_create_attribute_duplicate_unique(self):
        Attribute.objects.create(identity=self.superidentity, attribute_type=self.attribute_type_unique, value="test")
        client = APIClient()
        client.force_authenticate(user=self.user)
        self.data["attribute_type"] = self.attribute_type_unique.pk
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("with value test already exists", response.data["non_field_errors"][0])

    def test_modify_unique_attribute(self):
        unique_attribute = Attribute.objects.create(
            identity=self.superidentity, attribute_type=self.attribute_type_unique, value="test", source="testsource"
        )
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        data = {"source": "newsource"}
        response = client.patch(f"{self.url}{unique_attribute.pk}/", data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class AttributeTypeAPITests(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.url = f"{self.url}attributetypes/"
        self.data = {
            "identifier": "testattributetype",
            "name_fi": "fi",
            "name_en": "en",
            "name_sv": "sv",
            "description_fi": "descfi",
            "description_en": "descen",
            "description_sv": "descsv",
            "regex_pattern": ".*",
        }

    def test_create_attribute_type(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_attribute_type_incorrect_regex(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        self.data["regex_pattern"] = "["
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid regex pattern", response.data["regex_pattern"])
