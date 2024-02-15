"""
API tests for identity app.
"""

from django.test import override_settings
from rest_framework import status
from rest_framework.test import APIClient

from kamu.models.identity import Contract, ContractTemplate
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
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_identity(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.get(f"{self.url}identities/1/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_identities_superuser(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        response = client.get(f"{self.url}identities/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    @override_settings(ALLOW_TEST_FPIC=True)
    def test_update_identity_supseruser(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        data = {"name": "New Name", "fpic": "010181-900C"}
        response = client.patch(f"{self.url}identities/1/", data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_settings(ALLOW_TEST_FPIC=False)
    def test_update_identity_supseruser_incorrect_fpic(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        data = {"name": "New Name", "fpic": "010181-900C"}
        response = client.patch(f"{self.url}identities/1/", data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Incorrect numeric part", response.data["fpic"][0])


class EmailAddressAPITests(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.url = f"{self.url}emailaddresses/"
        self.data = {
            "identity": self.identity.pk,
            "address": "new.email@example.org",
        }

    def test_create_email(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_update_email(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        data = {"address": "updated.email@example.org"}
        response = client.patch(f"{self.url}{self.email_address.pk}/", data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create_email_missing_address(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        self.data.pop("address")
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("This field is required", response.data["address"][0])

    def test_create_email_incorrect_address(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        self.data["address"] = "incorrect_email"
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Enter a valid email address", response.data["address"][0])

    def test_create_email_duplicate(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        self.data["address"] = self.email_address.address
        response = client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("identity already has the given email address", response.data["non_field_errors"][0])


class ContractAPITestCase(BaseAPITestCase):
    """
    APITestCase class with contract test data.
    """

    def setUp(self):
        super().setUp()
        self.contract_template = ContractTemplate.objects.create(
            type="testtemplate",
            version=1,
            name_en="Test Contract en",
            name_fi="Test Contract fi",
            name_sv="Test Contract sv",
            text_en="Test Content en",
            text_fi="Test Content fi",
            text_sv="Test Content sv",
        )


class ContractTemplateAPITests(ContractAPITestCase):
    def setUp(self):
        super().setUp()
        self.url = f"{self.url}contracttemplates/"
        self.data = {
            "type": "newtemplate",
            "version": 1,
            "name_en": "Test Contract en",
            "name_fi": "Test Contract fi",
            "name_sv": "Test Contract sv",
            "text_en": "Test Content en",
            "text_fi": "Test Content fi",
            "text_sv": "Test Content sv",
        }
        self.client = APIClient()

    def test_list_without_permission(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(self.url)
        self.assertEqual(len(response.data), 1)

    def test_create_without_permission(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)


class ContractAPITests(ContractAPITestCase):
    def setUp(self):
        super().setUp()
        self.url = f"{self.url}contracts/"
        Contract.objects.sign_contract(self.contract_template, self.identity)

    def test_list_without_permission(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(self.url)
        self.assertEqual(len(response.data), 1)

    def test_create(self):
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(self.url, {"template": self.contract_template.pk, "identity": self.identity.pk})
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
