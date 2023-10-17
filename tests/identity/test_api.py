from rest_framework import status
from rest_framework.test import APIClient

from tests.setup import BaseTestCase


class IdentityAPITests(BaseTestCase):
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
