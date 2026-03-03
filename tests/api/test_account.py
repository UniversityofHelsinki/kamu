"""
API tests for accounts.
"""

from rest_framework import status

from tests.setup import BaseAPITestCase


class AccountAPITests(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.create_identity()
        self.url = f"{self.url}accounts/"
        self.account = self.create_account(self.identity, uid="testuser")

    def test_list_without_permission(self):
        self.create_user()
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list(self):
        self.create_superuser()
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["uid"], "testuser")

    def test_create(self):
        self.create_superuser()
        self.client.force_authenticate(user=self.superuser)
        response = self.client.post(self.url, {"identity": self.identity.pk, "uid": "newuser", "type": "account"})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["uid"], "newuser")
        self.assertEqual(response.data["type"], "account")
