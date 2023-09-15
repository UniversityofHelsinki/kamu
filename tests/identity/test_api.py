from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory, APITestCase

from identity.models import Identity
from identity.views import IdentityView


class IdentityAPITests(APITestCase):
    def setUp(self):
        self.url = "/api/v0/identities/"
        self.view = IdentityView.as_view()
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(username="testuser", password="test_pass")
        self.superuser = User.objects.create_user(username="admin", password="test_pass", is_superuser=True)
        self.identity = Identity.objects.create(user=self.user)
        self.superidentity = Identity.objects.create(user=self.superuser)

    def test_anonymous_list_identities(self):
        client = APIClient()
        client.force_authenticate(None)
        response = client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_identities(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_list_identities_superuser(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        response = client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
