import datetime

from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from role.models import Membership, Role
from tests.setup import BaseTestCase


class RoleAPITests(BaseTestCase):
    def test_anonymous_list_roles(self):
        client = APIClient()
        client.force_authenticate(None)
        response = client.get(f"{self.url}roles/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_roles(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.get(f"{self.url}roles/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)


class PermissionAPITests(BaseTestCase):
    def test_anonymous_list_permissions(self):
        client = APIClient()
        client.force_authenticate(None)
        response = client.get(f"{self.url}permissions/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_permissions(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.get(f"{self.url}permissions/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)


class MembershipAPITests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = f"{self.url}memberships/"
        self.membership = Membership.objects.create(
            role=self.role,
            identity=self.identity,
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        self.super_membership = Membership.objects.create(
            role=self.role,
            identity=self.superidentity,
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        self.new_role = Role.objects.create(name="newrole", maximum_duration=10)

    def test_anonymous_list_membership(self):
        client = APIClient()
        client.force_authenticate(None)
        response = client.get(f"{self.url}")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_membership(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.get(f"{self.url}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_list_membership_superuser(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        response = client.get(f"{self.url}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_create_membership(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.post(
            f"{self.url}",
            {
                "role": self.new_role.id,
                "identity": self.identity.id,
                "start_date": timezone.now().date(),
                "expire_date": timezone.now().date() + datetime.timedelta(days=10),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_membership_invalid_date(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.post(
            f"{self.url}",
            {
                "role": self.new_role.id,
                "identity": self.identity.id,
                "start_date": timezone.now().date(),
                "expire_date": timezone.now().date() + datetime.timedelta(days=-1),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(response.data["non_field_errors"][0], "Start date cannot be later than expire date")

    def test_create_membership_invalid_duration(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.post(
            f"{self.url}",
            {
                "role": self.new_role.id,
                "identity": self.identity.id,
                "start_date": timezone.now().date(),
                "expire_date": timezone.now().date() + datetime.timedelta(days=self.new_role.maximum_duration + 1),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(response.data["non_field_errors"][0], "Role duration cannot be more than maximum duration")
