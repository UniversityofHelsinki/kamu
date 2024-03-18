"""
API tests for role app.
"""

import datetime

from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from kamu.models.role import Role
from tests.setup import BaseAPITestCase


class RoleAPITests(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.role = self.create_role()
        self.client = APIClient()

    def test_anonymous_list_roles(self):
        self.client.force_authenticate(None)
        response = self.client.get(f"{self.url}roles/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_roles_without_permission(self):
        self.create_user()
        self.client.force_authenticate(user=self.user)
        response = self.client.get(f"{self.url}roles/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_roles(self):
        self.create_superuser()
        self.client.force_authenticate(user=self.superuser)
        response = self.client.get(f"{self.url}roles/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_change_role_circular_hierarchy(self):
        self.create_superuser()
        self.client.force_authenticate(user=self.superuser)
        sub_role = self.create_role("ext_research", parent=self.role)
        data = {"parent": sub_role.identifier}
        response = self.client.patch(f"{self.url}roles/{self.role.pk}/", data)
        self.assertIn(response.data["parent"][0], "Role cannot be in its own hierarchy")


class PermissionAPITests(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.role = self.create_role()
        self.client = APIClient()
        self.create_permission()

    def test_anonymous_list_permissions(self):
        self.create_user()
        client = APIClient()
        client.force_authenticate(None)
        response = client.get(f"{self.url}permissions/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_permissions_without_access(self):
        self.create_user()
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.get(f"{self.url}permissions/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_permissions(self):
        self.create_superuser()
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        response = client.get(f"{self.url}permissions/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)


class MembershipAPITests(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.url = f"{self.url}memberships/"
        self.role = self.create_role()
        self.create_identity(user=True)
        self.create_superidentity(user=True)
        self.membership = self.create_membership(self.role, self.identity, start_delta_days=0, expire_delta_days=1)
        self.super_membership = self.create_membership(
            self.role, self.superidentity, start_delta_days=0, expire_delta_days=1
        )
        self.new_role = Role.objects.create(identifier="newrole", name_en="New Role", maximum_duration=10)

    def test_anonymous_list_membership(self):
        client = APIClient()
        client.force_authenticate(None)
        response = client.get(f"{self.url}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_membership_without_access(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.get(f"{self.url}")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_membership_superuser(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        response = client.get(f"{self.url}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_create_membership(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        response = client.post(
            f"{self.url}",
            {
                "role": self.new_role.id,
                "identity": self.identity.id,
                "reason": "Because",
                "start_date": timezone.now().date(),
                "expire_date": timezone.now().date() + datetime.timedelta(days=10),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_membership_invalid_date(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        response = client.post(
            f"{self.url}",
            {
                "role": self.new_role.id,
                "identity": self.identity.id,
                "reason": "Because",
                "start_date": timezone.now().date(),
                "expire_date": timezone.now().date() + datetime.timedelta(days=-1),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(response.data["expire_date"][0], "Role expire date cannot be earlier than start date")

    def test_create_membership_invalid_duration(self):
        client = APIClient()
        client.force_authenticate(user=self.superuser)
        response = client.post(
            f"{self.url}",
            {
                "role": self.new_role.id,
                "identity": self.identity.id,
                "reason": "Because",
                "start_date": timezone.now().date(),
                "expire_date": timezone.now().date() + datetime.timedelta(days=self.new_role.maximum_duration + 1),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(
            response.data["expire_date"][0],
            "Maximum membership duration for this role is 10 days. Last possible date for this membership is "
            + (timezone.now().date() + datetime.timedelta(days=self.new_role.maximum_duration)).strftime("%m/%d/%Y")
            + ".",
        )
