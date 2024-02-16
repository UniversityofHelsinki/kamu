"""
View tests for roles.
"""

import datetime

from django.contrib.auth.models import Group
from django.test import Client
from django.utils import timezone

from kamu.models.membership import Membership
from kamu.models.role import Role
from kamu.utils.auth import set_default_permissions
from kamu.views.role import RoleListApproverView, RoleListInviterView, RoleListOwnerView
from tests.setup import BaseTestCase


class RoleListTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/role/"
        self.another_role = Role.objects.create(identifier="another", name_en="Another Role", maximum_duration=10)
        self.group = Group.objects.create(name="group")
        self.client = Client()
        self.client.force_login(self.user)

    def test_anonymous_view_redirects_to_login(self):
        client = Client()
        response = client.get(f"{self.url}owner/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["location"])

    def test_view_role_owner_list(self):
        request = self.factory.get(f"{self.url}owner/")
        request.user = self.user
        self.role.owner = self.user
        self.role.save()
        response = RoleListOwnerView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["object_list"].count(), 1)

    def test_view_role_approver_list(self):
        request = self.factory.get(f"{self.url}approver/")
        request.user = self.user
        self.role.approvers.add(self.group)
        self.user.groups.add(self.group)
        response = RoleListApproverView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["object_list"].count(), 1)

    def test_view_role_inviter_list(self):
        request = self.factory.get(f"{self.url}inviter/")
        request.user = self.user
        self.role.approvers.add(self.group)
        self.another_role.inviters.add(self.group)
        self.user.groups.add(self.group)
        response = RoleListInviterView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["object_list"].count(), 2)

    def test_view_role_search(self):
        set_default_permissions(self.user)
        url = f"{self.url}search/?search=anoth"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Another Role", response.content.decode("utf-8"))
        self.assertNotIn("Test Role", response.content.decode("utf-8"))

    def test_view_role_search_without_permission(self):
        set_default_permissions(self.user, remove=True)
        url = f"{self.url}search/?search=anoth"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)


class RoleViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/role/"
        self.client = Client()
        self.client.force_login(self.user)

    def test_show_role(self):
        url = f"{self.url}{self.role.pk}/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Role", response.content.decode("utf-8"))

    def test_show_role_list(self):
        Membership.objects.create(
            role=self.role,
            identity=self.superidentity,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        group = Group.objects.create(name="ApproverGroup")
        self.role.approvers.add(group)
        self.user.groups.add(group)
        url = f"{self.url}{self.role.pk}/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Super User", response.content.decode("utf-8"))

    def test_restrict_role_list_to_role_managers(self):
        Membership.objects.create(
            role=self.role,
            identity=self.superidentity,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        url = f"{self.url}{self.role.pk}/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Superuser", response.content.decode("utf-8"))
