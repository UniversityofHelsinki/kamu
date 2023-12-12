"""
View tests for role app.
"""

import datetime

from django.contrib.auth.models import Group
from django.core import mail
from django.test import Client, override_settings
from django.utils import timezone

from role.models import Membership, Role
from role.views import RoleListView
from tests.setup import BaseTestCase


class RoleListTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/role/"
        self.another_role = Role.objects.create(identifier="another", name_en="Another Role", maximum_duration=10)
        self.client = Client()
        self.client.force_login(self.user)

    def test_anonymous_view_redirects_to_login(self):
        client = Client()
        response = client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["location"])

    def test_view_role_list(self):
        request = self.factory.get(self.url)
        request.user = self.user
        response = RoleListView.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["object_list"].count(), 2)

    def test_view_role_search(self):
        url = f"{self.url}search/?search=anoth"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Another Role", response.content.decode("utf-8"))
        self.assertNotIn("Test Role", response.content.decode("utf-8"))

    def test_view_role_list_approver(self):
        group = Group.objects.create(name="ApproverGroup")
        self.role.approvers.add(group)
        self.user.groups.add(group)
        url = f"{self.url}?filter=approver"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Role", response.content.decode("utf-8"))
        self.assertNotIn("Another Role", response.content.decode("utf-8"))


class RoleJoinTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/role/"
        self.client = Client()
        self.client.force_login(self.user)

    def _test_join_role(self, start_date_delta: int = 0, expire_date_delta: int = 0):
        url = f"{self.url}{self.role.pk}/join/"
        return self.client.post(
            url,
            {
                "start_date": timezone.now().date() + datetime.timedelta(days=start_date_delta),
                "expire_date": timezone.now().date() + datetime.timedelta(days=expire_date_delta),
                "reason": "Because",
            },
            follow=True,
        )

    def test_join_role(self):
        group = Group.objects.create(name="approver")
        self.user.groups.add(group)
        self.role.approvers.add(group)
        response = self._test_join_role(expire_date_delta=7)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Role membership", response.content.decode("utf-8"))
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))

    def test_join_role_without_approver_status(self):
        response = self._test_join_role()
        self.assertEqual(response.status_code, 403)

    def test_join_role_with_invalid_date(self):
        url = f"{self.url}{self.role.pk}/join/"
        response = self._test_join_role(start_date_delta=7)
        self.assertIn("Role expire date cannot be earlier than start date", response.content.decode("utf-8"))

    def test_join_role_with_too_long_duration(self):
        self.role.maximum_duration = 3
        self.role.save()
        response = self._test_join_role(expire_date_delta=4)
        self.assertIn("Role duration cannot be more than maximum duration", response.content.decode("utf-8"))


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


class RoleInviteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/role/1/invite/"
        self.client = Client()
        self.client.force_login(self.user)
        group = Group.objects.create(name="InviterGroup")
        self.role.inviters.add(group)
        self.user.groups.add(group)

    def test_search_user(self):
        url = f"{self.url}?given_names=test"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User", response.content.decode("utf-8"))
        self.assertIn("Select", response.content.decode("utf-8"))

    def test_search_not_found_email(self):
        url = f"{self.url}?email=nonexisting@example.org"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Email address not found", response.content.decode("utf-8"))

    def test_join_role_with_identity(self):
        url = f"{self.url}{self.identity.pk}/"
        response = self.client.post(
            url,
            {
                "start_date": timezone.now().date(),
                "expire_date": timezone.now().date() + datetime.timedelta(days=7),
                "reason": "Because",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Membership.objects.filter(role=self.role, identity=self.identity).exists())

    def test_join_role_send_email_invite(self):
        url = f"{self.url}email/"
        response = self.client.post(
            url,
            {
                "start_date": timezone.now().date(),
                "expire_date": timezone.now().date() + datetime.timedelta(days=7),
                "reason": "Because",
                "invite_email_address": "invite@example.org",
                "invite_language": "en",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            Membership.objects.filter(
                role=self.role, identity=None, invite_email_address="invite@example.org"
            ).exists()
        )
        self.assertIn("Your invite code is", mail.outbox[0].body)


class AdminSiteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/admin/role/"
        self.client = Client()
        self.client.force_login(user=self.superuser)
        self.role_data = {
            "identifier": "new_role",
            "name_en": "New Role",
            "name_fi": "New Role",
            "name_sv": "New Role",
            "description_en": "New Description",
            "description_fi": "New Description",
            "description_sv": "New Description",
            "organisation_unit": "Test unit",
            "reason": "Testing",
            "maximum_duration": 30,
            "created_at_0": timezone.now().date(),
            "created_at_1": timezone.now().time(),
        }

    def test_view_admin_role(self):
        response = self.client.get(f"{self.url}role/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Role", response.content.decode("utf-8"))

    def test_view_admin_membership(self):
        Membership.objects.create(
            role=self.role,
            identity=self.identity,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        response = self.client.get(f"{self.url}membership/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Role", response.content.decode("utf-8"))
        self.assertIn("Test User", response.content.decode("utf-8"))

    def test_view_admin_permission(self):
        response = self.client.get(f"{self.url}permission/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Permission", response.content.decode("utf-8"))

    def test_add_role(self):
        url = f"{self.url}role/add/"
        response = self.client.post(url, self.role_data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("New Role", response.content.decode("utf-8"))
        self.assertTrue(Role.objects.filter(identifier="new_role").exists())

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=3)
    def test_add_role_hierarchy_allowed_depth(self):
        url = f"{self.url}role/add/"
        sub_role = Role.objects.create(identifier="subrole", name_en="Sub Role", maximum_duration=10, parent=self.role)
        self.role_data["parent"] = sub_role.pk
        response = self.client.post(url, self.role_data)
        self.assertNotIn("Role hierarchy cannot be more than maximum depth.", response.content.decode("utf-8"))
        self.assertTrue(Role.objects.filter(identifier="new_role").exists())

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=2)
    def test_add_role_hierarchy_too_deep(self):
        url = f"{self.url}role/add/"
        sub_role = Role.objects.create(identifier="subrole", name_en="Sub Role", maximum_duration=10, parent=self.role)
        self.role_data["parent"] = sub_role.pk
        response = self.client.post(url, self.role_data)
        self.assertIn("Role hierarchy cannot be more than maximum depth", response.content.decode("utf-8"))
        self.assertFalse(Role.objects.filter(identifier="new_role").exists())
