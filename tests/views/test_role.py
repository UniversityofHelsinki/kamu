"""
View tests for roles.
"""

from unittest import mock

from django.contrib.auth.models import Group, Permission
from django.test import Client, override_settings

from kamu.utils.auth import set_default_permissions
from kamu.views.role import RoleListApproverView, RoleListInviterView, RoleListOwnerView
from tests.setup import BaseTestCase
from tests.utils import MockLdapConn


class RoleListTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_user()
        self.url = "/role/"
        self.role = self.create_role()
        self.another_role = self.create_role("consultant")
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
        request = self.factory.get(f"{self.url}inviter/?search={self.another_role.name()[:-1]}")
        request.user = self.user
        response = RoleListInviterView.as_view()(request)
        self.assertEqual(response.context_data["object_list"].count(), 1)

    def test_view_role_search(self):
        set_default_permissions(self.user)
        url = f"{self.url}search/?search={self.another_role.name()[:-1]}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.another_role.name(), response.content.decode("utf-8"))
        self.assertNotIn(self.role.name(), response.content.decode("utf-8"))

    def test_view_role_filter_permission(self):
        set_default_permissions(self.user)
        permission = self.create_permission()
        self.role.permissions.add(permission)
        url = f"{self.url}search/?permission={permission.pk}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.role.name(), response.content.decode("utf-8"))
        self.assertNotIn(self.another_role.name(), response.content.decode("utf-8"))
        # Filter with permission and search term
        url = f"{self.url}search/?search={self.another_role.name()[:-1]}&permission={permission.pk}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.role.name(), response.content.decode("utf-8"))
        self.assertNotIn(self.another_role.name(), response.content.decode("utf-8"))

    def test_view_role_search_without_permission(self):
        set_default_permissions(self.user, remove=True)
        url = f"{self.url}search/?search=anoth"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)


class RoleViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_user()
        self.role = self.create_role()
        self.url = "/role/"
        self.client = Client()
        self.client.force_login(self.user)

    def test_show_role(self):
        permission = self.create_permission()
        self.role.permissions.add(permission)
        requirement = self.create_requirement()
        permission.requirements.add(requirement)
        url = f"{self.url}{self.role.pk}/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.role.name(), response.content.decode("utf-8"))
        self.assertIn(permission.name(), response.content.decode("utf-8"))
        self.assertIn(requirement.name(), response.content.decode("utf-8"))

    def test_show_role_list(self):
        self.create_superidentity()
        self.create_membership(self.role, self.superidentity)
        group = Group.objects.create(name="ApproverGroup")
        self.role.approvers.add(group)
        self.user.groups.add(group)
        url = f"{self.url}{self.role.pk}/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.superidentity.display_name(), response.content.decode("utf-8"))

    def test_restrict_role_list_to_role_managers(self):
        self.create_superidentity()
        self.create_membership(self.role, self.superidentity)
        url = f"{self.url}{self.role.pk}/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Superuser", response.content.decode("utf-8"))


class RoleGroupViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_user()
        self.role = self.create_role()
        self.group = Group.objects.create(name="ApproverGroup")
        self.role.approvers.add(self.group)
        self.url = f"/role/{self.role.pk}/group/{self.group.pk}/"
        self.client = Client()
        self.client.force_login(self.user)

    @override_settings(LDAP_SHOW_GROUP_MEMBER_LISTS=True)
    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_show_role_group(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)
        self.user.user_permissions.add(Permission.objects.get(codename="search_roles"))
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.group.name, response.content.decode("utf-8"))
        self.assertIn("Ldap User", response.content.decode("utf-8"))

    @override_settings(LDAP_SHOW_GROUP_MEMBER_LISTS=True)
    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_show_role_group_max_size(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn(size_exceeded=True)
        self.user.user_permissions.add(Permission.objects.get(codename="search_roles"))
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.group.name, response.content.decode("utf-8"))
        self.assertIn("This group has too many members to display", response.content.decode("utf-8"))
        self.assertNotIn("Ldap User", response.content.decode("utf-8"))

    @override_settings(LDAP_GROUP_MEMBERS_SEARCH_LIMIT=0)
    @override_settings(LDAP_SHOW_GROUP_MEMBER_LISTS=True)
    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_show_role_group_max_size_local(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn()
        self.user.user_permissions.add(Permission.objects.get(codename="search_roles"))
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("This group has too many members to display", response.content.decode("utf-8"))

    def test_show_role_group_no_ldap_membership_lists(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)
        self.user.user_permissions.add(Permission.objects.get(codename="search_roles"))
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)
