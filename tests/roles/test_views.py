import datetime

from django.contrib.auth.models import Group
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

    def test_join_role(self):
        url = f"{self.url}{self.role.pk}/join/"
        response = self.client.post(
            url, {"start_date": "2020-01-01", "expire_date": "2020-01-08", "reason": "Because"}, follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Role membership", response.content.decode("utf-8"))
        self.assertIn(self.identity.name, response.content.decode("utf-8"))

    def test_join_role_with_invalid_date(self):
        url = f"{self.url}{self.role.pk}/join/"
        response = self.client.post(
            url, {"start_date": "2020-01-11", "expire_date": "2020-01-01", "reason": "Because"}, follow=True
        )
        self.assertIn("Start date cannot be later than expire date", response.content.decode("utf-8"))

    def test_join_role_with_too_long_duration(self):
        url = f"{self.url}{self.role.pk}/join/"
        self.role.maximum_duration = 3
        self.role.save()
        response = self.client.post(
            url, {"start_date": "2020-01-01", "expire_date": "2020-01-05", "reason": "Because"}, follow=True
        )
        self.assertIn("Role duration cannot be more than maximum duration", response.content.decode("utf-8"))


class RoleViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/role/"
        self.client = Client()
        self.client.force_login(self.user)
        self.role_data = {
            "identifier": "addrole",
            "name_en": "Add Role",
            "name_fi": "Add Role",
            "name_sv": "Add Role",
            "description_en": "Adding Role",
            "description_fi": "Adding Role",
            "description_sv": "Adding Role",
            "organisation_unit": "Test unit",
            "reason": "Testing",
            "maximum_duration": 30,
        }

    def test_show_role(self):
        url = f"{self.url}{self.role.pk}/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test Role", response.content.decode("utf-8"))

    def test_add_role(self):
        url = f"{self.url}add/"
        response = self.client.post(url, self.role_data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("New role created.", response.content.decode("utf-8"))
        self.assertIn("Role: Add Role", response.content.decode("utf-8"))

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=3)
    def test_add_role_hierarchy_allowed_depth(self):
        url = f"{self.url}add/"
        sub_role = Role.objects.create(identifier="subrole", name_en="Sub Role", maximum_duration=10, parent=self.role)
        self.role_data["parent"] = sub_role.pk
        response = self.client.post(url, self.role_data)
        self.assertNotIn("Role hierarchy cannot be more than maximum depth.", response.content.decode("utf-8"))

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=2)
    def test_add_role_hierarchy_too_deep(self):
        url = f"{self.url}add/"
        sub_role = Role.objects.create(identifier="subrole", name_en="Sub Role", maximum_duration=10, parent=self.role)
        self.role_data["parent"] = sub_role.pk
        response = self.client.post(url, self.role_data)
        self.assertIn("Role hierarchy cannot be more than maximum depth", response.content.decode("utf-8"))


class AdminSiteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/admin/role/"
        self.client = Client()
        self.client.force_login(user=self.superuser)

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
