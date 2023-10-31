import datetime

from django.test import Client
from django.utils import timezone

from role.models import Membership, Role
from role.views import RoleListView
from tests.setup import BaseTestCase


class RoleTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/roles/"

    def test_anonymous_view_redirects_to_login(self):
        client = Client()
        response = client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["location"])

    def test_view_role_list_without_roles(self):
        request = self.factory.get(self.url)
        request.user = self.user
        response = RoleListView.as_view()(request)
        self.assertEqual(response.status_code, 200)

    def test_add_role(self):
        url = "/role/add/"
        client = Client()
        client.force_login(self.user)
        response = client.post(url, {"identifier": "addrole", "name_en": "Add Role", "maximum_duration": 30})
        role_pk = Role.objects.last().pk
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/roles/{role_pk}/", response["location"])

    def test_join_role(self):
        url = f"/role/{self.role.pk}/join/"
        client = Client()
        client.force_login(self.user)
        response = client.post(
            url, {"start_date": "2020-01-01", "expire_date": "2020-01-08", "reason": "Because"}, follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Role membership", response.content.decode("utf-8"))
        self.assertIn(self.identity.name, response.content.decode("utf-8"))

    def test_join_role_with_invalid_date(self):
        url = f"/role/{self.role.pk}/join/"
        client = Client()
        client.force_login(self.user)
        response = client.post(
            url, {"start_date": "2020-01-11", "expire_date": "2020-01-01", "reason": "Because"}, follow=True
        )
        self.assertIn("Start date cannot be later than expire date", response.content.decode("utf-8"))

    def test_join_role_with_too_long_duration(self):
        self.role.maximum_duration = 3
        self.role.save()
        url = f"/role/{self.role.pk}/join/"
        client = Client()
        client.force_login(self.user)
        response = client.post(
            url, {"start_date": "2020-01-01", "expire_date": "2020-01-05", "reason": "Because"}, follow=True
        )
        self.assertIn("Role duration cannot be more than maximum duration", response.content.decode("utf-8"))


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
