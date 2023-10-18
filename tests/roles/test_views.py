from django.contrib.auth.models import User
from django.test import Client, RequestFactory, TestCase

from identity.models import Identity
from role.models import Role
from role.views import RoleListView


class RoleTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username="testuser", first_name="Test", last_name="User", password="test_pass"
        )
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
        response = client.post(url, {"name": "testrole", "maximum_duration": 30})
        role_pk = Role.objects.last().pk
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"/roles/{role_pk}/", response["location"])

    def test_join_role_without_identity(self):
        url = "/role/1/join/"
        Role.objects.create(name="testrole", maximum_duration=365)
        client = Client()
        client.force_login(self.user)
        response = client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_join_role(self):
        role = Role.objects.create(name="testrole", maximum_duration=365)
        url = f"/role/{role.pk}/join/"
        identity = Identity.objects.create(user=self.user)
        client = Client()
        client.force_login(self.user)
        response = client.post(url, {"start_date": "2020-01-01", "expire_date": "2020-12-31"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Role membership", response.content.decode("utf-8"))
        self.assertIn(identity.user.get_full_name(), response.content.decode("utf-8"))

    def test_join_role_with_invalid_date(self):
        role = Role.objects.create(name="testrole", maximum_duration=365)
        url = f"/role/{role.pk}/join/"
        Identity.objects.create(user=self.user)
        client = Client()
        client.force_login(self.user)
        response = client.post(url, {"start_date": "2020-01-11", "expire_date": "2020-01-01"}, follow=True)
        self.assertIn("Start date cannot be later than expire date", response.content.decode("utf-8"))

    def test_join_role_with_too_long_duration(self):
        role = Role.objects.create(name="testrole", maximum_duration=3)
        url = f"/role/{role.pk}/join/"
        Identity.objects.create(user=self.user)
        client = Client()
        client.force_login(self.user)
        response = client.post(url, {"start_date": "2020-01-01", "expire_date": "2020-01-05"}, follow=True)
        self.assertIn("Role duration cannot be more than maximum duration", response.content.decode("utf-8"))
