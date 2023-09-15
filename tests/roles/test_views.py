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
        response = client.post(url, {"name": "testrole"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/roles/1/", response["location"])

    def test_join_role_without_identity(self):
        url = "/role/1/join/"
        Role.objects.create(name="testrole")
        client = Client()
        client.force_login(self.user)
        response = client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_join_role(self):
        url = "/role/1/join/"
        identity = Identity.objects.create(user=self.user)
        Role.objects.create(name="testrole")
        client = Client()
        client.force_login(self.user)
        response = client.post(url, {"start_date": "2020-01-01", "expiring_date": "2020-12-31"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Role membership", response.content.decode("utf-8"))
        self.assertIn(identity.user.get_full_name(), response.content.decode("utf-8"))
