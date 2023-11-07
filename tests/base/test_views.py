from django.test import Client

from tests.setup import BaseTestCase


class LoginViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()

    def test_login_redirect(self):
        url = "/login/?next=/identity/1/"
        response = self.client.post(
            url,
            {"username": "testuser", "password": "test_pass"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Identity: Test User", response.content.decode("utf-8"))
