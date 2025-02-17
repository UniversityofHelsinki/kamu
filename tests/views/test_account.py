"""
View tests for accounts.
"""

import secrets
import string
from unittest import mock
from unittest.mock import ANY, call

from django.test import Client, override_settings

from kamu.models.account import Account
from tests.setup import BaseTestCase


class AccountApiResponseMock:
    def __init__(self, status: int = 200, content: str = '{"uid": "1k234567"}'):
        self.status_code = status
        self.content = content


class AccountTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.role = self.create_role("consultant")
        self.permission = self.create_permission("lightaccount")
        self.permission_service = self.create_permission("service")
        self.role.permissions.add(self.permission)
        self.role.permissions.add(self.permission_service)
        self.identity = self.create_identity(user=True, email=True)
        self.membership = self.create_membership(
            self.role, self.identity, start_delta_days=-2, expire_delta_days=1, approver=self.identity.user
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_view_account_list(self):
        response = self.client.get(f"/identity/{self.identity.pk}/account/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("You do not have any accounts", response.content.decode("utf-8"))
        self.assertIn("Light Account", response.content.decode("utf-8"))

    def test_view_account_list_with_account(self):
        self.create_account()
        response = self.client.get(f"/identity/{self.identity.pk}/account/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Manage account", response.content.decode("utf-8"))

    def test_view_account_list_external_link(self):
        self.permission_account = self.create_permission("account")
        self.role.permissions.add(self.permission_account)
        response = self.client.get(f"/identity/{self.identity.pk}/account/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Manage in external service", response.content.decode("utf-8"))

    def test_view_account_create_view(self):
        response = self.client.get(f"/identity/{self.identity.pk}/account/lightaccount/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Account will be created with the following information", response.content.decode("utf-8"))
        self.assertIn("Service 1", response.content.decode("utf-8"))

    @mock.patch("kamu.connectors.account.AccountApiConnector.get_uid_choices")
    @override_settings(ALLOW_TEST_FPIC=True)
    def test_account_choice_exclusions(self, mock_connector_get):
        mock_connector_get.return_value = ["1k234567"]
        self.identity.fpic = "010181-900C"
        self.identity.save()
        response = self.client.get(f"/identity/{self.identity.pk}/account/lightaccount/", follow=True)
        self.assertEqual(response.status_code, 200)
        mock_connector_get.assert_called_with(number=5, exclude_chars=" .cemrstu", exclude_string="900")

    def test_view_account_create_invalid_password(self):
        data = {
            "password": "password",
            "confirm_password": "password",
        }
        response = self.client.post(f"/identity/{self.identity.pk}/account/lightaccount/", data)
        self.assertIn("This password is too short.", response.content.decode("utf-8"))
        self.assertIn("This password is too common.", response.content.decode("utf-8"))
        self.assertIn("Minimum 15 characters", response.content.decode("utf-8"))

    @mock.patch("kamu.connectors.account.AccountApiConnector.api_call_get")
    @mock.patch("kamu.connectors.account.AccountApiConnector.api_call_post")
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_account_create(self, mock_logger, mock_connector_post, mock_connector_get):
        mock_connector_post.return_value = AccountApiResponseMock()
        mock_connector_get.return_value = AccountApiResponseMock(content='["1k234567", "2k234567"]')

        password = "".join(secrets.choice(string.ascii_letters) for _ in range(20))
        data = {
            "uid": "1k234567",
            "password": password,
            "confirm_password": password,
        }
        response = self.client.post(f"/identity/{self.identity.pk}/account/lightaccount/", data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Account created", response.content.decode("utf-8"))
        self.assertTrue(Account.objects.filter(identity=self.identity).exists())
        mock_logger.log.assert_has_calls(
            [
                call(20, "Account created: 1k234567", extra=ANY),
            ]
        )

    @mock.patch("kamu.connectors.account.AccountApiConnector.api_call_get")
    @mock.patch("kamu.connectors.account.AccountApiConnector.api_call_post")
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_account_api_failure(self, mock_logger, mock_connector_post, mock_connector_get):
        mock_connector_post.return_value = AccountApiResponseMock(status=500)
        mock_connector_get.return_value = AccountApiResponseMock(content='["uid1", "uid2"]')
        password = "".join(secrets.choice(string.ascii_letters) for _ in range(20))
        data = {
            "uid": "uid1",
            "password": password,
            "confirm_password": password,
        }
        response = self.client.post(f"/identity/{self.identity.pk}/account/lightaccount/", data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Account creation failed, please try again later", response.content.decode("utf-8"))
        self.assertFalse(Account.objects.filter(identity=self.identity).exists())
        mock_logger.log.assert_has_calls(
            [
                call(30, "Account of type lightaccount creation failed: API error, status 500", extra=ANY),
            ]
        )

    @mock.patch("kamu.connectors.account.AccountApiConnector.api_call_post")
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_account_disable_status(self, mock_logger, mock_connector):
        mock_connector.return_value = AccountApiResponseMock()
        account = self.create_account()
        data = {"disable_account": True}
        response = self.client.post(f"/account/{account.pk}/", data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Account disabled", response.content.decode("utf-8"))
        account.refresh_from_db()
        self.assertEqual(account.status, Account.Status.DISABLED)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Account disabled: 1k234567", extra=ANY),
                call(20, "Read account information", extra=ANY),
            ]
        )

    @mock.patch("kamu.connectors.account.AccountApiConnector.api_call_post")
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_account_enable_status(self, mock_logger, mock_connector):
        mock_connector.return_value = AccountApiResponseMock()
        account = self.create_account(status=Account.Status.DISABLED)
        data = {"enable_account": True}
        response = self.client.post(f"/account/{account.pk}/", data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Account enabled", response.content.decode("utf-8"))
        account.refresh_from_db()
        self.assertEqual(account.status, Account.Status.ENABLED)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Account enabled: 1k234567", extra=ANY),
                call(20, "Read account information", extra=ANY),
            ]
        )

    @mock.patch("kamu.connectors.account.AccountApiConnector.api_call_post")
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_view_account_reset_password(self, mock_logger, mock_connector):
        mock_connector.return_value = AccountApiResponseMock()
        account = self.create_account()
        password = "".join(secrets.choice(string.ascii_letters) for _ in range(20))
        data = {
            "password": password,
            "confirm_password": password,
        }
        response = self.client.post(f"/account/{account.pk}/", data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Password reset", response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Password reset: 1k234567", extra=ANY),
                call(20, "Read account information", extra=ANY),
            ]
        )

    def test_view_account_update(self):
        account = self.create_account()
        self.identity.given_name_display = "Updated"
        self.identity.save()
        self.assertEqual(account.accountsynchronization_set.all().count(), 1)
        self.identity.save()
        self.assertEqual(account.accountsynchronization_set.all().count(), 2)
