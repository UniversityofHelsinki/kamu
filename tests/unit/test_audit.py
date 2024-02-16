"""
Unit tests for audit logs
"""

from unittest.mock import patch

from django.contrib.admin.models import LogEntry
from django.test import RequestFactory, TestCase, override_settings

from kamu.utils.audit import AuditLog, get_client_ip
from tests.setup import BaseTestCase

audit_log = AuditLog()


class GetIPChecks(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.request = self.factory.get("/")
        self.request.META = {"REMOTE_ADDR": "10.1.2.3", "HTTP_X_FORWARDED_FOR": "10.0.0.1, 10.0.0.2"}

    def test_ip_without_forwarding_header(self):
        self.request.META = {"REMOTE_ADDR": "10.1.2.3"}
        response = get_client_ip(self.request)
        self.assertEqual(response, "10.1.2.3")

    def test_ip_forwarding(self):
        response = get_client_ip(self.request)
        self.assertEqual(response, "10.0.0.1")

    @override_settings(HTTP_FORWARDING_IP_FIRST=False)
    def test_ip_forwarding_get_last(self):
        response = get_client_ip(self.request)
        self.assertEqual(response, "10.0.0.2")

    @override_settings(HTTP_CHECK_FORWARDING_HEADER=False)
    def test_ip_no_forwarding_check(self):
        response = get_client_ip(self.request)
        self.assertEqual(response, "10.1.2.3")


class AuditLogTests(BaseTestCase):
    @patch("kamu.utils.audit.logger")
    @patch("kamu.utils.audit.logger_audit.log")
    def test_logging(self, mock_audit_logger, mock_logger):
        audit_log.info("TestMsg", category="role", action="info", objects=[self.identity])
        mock_audit_logger.assert_called_with(
            20,
            "TestMsg",
            extra={
                "category": "role",
                "action": "info",
                "outcome": "none",
                "identity": "Test User",
                "identity_id": self.identity.pk,
                "user": "testuser",
                "user_id": self.user.pk,
            },
        )

    @patch("kamu.utils.audit.logger")
    @patch("kamu.utils.audit.logger_audit.log")
    def test_logging_request(self, mock_audit_logger, mock_logger):
        headers = {"REMOTE_ADDR": "10.1.2.3", "HTTP_USER_AGENT": "TestAgent"}
        request = self.factory.get("/", **headers)
        request.user = self.superuser
        audit_log.debug(
            "TestMsg",
            category="identity",
            action="info",
            outcome="success",
            request=request,
            objects=[self.user],
            extra={"test": "test"},
            log_to_db=True,
        )
        mock_audit_logger.assert_called_with(
            10,
            "TestMsg",
            extra={
                "category": "identity",
                "action": "info",
                "outcome": "success",
                "identity": "Test User",
                "identity_id": self.identity.pk,
                "user": "testuser",
                "user_id": self.user.pk,
                "ip": "10.1.2.3",
                "user_agent": "TestAgent",
                "actor": "admin",
                "actor_id": self.superuser.pk,
                "test": "test",
            },
        )
        self.assertEqual(LogEntry.objects.filter(change_message="TestMsg").count(), 1)
        mock_logger.warning.assert_not_called()
