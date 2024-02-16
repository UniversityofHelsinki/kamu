"""
View tests for memberships and invites.
"""

import datetime
from unittest import mock
from unittest.mock import ANY, call, patch

from django.conf import settings
from django.contrib.auth.models import Group
from django.core import mail
from django.test import Client, override_settings
from django.utils import timezone

from kamu.models.identity import Identifier, Identity
from kamu.models.membership import Membership
from kamu.utils.auth import set_default_permissions
from tests.setup import BaseTestCase
from tests.utils import MockLdapConn


class MembershipViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.membership = Membership.objects.create(
            role=self.role,
            identity=self.identity,
            invite_email_address="invited_user@example.org",
            inviter=self.superuser,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        self.url = f"/membership/{ self.membership.pk }/"
        self.group = Group.objects.create(name="group")
        self.role.inviters.add(self.group)
        self.user.groups.add(self.group)
        self.client = Client()
        self.client.force_login(self.user)

    def test_show_membership(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Membership details", response.content.decode("utf-8"))
        self.assertIn(self.role.name(), response.content.decode("utf-8"))
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))
        self.assertNotIn("invited_user@example.org", response.content.decode("utf-8"))
        self.assertNotIn("Approval required", response.content.decode("utf-8"))

    def test_show_membership_without_linked_identity(self):
        self.membership.identity = None
        self.membership.save()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Membership details", response.content.decode("utf-8"))
        self.assertIn("invited_user@example.org", response.content.decode("utf-8"))
        self.assertIn("Resend invite email", response.content.decode("utf-8"))

    def test_resend_membership_invite(self):
        self.membership.identity = None
        self.membership.save()
        response = self.client.post(self.url, {"resend_invite": "resend"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invite email sent", response.content.decode("utf-8"))
        self.assertIn("Your invite code is", mail.outbox[0].body)
        response = self.client.post(self.url, {"resend_invite": "resend"}, follow=True)
        self.assertIn("Tried to send a new invite too soon", response.content.decode("utf-8"))

    def test_show_membership_approval_info(self):
        self.role.approvers.add(self.group)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Approval required", response.content.decode("utf-8"))
        self.assertIn("Update membership", response.content.decode("utf-8"))

    def test_approve_membership(self):
        self.role.approvers.add(self.group)
        response = self.client.post(self.url, {"approve_membership": "approve"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Approval required", response.content.decode("utf-8"))
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.approver, self.user)

    def test_view_membership_approval_list(self):
        response = self.client.get("/membership/approval/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["object_list"].count(), 1)
        self.membership.approver = self.user
        self.membership.save()
        response = self.client.get("/membership/approval/")
        self.assertEqual(response.context_data["object_list"].count(), 0)

    def test_view_membership_expiring_list(self):
        response = self.client.get("/membership/expiring/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["object_list"].count(), 1)
        self.membership.expire_date = timezone.now().date() + datetime.timedelta(days=31)
        self.membership.save()
        response = self.client.get("/membership/expiring/")
        self.assertEqual(response.context_data["object_list"].count(), 0)

    def test_edit_membership_without_access(self):
        url = f"{self.url}change/"
        response = self.client.post(
            url,
            {
                "start_date": timezone.now().date(),
                "expire_date": timezone.now().date() + datetime.timedelta(days=2),
                "reason": "Because new role",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 403)

    @patch("kamu.utils.audit.logger_audit")
    def test_edit_membership(self, mock_logger):
        self.role.approvers.add(self.group)
        url = f"{self.url}change/"
        expire_date = timezone.now().date() + datetime.timedelta(days=2)
        response = self.client.post(
            url,
            {
                "start_date": timezone.now().date(),
                "expire_date": expire_date,
                "reason": "Updated",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.reason, "Updated")
        self.assertEqual(self.membership.approver, self.user)
        self.assertEqual(self.membership.expire_date, expire_date)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Membership modified, role: Test Role, identity: Test User", extra=ANY),
            ]
        )

    def test_edit_membership_ignore_disabled_start_date(self):
        self.role.approvers.add(self.group)
        url = f"{self.url}change/"
        expire_date = timezone.now().date() + datetime.timedelta(days=2)
        response = self.client.post(
            url,
            {
                "start_date": timezone.now().date() + datetime.timedelta(days=1),
                "expire_date": expire_date,
                "reason": "Updated",
            },
            follow=True,
        )
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.start_date, timezone.now().date())
        self.assertEqual(self.membership.expire_date, expire_date)

    @patch("kamu.utils.audit.logger_audit")
    def test_end_membership(self, mock_logger):
        response = self.client.post(self.url, {"end_membership": "end"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Membership set to end today", response.content.decode("utf-8"))
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.expire_date, timezone.now().date())
        mock_logger.log.assert_has_calls(
            [
                call(20, "Membership to Test Role ended for identity: Test User", extra=ANY),
            ]
        )

    def test_end_membership_without_access(self):
        self.membership.identity = self.superidentity
        self.membership.save()
        response = self.client.post(self.url, {"end_membership": "end"}, follow=True)
        self.assertEqual(response.status_code, 403)


class MembershipJoinTests(BaseTestCase):
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

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_join_role(self, mock_logger):
        group = Group.objects.create(name="approver")
        self.user.groups.add(group)
        self.role.approvers.add(group)
        response = self._test_join_role(expire_date_delta=7)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Role membership", response.content.decode("utf-8"))
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))
        mock_logger.log.assert_has_calls(
            [
                call(20, "Membership to Test Role added to identity: Test User", extra=ANY),
                call(20, "Read membership information", extra=ANY),
            ]
        )

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


class MembershipInviteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.url = "/role/1/invite/"
        self.client = Client()
        self.client.force_login(self.user)
        set_default_permissions(self.user)
        self.group = Group.objects.create(name="InviterGroup")
        self.role.inviters.add(self.group)
        self.user.groups.add(self.group)

    @mock.patch("kamu.views.identity.ldap_search")
    def test_search_user(self, mock_ldap):
        mock_ldap.return_value = []
        url = f"{self.url}?given_names=test"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User", response.content.decode("utf-8"))
        self.assertIn("Select", response.content.decode("utf-8"))

    @mock.patch("kamu.connectors.ldap.logger")
    def test_search_ldap_fail(self, mock_logger):
        url = f"{self.url}?uid=testuser"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("LDAP search failed", response.content.decode("utf-8"))
        mock_logger.error.assert_called_once()

    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_search_ldap(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn(limited_fields=True)
        url = f"{self.url}?uid=testuser&given_names=test"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Test User", response.content.decode("utf-8"))
        self.assertEqual(response.content.decode("utf-8").count("ldap.user@example.org"), 1)

    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_search_ldap_sizelimit_exceeded(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn(limited_fields=True, size_exceeded=True)
        url = f"{self.url}?uid=testuser&given_names=test"
        response = self.client.get(url)
        self.assertIn("search returned too many results", response.content.decode("utf-8"))

    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_search_ldap_escaping(self, mock_ldap):
        conn = MockLdapConn(limited_fields=True)
        mock_ldap.return_value = conn
        url = f"{self.url}?given_names=t*est"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("(givenName=*t\\2aest*)", conn.search_args[0][2])

    @mock.patch("kamu.views.identity.ldap_search")
    def test_search_not_found_email(self, mock_ldap):
        mock_ldap.return_value = []
        url = f"{self.url}?email=nonexisting@example.org"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Email address not found", response.content.decode("utf-8"))

    @mock.patch("kamu.views.identity.ldap_search")
    def test_search_email_found_kamu(self, mock_ldap):
        mock_ldap.return_value = []
        url = f"{self.url}?email=test@example.org"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Email address not found", response.content.decode("utf-8"))

    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_search_email_found_ldap(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn()
        url = f"{self.url}?email=ldap.user@example.org"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Email address not found", response.content.decode("utf-8"))

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
        self.assertIn("Test User has added you a new role membership in Kamu", mail.outbox[0].body)

    @mock.patch("kamu.connectors.ldap._get_connection")
    @mock.patch("kamu.utils.audit.logger_audit")
    @override_settings(ALLOW_TEST_FPIC=True)
    def test_add_role_with_ldap(self, mock_logger, mock_ldap):
        mock_ldap.return_value = MockLdapConn()
        url = f"{self.url}ldap/ldapuser/"
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
        identity = Identity.objects.get(uid="ldapuser")
        self.assertTrue(Membership.objects.filter(role=self.role, identity=identity).exists())
        self.assertEqual(identity.fpic, "010181-900C")
        self.assertEqual(identity.display_name(), "Ldap User")
        self.assertTrue(
            Identifier.objects.filter(
                identity=identity, type=Identifier.Type.EPPN, value=f"ldapuser{settings.LOCAL_EPPN_SUFFIX}"
            ).exists()
        )
        mock_logger.log.assert_has_calls(
            [
                call(20, "Identity created.", extra=ANY),
                call(20, "Email address added to identity Ldap User", extra=ANY),
                call(20, "Linked eppn identifier to identity Ldap User", extra=ANY),
                call(20, "Membership to testrole added to identity: Ldap User", extra=ANY),
            ]
        )
        self.assertIn("Test User has added you a new role membership in Kamu", mail.outbox[0].body)

    @mock.patch("kamu.connectors.ldap._get_connection")
    @override_settings(ALLOW_TEST_FPIC=True)
    def test_join_role_with_ldap_existing_identity(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn()
        Identifier.objects.create(identity=self.identity, type=Identifier.Type.FPIC, value="010181-900C")
        url = f"{self.url}ldap/ldapuser/"
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

    def _test_join_role_send_email_invite(self):
        url = f"{self.url}email/"
        return self.client.post(
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

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_join_role_send_email_invite(self, mock_logger):
        response = self._test_join_role_send_email_invite()
        self.assertEqual(response.status_code, 200)
        membership = Membership.objects.get(role=self.role, identity=None, invite_email_address="invite@example.org")
        self.assertEqual(membership.inviter, self.user)
        self.assertIsNone(membership.approver)
        self.assertIn("Your invite code is", mail.outbox[0].body)
        mock_logger.log.assert_has_calls(
            [
                call(20, "Invited invite@example.org to role testrole", extra=ANY),
            ]
        )

    def test_join_role_invite_as_approver(self):
        self.role.approvers.add(self.group)
        self._test_join_role_send_email_invite()
        membership = Membership.objects.get(role=self.role, identity=None, invite_email_address="invite@example.org")
        self.assertEqual(membership.inviter, self.user)
        self.assertEqual(membership.approver, self.user)