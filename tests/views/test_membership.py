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
        self.create_identity(user=True)
        self.create_superidentity(user=True)
        self.role = self.create_role()
        self.membership = self.create_membership(
            self.role,
            self.identity,
            start_delta_days=0,
            expire_delta_days=1,
            inviter=self.superuser,
            invite_email_address="invited_user@example.org",
        )
        self.url = f"/membership/{self.membership.pk}/"
        self.group = Group.objects.create(name="group")
        self.role.inviters.add(self.group)
        self.user.groups.add(self.group)
        self.client = Client()
        self.client.force_login(self.user)

    def test_show_membership_in_identity_details(self):
        response = self.client.get(f"/identity/{self.identity.pk}/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Role memberships", response.content.decode("utf-8"))
        self.assertIn(self.role.name(), response.content.decode("utf-8"))
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))
        self.assertNotIn("invited_user@example.org", response.content.decode("utf-8"))
        self.assertNotIn("Approval required", response.content.decode("utf-8"))

    def test_show_membership_details(self):
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

    def test_resend_membership_invite_custom(self):
        self.membership.identity = None
        self.membership.invite_text = "Custom invite text"
        self.membership.invite_language = "en"
        self.membership.save()
        response = self.client.post(self.url, {"resend_invite": "resend"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Your invite code is", mail.outbox[0].body)
        self.assertIn("Custom invite text", mail.outbox[0].body)

    def test_show_membership_approver_actions(self):
        self.role.approvers.add(self.group)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Approve", response.content.decode("utf-8"))
        self.assertIn("Update membership", response.content.decode("utf-8"))
        self.assertIn("Cancel membership", response.content.decode("utf-8"))
        self.assertIn("End membership", response.content.decode("utf-8"))

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
        self.membership.cancelled_at = timezone.now()
        self.membership.save()
        response = self.client.get("/membership/expiring/")
        self.assertEqual(response.context_data["object_list"].count(), 0)
        self.membership.cancelled_at = None
        self.membership.approver = self.user
        self.membership.save()
        response = self.client.get("/membership/approval/")
        self.assertEqual(response.context_data["object_list"].count(), 0)

    def test_view_membership_expiring_list(self):
        response = self.client.get("/membership/expiring/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["object_list"].count(), 1)
        self.membership.cancelled_at = timezone.now()
        self.membership.save()
        response = self.client.get("/membership/expiring/")
        self.assertEqual(response.context_data["object_list"].count(), 0)
        self.membership.cancelled_at = None
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
                call(
                    20,
                    f"Membership modified, role: {self.role.name()}, identity: {self.identity.display_name()}",
                    extra=ANY,
                ),
            ]
        )

    def test_edit_membership_ignore_disabled_start_date(self):
        self.role.approvers.add(self.group)
        url = f"{self.url}change/"
        expire_date = timezone.now().date() + datetime.timedelta(days=2)
        self.client.post(
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
                call(
                    20,
                    f"Membership to {self.role.name()} ended for identity: {self.identity.display_name()}",
                    extra=ANY,
                ),
            ]
        )

    def test_cancel_membership_without_approver_access(self):
        response = self.client.post(self.url, {"cancel_membership": "cancel"}, follow=True)
        self.assertEqual(response.status_code, 403)

    @patch("kamu.utils.audit.logger_audit")
    def test_cancel_membership(self, mock_logger):
        self.role.approvers.add(self.group)
        response = self.client.post(self.url, {"cancel_membership": "cancel"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Membership cancelled", response.content.decode("utf-8"))
        self.assertNotIn("Cancel membership", response.content.decode("utf-8"))
        self.membership.refresh_from_db()
        self.assertIsNotNone(self.membership.cancelled_at)
        mock_logger.log.assert_has_calls(
            [
                call(
                    20,
                    f"Membership to {self.role.name()} cancelled for identity: {self.identity.display_name()}",
                    extra=ANY,
                ),
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
        self.create_identity(user=True)
        self.role = self.create_role()
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
                call(
                    20,
                    f"Membership to {self.role.name()} added to identity: {self.identity.display_name()}",
                    extra=ANY,
                ),
                call(20, "Read membership information", extra=ANY),
            ]
        )

    def test_join_role_without_approver_status(self):
        response = self._test_join_role()
        self.assertEqual(response.status_code, 403)

    def test_join_role_with_invalid_date(self):
        response = self._test_join_role(start_date_delta=7)
        self.assertIn("Membership expiry date cannot be earlier than start date", response.content.decode("utf-8"))

    def test_join_role_with_too_long_duration(self):
        self.role.maximum_duration = 3
        self.role.save()
        response = self._test_join_role(expire_date_delta=4)
        self.assertIn("Maximum membership duration for this role is 3 days.", response.content.decode("utf-8"))


class MembershipInviteTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_identity(user=True, email=True)
        self.role = self.create_role()
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
        data = {
            "given_names": "test",
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))
        self.assertIn("Select", response.content.decode("utf-8"))

    @mock.patch("kamu.connectors.ldap.logger")
    def test_search_ldap_fail(self, mock_logger):
        data = {
            "uid": "testuser",
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("LDAP search failed", response.content.decode("utf-8"))
        mock_logger.error.assert_called_once()

    @mock.patch("kamu.connectors.ldap._get_connection")
    @override_settings(SKIP_NAME_SEARCH_IF_IDENTIFIER_MATCHES=False)
    def test_search_ldap(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn(limited_fields=True)
        data = {
            "given_names": "test",
            "uid": "testuser",
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.identity.display_name(), response.content.decode("utf-8"))
        self.assertEqual(response.content.decode("utf-8").count("ldap.user@example.org"), 1)

    @override_settings(ALLOW_TEST_FPIC=True)
    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_search_ldap_fpic(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn(limited_fields=True)
        data = {
            "fpic": "010181-900C",
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode("utf-8").count("ldap.user@example.org"), 1)

    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_search_ldap_sizelimit_exceeded(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn(limited_fields=True, size_exceeded=True)
        data = {
            "given_names": "test",
            "uid": "testuser",
        }
        response = self.client.post(self.url, data)
        self.assertIn("search returned too many results", response.content.decode("utf-8"))

    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_search_ldap_escaping(self, mock_ldap):
        conn = MockLdapConn(limited_fields=True)
        mock_ldap.return_value = conn
        data = {
            "given_names": "t*est",
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("(givenName=*t\\2aest*)", conn.search_args[0][2])

    @mock.patch("kamu.views.identity.ldap_search")
    def test_search_not_found_email(self, mock_ldap):
        mock_ldap.return_value = []
        data = {"email": "nonexisting@example.org"}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Email address not found", response.content.decode("utf-8"))

    @mock.patch("kamu.views.identity.ldap_search")
    def test_search_email_found_kamu(self, mock_ldap):
        mock_ldap.return_value = []
        data = {"email": self.email_address.address}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Email address not found", response.content.decode("utf-8"))

    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_search_email_found_ldap(self, mock_ldap):
        mock_ldap.return_value = MockLdapConn()
        data = {"email": "ldap.user@example.org"}
        response = self.client.post(self.url, data)
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
        self.assertIn(
            f"{self.identity.display_name()} has added you a new role membership in Kamu", mail.outbox[0].body
        )

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
                call(20, f"Membership to {self.role.name()} added to identity: Ldap User", extra=ANY),
            ]
        )
        self.assertIn(
            f"{self.identity.display_name()} has added you a new role membership in Kamu", mail.outbox[0].body
        )

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

    def _test_join_role_send_email_invite(self, preview=False):
        url = f"{self.url}email/"
        data = {
            "start_date": timezone.now().date(),
            "expire_date": timezone.now().date() + datetime.timedelta(days=7),
            "reason": "Because",
            "invite_text": "Test text",
            "invite_email_address": "invite@example.org",
            "invite_language": "en",
        }

        if preview:
            data["preview_message"] = ""
        return self.client.post(
            url,
            data,
            follow=True,
        )

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_join_role_send_email_invite_preview(self, mock_logger):
        self.session = self.client.session
        self.session["invitation_email_address"] = "invite@example.org"
        self.session.save()
        response = self._test_join_role_send_email_invite(preview=True)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            Membership.objects.filter(
                role=self.role, identity=None, invite_email_address="invite@example.org"
            ).exists()
        )
        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(mock_logger.called)
        self.assertIn("Preview message", response.content.decode("utf-8"))

    @mock.patch("kamu.utils.audit.logger_audit")
    def test_join_role_send_email_invite(self, mock_logger):
        response = self._test_join_role_send_email_invite()
        self.assertEqual(response.status_code, 200)
        membership = Membership.objects.get(role=self.role, identity=None, invite_email_address="invite@example.org")
        self.assertEqual(membership.inviter, self.user)
        self.assertIsNone(membership.approver)
        self.assertIn("Your invite code is", mail.outbox[0].body)
        self.assertIn("Test text", mail.outbox[0].body)
        mock_logger.log.assert_has_calls(
            [
                call(20, f"Invited invite@example.org to role {self.role.name()}", extra=ANY),
            ]
        )

    def test_join_role_invite_as_approver(self):
        self.role.approvers.add(self.group)
        self._test_join_role_send_email_invite()
        membership = Membership.objects.get(role=self.role, identity=None, invite_email_address="invite@example.org")
        self.assertEqual(membership.inviter, self.user)
        self.assertEqual(membership.approver, self.user)

    def test_invite_form_help_text(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Name search returns partial matches from Kamu and names starting with the search parameters in "
            "the user directory.",
            response.content.decode("utf-8"),
        )


class MembershipMassInviteViewTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.create_identity(user=True, email=True)
        self.create_superidentity(user=True, phone=True)
        self.role = self.create_role()
        self.url = f"/role/{self.role.pk}/invite/multiple/"
        self.group = Group.objects.create(name="group")
        self.role.inviters.add(self.group)
        self.user.groups.add(self.group)
        self.data = {
            "start_date": timezone.now().date(),
            "expire_date": timezone.now().date() + datetime.timedelta(days=7),
            "reason": "Because",
            "invite_language": "en",
        }
        self.client = Client()
        self.client.force_login(self.user)

    @override_settings(ALLOW_TEST_FPIC=True)
    @override_settings(MASS_INVITE_PERMISSION_GROUPS={"group": 3})
    def test_mass_invite_preview(self):
        identifier = Identifier.objects.create(
            identity=self.superidentity, type=Identifier.Type.FPIC, value="010181-900C"
        )
        response = self.client.post(
            self.url,
            self.data
            | {"invited": f"{self.email_address}\n010181-900C\ninvited@example.org", "preview_message": "True"},
        )
        self.assertIn("Multiple invites", response.content.decode("utf-8"))
        self.assertIn("Tester Mc.", response.content.decode("utf-8"))
        self.assertIn("Dr. User", response.content.decode("utf-8"))
        self.assertIn("invited@example.org", response.content.decode("utf-8"))
        identifier.deactivated_at = timezone.now()
        identifier.save()
        response = self.client.post(
            self.url,
            self.data
            | {"invited": f"{self.email_address}\n010181-900C\ninvited@example.org", "preview_message": "True"},
        )
        self.assertNotIn("Dr. User", response.content.decode("utf-8"))

    @override_settings(ALLOW_TEST_FPIC=True)
    @override_settings(MASS_INVITE_PERMISSION_GROUPS={"group": 3})
    @mock.patch("kamu.utils.audit.logger_audit")
    def test_mass_invite(self, mock_logger):
        Identifier.objects.create(identity=self.superidentity, type=Identifier.Type.FPIC, value="010181-900C")
        response = self.client.post(
            self.url, self.data | {"invited": f"{self.email_address}\n010181-900C\ninvited@example.org"}, follow=True
        )
        self.assertIn("Role details", response.content.decode("utf-8"))
        self.assertIn("Added following identities: Tester Mc., Dr. User", response.content.decode("utf-8"))
        self.assertIn(
            "Invite email sent to following addresses: invited@example.org", response.content.decode("utf-8")
        )
        mock_logger.log.assert_has_calls(
            [
                call(
                    20, f"Membership to {self.role.name()} added to identity: {self.user.get_full_name()}", extra=ANY
                ),
                call(
                    20,
                    f"Membership to {self.role.name()} added to identity: {self.superuser.get_full_name()}",
                    extra=ANY,
                ),
                call(20, f"Invited invited@example.org to role {self.role.name()}", extra=ANY),
                call(20, "List role memberships", extra=ANY),
            ]
        )
        self.assertIn("Tester Mc. has added you a new role membership in Kamu", mail.outbox[0].body)
        self.assertIn("Tester Mc. has invited you to join the role", mail.outbox[1].body)

    @override_settings(MASS_INVITE_PERMISSION_GROUPS={"group": 1})
    def test_mass_invite_too_many_lines(self):
        response = self.client.post(
            self.url,
            self.data | {"invited": f"{self.email_address}\n{self.phone_number}", "preview_message": "True"},
        )
        self.assertIn("Too many invited persons.", response.content.decode("utf-8"))
        self.assertEqual(response.status_code, 200)

    @override_settings(MASS_INVITE_PERMISSION_GROUPS={"group": 3})
    def test_mass_invite_attribute_conflict(self):
        self.phone_number.verified = True
        self.phone_number.save()
        response = self.client.post(
            self.url,
            self.data
            | {"invited": f"{self.email_address},+1234000000\ninvited@example.org", "preview_message": "True"},
        )
        self.assertIn("are registered to different identities", response.content.decode("utf-8"))
