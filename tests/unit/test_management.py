"""
Tests for management commands.
"""

import datetime
import json
from io import StringIO
from unittest import mock

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from kamu.management.commands.purge_data import UsageError
from kamu.models.account import AccountSynchronization
from kamu.models.identity import Identifier, Identity
from kamu.models.membership import Membership
from kamu.models.organisation import Organisation
from kamu.models.role import Role
from tests.setup import TestData
from tests.views.test_account import AccountApiResponseMock


class ManagementCommandTestCase(TestCase):
    command = None

    def call_command(self, *args, **kwargs):
        out = StringIO()
        err = StringIO()
        call_command(
            self.command,
            *args,
            stdout=out,
            stderr=err,
            **kwargs,
        )
        return out.getvalue(), err.getvalue()


class GenerateTestDataTests(ManagementCommandTestCase):
    command = "generate_test_data"

    def test_generate_data(self):
        self.call_command("-v 0", "-i 10")
        self.assertEqual(Identity.objects.all().count(), 10)
        self.assertGreaterEqual(Membership.objects.all().count(), 1)


class PurgeMembershipTests(ManagementCommandTestCase):
    command = "purge_data"

    def setUp(self):
        user = get_user_model()
        self.user = user.objects.create_user(username="testuser", password="test_pass")

        self.identity = Identity.objects.create(
            user=self.user, given_names="Test Me", surname="User", given_name_display="Test"
        )

        self.roles = (
            Role.objects.create(identifier="first", name_en="First Role", maximum_duration=400),
            Role.objects.create(identifier="second", name_en="Second Role", maximum_duration=400),
            Role.objects.create(identifier="third", name_en="Third Role", maximum_duration=400),
        )

        for i in range(3):
            self._create_test_membership(self.roles[i], days=2 * i)

    def _create_test_membership(self, role, days):
        start = timezone.now().date() - datetime.timedelta(days=390)
        end = timezone.now().date() - datetime.timedelta(days=days)
        Membership.objects.create(
            role=role,
            identity=self.identity,
            reason="Because",
            start_date=start,
            expire_date=end,
        )

    def test_purge_expired(self):
        self.assertEqual(Membership.objects.all().count(), 3)
        self.call_command("-v=0", "--days=3", "-t=membership")
        self.assertEqual(Membership.objects.all().count(), 2)
        self.call_command("-v=0", "-d=3")
        self.assertEqual(Membership.objects.all().count(), 2)
        self.call_command("-v=0", "--days=1")
        self.assertEqual(Membership.objects.all().count(), 1)
        self.assertEqual(Membership.objects.first().role, self.roles[0])

    def test_purge_nothing(self):
        self.assertEqual(Membership.objects.all().count(), 3)
        self.call_command("-v=0", "-d=10")
        self.assertEqual(Membership.objects.all().count(), 3)
        self.call_command("-v=0", "-d=5", "--type=membership")
        self.assertEqual(Membership.objects.all().count(), 3)

    def test_purge_args(self):
        with self.assertRaises(UsageError):
            self.call_command("--type=foo")
        out, _ = self.call_command("-l")
        self.assertIn("membership", out)

    def test_purge_settings(self):
        self.assertEqual(Membership.objects.all().count(), 3)
        with self.settings(PURGE_DELAY_DAYS=10):
            self.call_command("-v=0")
            self.assertEqual(Membership.objects.all().count(), 3)
        with self.settings(PURGE_DELAY_DAYS=3):
            self.call_command("-v=0")
            self.assertEqual(Membership.objects.all().count(), 2)

    def test_purge_delay(self):
        self.roles[0].purge_delay = 40
        self.roles[0].save()
        self.roles[1].purge_delay = 50
        self.roles[1].save()

        self.assertEqual(Membership.objects.all().count(), 3)
        self.call_command("-v=0")
        self.assertEqual(Membership.objects.all().count(), 3)
        for membership in Membership.objects.all():
            membership.expire_date = timezone.now().date() - datetime.timedelta(days=45)
            membership.save()
        self.call_command("-v=0")
        self.assertEqual(Membership.objects.all().count(), 2)


class PurgeIdentifierTests(ManagementCommandTestCase):
    command = "purge_data"

    def setUp(self):
        self.identities = [
            Identity.objects.create(
                user=None,
                given_names=f"Test Me {i}",
                surname=f"User{i}",
                given_name_display=f"Test {i}",
                created_at=timezone.now() - datetime.timedelta(days=5 * i + 2),
            )
            for i in range(10)
        ]

        self.identifiers = [
            Identifier.objects.create(
                identity=self.identities[i],
                type=Identifier.Type.values[i % 3],
                value="whatever",
                verified=bool(i % 3),
                deactivated_at=None if i % 2 == 1 else timezone.now() - datetime.timedelta(days=5 * i),
            )
            for i in range(10)
        ]

    def test_purge_args(self):
        with self.assertRaises(UsageError):
            self.call_command("--type=foo")
        out, _ = self.call_command("-l")
        self.assertIn("identifier", out)

    def test_purge_deactivated(self):
        self.assertEqual(Identifier.objects.all().count(), 10)
        self.call_command("-v=0", "--days=61", "-t=identifier")
        self.assertEqual(Identifier.objects.all().count(), 10)
        self.call_command("-v=0", "--days=26", "-t=identifier")
        self.assertEqual(Identifier.objects.all().count(), 8)  # 0 1 2 3 4 5 7 9
        self.call_command("-v=0", "--days=11", "-t=identifier")
        self.assertEqual(Identifier.objects.all().count(), 7)  # 0 1 2 3 5 7 9
        self.assertTrue(all(ident.deactivated_at is None for ident in Identifier.objects.all()[3:]))
        self.assertFalse(all(ident.deactivated_at is None for ident in Identifier.objects.all()))

    def test_purge_cascade(self):
        self.assertEqual(Identifier.objects.all().count(), 10)
        self.call_command("-v=0", "--days=41", "-t=identity")
        self.assertEqual(Identifier.objects.all().count(), 8)  # 0 1 2 3 4 5 6 7


class PurgeIdentityTests(ManagementCommandTestCase):
    command = "purge_data"

    def setUp(self):
        user = get_user_model()
        self.users = [
            user.objects.create_user(
                username=f"testuser{i}",
                password=f"test_pass{i}",
                last_login=timezone.now() - datetime.timedelta(days=5 * i),
            )
            for i in range(4)
        ]

        self.identities = [
            Identity.objects.create(
                user=self.users[i] if i < len(self.users) else None,
                given_names=f"Test Me {i}",
                surname=f"User{i}",
                given_name_display=f"Test {i}",
                created_at=timezone.now() - datetime.timedelta(days=5 * i + 2),
            )
            for i in range(6)
        ]

        self.role = Role.objects.create(identifier="test", name_en="Test Role", maximum_duration=400)

    def _create_test_membership(self, identity, days):
        start = timezone.now().date() - datetime.timedelta(days=390)
        end = timezone.now().date() - datetime.timedelta(days=days)
        Membership.objects.create(
            role=self.role,
            identity=identity,
            reason="Because",
            start_date=start,
            expire_date=end,
        )

    def test_purge_args(self):
        with self.assertRaises(UsageError):
            self.call_command("--type=foo")
        out, _ = self.call_command("-l")
        self.assertIn("identity", out)

    def test_purge_inactive_without_roles(self):
        self.assertEqual(Identity.objects.all().count(), 6)
        self.call_command("-v=0", "--days=11", "-t=membership")
        self.assertEqual(Identity.objects.all().count(), 6)
        self.call_command("-v=0", "--days=11", "-t=identity")
        self.assertEqual(Identity.objects.all().count(), 3)
        self.call_command("-v=0", "--days=11", "-t=identity")
        self.assertEqual(Identity.objects.all().count(), 3)
        self.call_command("-v=0", "--days=9", "-t=identity")
        self.assertEqual(Identity.objects.all().count(), 2)

    def test_purge_inactive_with_roles(self):
        self._create_test_membership(self.identities[5], 100)
        self._create_test_membership(self.identities[2], 100)
        self.assertEqual(Identity.objects.all().count(), 6)
        self.call_command("-v=0", "--days=11", "-t=identity")
        self.assertEqual(Identity.objects.all().count(), 4)
        self.call_command("-v=0", "--days=9", "-t=identity")
        self.assertEqual(Identity.objects.all().count(), 4)
        self.call_command("-v=0", "--days=4", "-t=identity")
        self.assertEqual(Identity.objects.all().count(), 3)


class PurgeUserTests(ManagementCommandTestCase):
    command = "purge_data"

    def setUp(self):
        user = get_user_model()
        self.users = [
            user.objects.create_user(
                username=f"testuser{i}",
                password=f"test_pass{i}",
                last_login=timezone.now() - datetime.timedelta(days=5 * i),
            )
            for i in range(5)
        ]

        self.identities = [
            Identity.objects.create(
                user=self.users[i] if i < len(self.users) else None,
                given_names=f"Test Me {i}",
                surname=f"User{i}",
                given_name_display=f"Test {i}",
                created_at=timezone.now() - datetime.timedelta(days=5 * i + 2),
            )
            for i in range(3)
        ]

        self.role = Role.objects.create(identifier="test", name_en="Test Role", maximum_duration=400)

    def _create_test_membership(self, identity, days, inviter=None, approver=None):
        start = timezone.now().date() - datetime.timedelta(days=390)
        end = timezone.now().date() - datetime.timedelta(days=days)
        Membership.objects.create(
            role=self.role,
            identity=identity,
            inviter=inviter,
            approver=approver,
            reason="Because",
            start_date=start,
            expire_date=end,
        )

    def test_purge_args(self):
        with self.assertRaises(UsageError):
            self.call_command("--type=foo")
        out, _ = self.call_command("-l")
        self.assertIn("user", out)

    def test_purge_inactive_without_identity(self):
        user = get_user_model()
        self.assertEqual(user.objects.all().count(), 5)
        self.call_command("-v=0", "--days=6", "-t=user")
        self.assertEqual(user.objects.all().count(), 3)
        self.call_command("-v=0", "--days=6", "-t=identity")
        self.assertEqual(user.objects.all().count(), 3)
        self.call_command("-v=0", "--days=6", "-t=user")
        self.assertEqual(user.objects.all().count(), 2)

    def test_purge_inactive_exclude_owner(self):
        user = get_user_model()
        self.role.owner = self.users[-1]
        self.assertEqual(user.objects.all().count(), 5)
        self.call_command("-v=0", "--days=6", "-t=user")
        self.assertEqual(user.objects.all().count(), 3)

    def test_purge_inactive_exclude_inviter(self):
        user = get_user_model()
        self._create_test_membership(self.identities[-1], 20, inviter=self.users[-1])
        self.assertEqual(user.objects.all().count(), 5)
        self.call_command("-v=0", "--days=6", "-t=user")
        self.assertEqual(user.objects.all().count(), 4)
        self.call_command("-v=0", "--days=6", "-t=membership")
        self.assertEqual(user.objects.all().count(), 4)
        self.call_command("-v=0", "--days=6", "-t=user")
        self.assertEqual(user.objects.all().count(), 3)

    def test_purge_inactive_exclude_approver(self):
        user = get_user_model()
        self._create_test_membership(self.identities[-1], 20, approver=self.users[-1])
        self.assertEqual(user.objects.all().count(), 5)
        self.call_command("-v=0", "--days=6", "-t=user")
        self.assertEqual(user.objects.all().count(), 4)
        self.call_command("-v=0", "--days=6", "-t=membership")
        self.assertEqual(user.objects.all().count(), 4)
        self.call_command("-v=0", "--days=6", "-t=user")
        self.assertEqual(user.objects.all().count(), 3)


class MembershipExpireNotifications(TestData, ManagementCommandTestCase):
    command = "notify_expiring_memberships"

    def setUp(self):
        super().setUp()
        self.role = self.create_role(name="ext_employee")
        self.role_guest = self.create_role(name="ext_research")
        self.create_identity(user=False, email=True)
        self.create_superidentity(user=True, email=True)
        self.create_membership(
            self.role, identity=self.identity, start_delta_days=0, expire_delta_days=10, inviter=self.superuser
        )
        self.create_membership(self.role, identity=self.superidentity, start_delta_days=0, expire_delta_days=5)
        self.create_membership(self.role_guest, identity=self.identity, start_delta_days=0, expire_delta_days=8)
        self.create_membership(self.role, identity=self.superidentity, start_delta_days=-1, expire_delta_days=-1)

    def test_member_notifications(self):
        self.call_command("-v 0", "-d 11", "-m")
        self.assertEqual(len(mail.outbox), 0)
        self.call_command("-v 0", "-d 10", "-m")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(f"Role:\n{self.role.name()}", mail.outbox[0].body)
        self.assertIn(f"You were invited by {self.superuser.get_full_name()}", mail.outbox[0].body)
        mail.outbox = []
        self.call_command("-v 0", "-d 6", "-m")
        self.assertEqual(len(mail.outbox), 0)
        self.call_command("-v 0", "-d 5", "-m")
        self.assertEqual(len(mail.outbox), 1)

    def test_role_notifications(self):
        self.call_command("-v 0", "-d 10", "-r")
        self.assertEqual(len(mail.outbox), 2)
        self.assertIn("Number of memberships expiring soon: 2", mail.outbox[0].body)
        self.assertIn("Number of memberships expiring soon: 1", mail.outbox[1].body)
        mail.outbox = []
        self.call_command("-v 0", "-d 5", "-r")
        self.assertEqual(len(mail.outbox), 1)
        mail.outbox = []
        self.call_command("-v 0", "-d 4", "-r")
        self.assertEqual(len(mail.outbox), 0)


class AccountSynchronizationTests(TestData, ManagementCommandTestCase):
    command = "account_synchronization"

    def setUp(self):
        super().setUp()
        self.role = self.create_role("consultant")
        self.permission = self.create_permission("lightaccount")
        self.role.permissions.add(self.permission)
        self.identity = self.create_identity(user=True, email=True)
        self.membership = self.create_membership(
            self.role, self.identity, start_delta_days=-2, expire_delta_days=1, approver=self.identity.user
        )
        self.account = self.create_account()
        self.identity.save()

    def test_synchronization_error(self):
        out, err = self.call_command("-v 2")
        self.assertEqual(AccountSynchronization.objects.all().first().number_of_failures, 1)
        self.assertIn(f"Syncing account {self.account.uid}", out)
        self.assertIn("Failed to synchronize account", err)

    @mock.patch("kamu.connectors.account.AccountApiConnector.api_call_post")
    def test_synchronization(self, mock_connector):
        mock_connector.return_value = AccountApiResponseMock()
        out, err = self.call_command("-v 2")
        self.assertIn(f"Syncing account {self.account.uid}", out)
        self.assertEqual("", err)
        self.assertEqual(AccountSynchronization.objects.all().count(), 0)


class OrganisationApiResponseMock:
    def __init__(self, status: int = 200):
        self.status_code = status
        self.content = json.dumps(
            [
                {
                    "uniqueId": "1-1",
                    "code": "SUB0001",
                    "nameFi": "Ala-organisaatio",
                    "nameEn": "Sub-organisation",
                    "nameSv": "Sub-organisation",
                    "parent": "1",
                },
                {
                    "uniqueId": "1",
                    "code": "ORG01",
                    "abbreviation": "ORG",
                    "nameFi": "Organisaatio",
                    "nameEn": "Organisation",
                    "nameSv": "Organisation",
                    "parent": None,
                },
            ]
        )


class OrganisationSynchronizationTests(TestData, ManagementCommandTestCase):
    command = "update_organisation_structure"

    @mock.patch("kamu.connectors.organisation.OrganisationApiConnector.api_call_get")
    def test_synchronization(self, mock_connector):
        mock_connector.return_value = OrganisationApiResponseMock()
        out, err = self.call_command("-v 2")
        self.assertEqual(Organisation.objects.all().count(), 2)
        self.assertIn("Organisation 1-1 updated with parent 1", out)
        self.assertIn("Organisation 1 updated with abbreviation ORG", out)
