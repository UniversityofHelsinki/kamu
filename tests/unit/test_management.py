"""
Tests for management commands.
"""

import datetime
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from kamu.management.commands.purge_data import UsageError
from kamu.models.identity import Identifier, Identity
from kamu.models.membership import Membership
from kamu.models.role import Role


class ManagementCommandTestCase(TestCase):
    command = None

    def call_command(self, *args, **kwargs):
        out = StringIO()
        call_command(
            self.command,
            *args,
            stdout=out,
            stderr=StringIO(),
            **kwargs,
        )
        return out.getvalue()


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
        out = self.call_command("-l")
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
        out = self.call_command("-l")
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
        out = self.call_command("-l")
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
        out = self.call_command("-l")
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
