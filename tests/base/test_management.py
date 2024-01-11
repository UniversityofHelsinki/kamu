"""
Tests for management commands.
"""

import datetime
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from base.management.commands.purge_data import UsageError
from identity.models import Identity
from role.models import Membership, Role


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
