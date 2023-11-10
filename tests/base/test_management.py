"""
Tests for management commands.
"""

from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from identity.models import Identity
from role.models import Membership


class GenerateTestDataTests(TestCase):
    def call_command(self, *args, **kwargs):
        out = StringIO()
        call_command(
            "generate_test_data",
            *args,
            stdout=out,
            stderr=StringIO(),
            **kwargs,
        )
        return out.getvalue()

    def test_generate_data(self):
        self.call_command("-s", "-i 10")
        self.assertEqual(Identity.objects.all().count(), 10)
        self.assertGreaterEqual(Membership.objects.all().count(), 10)
