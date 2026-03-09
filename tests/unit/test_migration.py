"""
Tests for migration management commands.
"""

from datetime import timedelta
from unittest import mock

from django.test import override_settings
from django.utils import timezone

from kamu.models.account import AccountSynchronization
from kamu.models.identity import Identifier, Identity
from tests.data import PERSONS
from tests.setup import ManagementCommandTestCase, TestData
from tests.utils import MockLdapConn


class LdapMigrationTests(TestData, ManagementCommandTestCase):
    command = "migrate_from_ldap"

    @override_settings(ALLOW_TEST_FPIC=True)
    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_migration(self, mock_ldap):
        role = self.create_role()
        mock_ldap.return_value = MockLdapConn()
        out, _ = self.call_command("-a ldapuser", "-t account", "-v 3", f"-r {role.identifier}")
        identity = Identity.objects.first()
        self.assertEqual(identity.uid, "ldapuser")
        self.assertEqual(identity.given_names, "Ldap")
        self.assertEqual(identity.surname, "User")
        self.assertEqual(identity.email_addresses.first().address, "ldap.user@example.org")
        self.assertEqual(identity.email_addresses.first().verified, None)
        self.assertEqual(identity.fpic, "010181-900C")
        self.assertEqual(identity.identifiers.filter(type=Identifier.Type.FPIC).first().value, "010181-900C")
        self.assertEqual(identity.date_of_birth.isoformat(), "1981-01-01")
        self.assertEqual(identity.useraccount.first().uid, "ldapuser")
        self.assertTrue(AccountSynchronization.objects.filter(account__uid="ldapuser").exists())
        membership = identity.membership_set.first()
        self.assertEqual(membership.role, role)
        self.assertEqual(membership.start_date, timezone.localdate())
        self.assertEqual(membership.expire_date, timezone.localdate() + timedelta(days=role.maximum_duration))
        self.assertIn("Account with UID: ldapuser migrated successfully.", out)
        self.assertIn("limiting expiry date to role maximum", out)

    @override_settings(ALLOW_TEST_FPIC=True)
    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_migration_to_existing_identity(self, mock_ldap):
        identity = self.create_identity()
        identity.fpic = "010181-900C"
        identity.save()
        mock_ldap.return_value = MockLdapConn()
        out, _ = self.call_command("-a ldapuser", "-t account", "-v 3")
        self.assertEqual(identity.useraccount.first().uid, "ldapuser")
        self.assertIn("Identity found by FPIC", out)

    @override_settings(ALLOW_TEST_FPIC=True)
    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_migration_to_skip_existing_account(self, mock_ldap):
        identity = self.create_identity()
        identity.useraccount.create(uid="ldapuser", type="account")
        mock_ldap.return_value = MockLdapConn()
        out, _ = self.call_command("-a ldapuser", "-t account", "-v 3")
        self.assertIn("skipping identity and account creation", out)

    @override_settings(ALLOW_TEST_FPIC=True)
    @mock.patch("kamu.connectors.ldap._get_connection")
    def test_migration_conflicting_existing_identities(self, mock_ldap):
        identity = self.create_identity()
        identity.fpic = "010181-900C"
        identity.save()
        superidentity = self.create_superidentity()
        superidentity.uid = "ldapuser"
        superidentity.save()
        mock_ldap.return_value = MockLdapConn()
        _, err = self.call_command("-a ldapuser", "-t account", "-v 3")
        self.assertIn("Conflicting identities found", err)

    @mock.patch("kamu.connectors.ldap._get_connection")
    @mock.patch("kamu.connectors.persondb.PersonDBApiConnector.search_identifier")
    @mock.patch("kamu.connectors.persondb.PersonDBApiConnector.search_email")
    @override_settings(PERSONDB_SEARCH_FOR_INVITES=True)
    def test_migrate_match_in_persondb(self, mock_persondb_email, mock_persondb_identifier, mock_ldap):
        mock_persondb_email.return_value = []
        mock_persondb_identifier.return_value = [PERSONS.get("tester")]
        mock_ldap.return_value = MockLdapConn()
        out, _ = self.call_command("-a ldapuser", "-t account", "-v 3")
        self.assertIn("PersonDB result found for person UUID", out)
        identity = Identity.objects.first()
        self.assertTrue(identity.phone_numbers.filter(number="+358401234567").exists())
        self.assertEqual(identity.useraccount.first().uid, "ldapuser")
