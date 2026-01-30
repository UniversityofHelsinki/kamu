"""
Unit tests for identities.
"""

from django.core.exceptions import MultipleObjectsReturned
from django.test import TestCase, override_settings
from django.utils import timezone

from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.utils.audit import AuditLog
from kamu.utils.identity import get_or_create_identity_from_persondb
from tests.data import PERSONS

audit_log = AuditLog()


class IdentityMethodTests(TestCase):
    def setUp(self):
        self.identity = Identity.objects.create(given_names="Test Identity")

    def test_identity_email_address(self):
        # Should return the lowest priority verified email address
        self.assertIsNone(self.identity.email_address())
        email_address1 = EmailAddress.objects.create(
            identity=self.identity, address="test@example.org", verified=None, priority=1
        )
        email_address2 = EmailAddress.objects.create(
            identity=self.identity, address="test@example.com", verified=None, priority=0
        )
        self.assertIsNone(self.identity.email_address())
        email_address1.verified = timezone.now()
        email_address1.save()
        self.assertEqual("test@example.org", self.identity.email_address())
        email_address2.verified = timezone.now()
        email_address2.save()
        self.assertEqual("test@example.com", self.identity.email_address())

    def test_identity_phone_number(self):
        # Should return the lowest priority verified phone number
        self.assertIsNone(self.identity.phone_number())
        phone_number1 = PhoneNumber.objects.create(
            identity=self.identity, number="+1234567890", verified=None, priority=1
        )
        phone_number2 = PhoneNumber.objects.create(
            identity=self.identity, number="+1234567891", verified=None, priority=0
        )
        self.assertIsNone(self.identity.phone_number())
        phone_number1.verified = timezone.now()
        phone_number1.save()
        self.assertEqual("+1234567890", self.identity.phone_number())
        phone_number2.verified = timezone.now()
        phone_number2.save()
        self.assertEqual("+1234567891", self.identity.phone_number())


class IdentityImportTests(TestCase):

    def test_identity_import_person(self):
        identity = Identity.objects.create(fpic="010180-9999", uid="olduser")
        Identifier.objects.create(
            identity=identity, type=Identifier.Type.PERSON, value="old-uuid-0000-0000-0000-000000000000"
        )

        person = PERSONS.get("tester")
        result = get_or_create_identity_from_persondb(person)
        self.assertNotEqual(result, identity)
        self.assertEqual(result.given_names, "Tester")
        self.assertEqual(result.fpic, "010181-900C")
        self.assertEqual(result.uid, "testuser")
        self.assertEqual(result.email_addresses.count(), 2)
        self.assertTrue(result.email_addresses.filter(verified__isnull=False).count(), 1)
        self.assertEqual(result.phone_numbers.count(), 2)
        self.assertEqual(result.identifiers.count(), 2)
        self.assertEqual(
            result.identifiers.filter(type=Identifier.Type.PERSON).first().value,
            "12345678-1234-1234-1234-123456789012",
        )

    def test_identity_match_found_fpic(self):
        identity = Identity.objects.create(fpic="010181-900C")
        person = PERSONS.get("tester")
        result = get_or_create_identity_from_persondb(person)
        self.assertEqual(result, identity)

    def test_identity_match_found_uid(self):
        identity = Identity.objects.create(uid="testuser")
        person = PERSONS.get("tester")
        result = get_or_create_identity_from_persondb(person)
        self.assertEqual(result, identity)

    def test_identity_match_found_person_uuid(self):
        identity = Identity.objects.create()
        Identifier.objects.create(
            identity=identity,
            type=Identifier.Type.PERSON,
            value="12345678-1234-1234-1234-123456789012",
        )
        person = PERSONS.get("tester")
        result = get_or_create_identity_from_persondb(person)
        self.assertEqual(result, identity)

    def test_duplicate_match_raises_exception(self):
        Identity.objects.create(fpic="010181-900C")
        Identity.objects.create(uid="testuser")
        person = PERSONS.get("tester")
        with self.assertRaises(MultipleObjectsReturned):
            get_or_create_identity_from_persondb(person)

    def test_duplicate_account_match_raises_exception(self):
        Identity.objects.create(uid="testuser")
        Identity.objects.create(uid="adminuser")
        person = PERSONS.get("tester")
        with self.assertRaises(MultipleObjectsReturned):
            get_or_create_identity_from_persondb(person)

    @override_settings(PERSONDB_IMPORT_IGNORE_ACCOUNT_TYPES_IN_DUPLICATE_CHECK=[8])
    def test_duplicate_account_match_exception(self):
        Identity.objects.create(uid="testuser")
        Identity.objects.create(uid="adminuser")
        person = PERSONS.get("tester")
        try:
            get_or_create_identity_from_persondb(person)
        except MultipleObjectsReturned:
            self.fail("get_or_create_identity_from_persondb raised MultipleObjectsReturned")
