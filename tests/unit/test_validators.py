"""
Unit tests for validators.
"""

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from kamu.validators.identity import (
    validate_eidas_identifier,
    validate_fpic,
    validate_phone_number,
)


class ValidateSSNTests(TestCase):
    @override_settings(ALLOW_TEST_FPIC=True)
    def test_correct_ssn(self):
        self.assertIsNone(validate_fpic("010181-900C"))

    @override_settings(ALLOW_TEST_FPIC=False)
    def test_test_ssn(self):
        with self.assertRaises(ValidationError) as e:
            validate_fpic("010181-900C")
        self.assertEqual(e.exception.message, "Incorrect numeric part.")

    @override_settings(ALLOW_TEST_FPIC=True)
    def test_incorrect_date(self):
        with self.assertRaises(ValidationError) as e:
            validate_fpic("320181-900C")
        self.assertEqual(e.exception.message, "Incorrect date part.")

    @override_settings(ALLOW_TEST_FPIC=True)
    def test_incorrect_intermediate(self):
        with self.assertRaises(ValidationError) as e:
            validate_fpic("010181o900C")
        self.assertEqual(e.exception.message, "Incorrect intermediate character.")

    @override_settings(ALLOW_TEST_FPIC=True)
    def test_incorrect_checksum(self):
        with self.assertRaises(ValidationError) as e:
            validate_fpic("010181-900B")
        self.assertEqual(e.exception.message, "Incorrect checksum.")


class ValidatePhoneNumberTests(TestCase):
    def test_correct_number(self):
        self.assertIsNone(validate_phone_number("+35850123456789"))

    def test_without_plus_sign(self):
        with self.assertRaises(ValidationError) as e:
            validate_phone_number("35850123456789")
        self.assertEqual(e.exception.message, "Phone number must start with a plus sign.")

    def test_invalid_characters(self):
        with self.assertRaises(ValidationError) as e:
            validate_phone_number("+35850132a456")
        self.assertEqual(e.exception.message, "Phone number contains invalid characters.")
        with self.assertRaises(ValidationError) as e:
            validate_phone_number("+358 50132456")
        self.assertEqual(e.exception.message, "Phone number contains invalid characters.")

    def test_too_short(self):
        with self.assertRaises(ValidationError) as e:
            validate_phone_number("+358501")
        self.assertEqual(e.exception.message, "Phone number is too short.")


class ValidateEidasIdentifierTests(TestCase):
    def test_correct_identifier(self):
        self.assertIsNone(validate_eidas_identifier("FI/ES/1234567"))

    def test_invalid_identifiers(self):
        for identifier in ["FIN/ES/1234567", "/FI/ES/1234567", "FI/ES/", "FI/12 123"]:
            with self.assertRaises(ValidationError) as e:
                validate_eidas_identifier(identifier)
            self.assertEqual(e.exception.message, "Invalid eIDAS identifier format.")
