"""
Unit tests for role app.
"""

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from identity.validators import validate_fpic


class ValidateSSNTests(TestCase):
    @override_settings(ALLOW_TEST_FPIC=True)
    def test_correct_ssn(self):
        self.assertIsNone(validate_fpic("010181-900C"))

    @override_settings(ALLOW_TEST_FPIC=False)
    def test_test_ssn(self):
        with self.assertRaises(ValidationError) as e:
            validate_fpic("010181-900C")
        self.assertEqual(e.exception.message, "Incorrect numeric part")

    @override_settings(ALLOW_TEST_FPIC=True)
    def test_incorrect_date(self):
        with self.assertRaises(ValidationError) as e:
            validate_fpic("320181-900C")
        self.assertEqual(e.exception.message, "Incorrect date part")

    @override_settings(ALLOW_TEST_FPIC=True)
    def test_incorrect_intermediate(self):
        with self.assertRaises(ValidationError) as e:
            validate_fpic("010181o900C")
        self.assertEqual(e.exception.message, "Incorrect intermediate character")

    @override_settings(ALLOW_TEST_FPIC=True)
    def test_incorrect_checksum(self):
        with self.assertRaises(ValidationError) as e:
            validate_fpic("010181-900B")
        self.assertEqual(e.exception.message, "Incorrect checksum")
