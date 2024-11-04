"""
Validators for the identity
"""

import re
import string
from datetime import datetime

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _


@deconstructible
class FpicValidator:
    """
    Validate Finnish personal identity code.
    """

    code = "invalid"

    def __init__(self, message: str | None = None, code: str | None = None) -> None:
        self.message = message
        if code is not None:
            self.code = code

    def __call__(self, value: str) -> None:
        if len(value) != 11:
            message = self.message or _("Personal identity code length should be 11 characters")
            raise ValidationError(message, self.code, params={"value": value})
        try:
            datetime.strptime(value[:6], "%d%m%y")
        except ValueError:
            message = self.message or _("Incorrect date part")
            raise ValidationError(message, self.code, params={"value": value}) from None
        if value[6] not in "+-ABCDEFYXWVU":
            message = self.message or _("Incorrect intermediate character")
            raise ValidationError(message, self.code, params={"value": value})
        allow_test_fpic = getattr(settings, "ALLOW_TEST_FPIC", False)
        if not value[7:10].isdigit() or int(value[7:10]) < 2 or (int(value[7:10]) > 899 and not allow_test_fpic):
            message = self.message or _("Incorrect numeric part")
            raise ValidationError(message, self.code, params={"value": value})
        checksum_characters = "0123456789ABCDEFHJKLMNPRSTUVWXY"
        if checksum_characters[int(value[:6] + value[7:10]) % 31] != value[10]:
            message = self.message or _("Incorrect checksum")
            raise ValidationError(message, self.code, params={"value": value})

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FpicValidator) and (self.message == other.message) and (self.code == other.code)


validate_fpic = FpicValidator()


@deconstructible
class PhoneNumberValidator:
    """
    Validate a phone number.

    Requires a phone number in international format, with only a plus sign and digits.
    """

    code = "invalid"

    def __init__(self, message: str | None = None, code: str | None = None) -> None:
        self.message = message
        if code is not None:
            self.code = code

    def __call__(self, value: str) -> None:
        if value[0] != "+":
            message = self.message or _("Phone number must start with a plus sign")
            raise ValidationError(message, self.code, params={"value": value})
        if not set(value[1:]).issubset(string.digits):
            message = self.message or _("Phone number contains invalid characters")
            raise ValidationError(message, self.code, params={"value": value})
        if len(value) < 8:
            message = self.message or _("Phone number is too short")
            raise ValidationError(message, self.code, params={"value": value})

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, PhoneNumberValidator) and (self.message == other.message) and (self.code == other.code)
        )


validate_phone_number = PhoneNumberValidator()


@deconstructible
class EidasIdentifierValidator:
    """
    Validate an eIDAS Unique Identifier.
    """

    code = "invalid"

    def __init__(self, message: str | None = None, code: str | None = None) -> None:
        self.message = message
        if code is not None:
            self.code = code

    def __call__(self, value: str) -> None:
        """
        Unique Identifier has two-letter country codes for source and destination country, and a unique identifier
        part, separated by slashes. Maximum total length is 256 characters and whitespace is not allowed.
        """
        if not re.match(r"^[A-Za-z]{2}/[A-Za-z]{2}/\S{1,250}$", value):
            message = self.message or _("Invalid eIDAS identifier format")
            raise ValidationError(message, self.code, params={"value": value})

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, EidasIdentifierValidator)
            and (self.message == other.message)
            and (self.code == other.code)
        )


validate_eidas_identifier = EidasIdentifierValidator()
