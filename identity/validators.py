"""
Validators for the identity app
"""
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

    def __init__(self, message=None, code=None) -> None:
        self.message = message
        if code is not None:
            self.code = code

    def __call__(self, value):
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

    def __eq__(self, other):
        return isinstance(other, FpicValidator) and (self.message == other.message) and (self.code == other.code)


validate_fpic = FpicValidator()
