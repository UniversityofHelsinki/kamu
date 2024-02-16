"""
Custom validators for roles.
"""

from __future__ import annotations

from datetime import date
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import ValidationError as DRFValidationError

if TYPE_CHECKING:
    from kamu.models.role import Role


def validate_membership(
    error_class: type[ValidationError] | type[DRFValidationError],
    role: Role,
    start_date: date,
    expire_date: date,
    edit: bool = False,
) -> None:
    """
    Validates membership dates.

    Allow past start dates when editing a membership. In this case, compare maximum role duration
    from the current date.
    """
    if expire_date < start_date:
        raise error_class({"expire_date": [_("Role expire date cannot be earlier than start date")]})
    if expire_date < timezone.now().date():
        raise error_class({"expire_date": [_("Role expire date cannot be in the past")]})
    if not edit and start_date < timezone.now().date():
        raise error_class({"start_date": [_("Role start date cannot be in the past")]})
    if start_date >= timezone.now().date() and (expire_date - start_date).days > role.maximum_duration:
        raise error_class({"expire_date": [_("Role duration cannot be more than maximum duration")]})
    if start_date < timezone.now().date() and (expire_date - timezone.now().date()).days > role.maximum_duration:
        raise error_class({"expire_date": [_("Role duration cannot be more than maximum duration")]})
