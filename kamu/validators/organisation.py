"""
Custom validators for organisations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import ValidationError as DRFValidationError

if TYPE_CHECKING:
    from kamu.models.organisation import Organisation


def validate_organisation_hierarchy(
    error_class: type[ValidationError] | type[DRFValidationError],
    initial_organisation: Organisation | None,
    parent: Organisation | None,
) -> None:
    """
    Detects circular organisation hierarchy and hierarchy maximum depth.

    Cannot have circular hierarchy when creating a new organisation, only when changing the parent node.
    """
    n = 1
    while parent:
        n += 1
        if n > settings.ORGANISATION_HIERARCHY_MAXIMUM_DEPTH:
            raise error_class(_("Organisation hierarchy cannot be deeper than maximum depth."))
        if initial_organisation and parent == initial_organisation:
            raise error_class(_("Organisation cannot be in its own hierarchy."))
        parent = parent.parent
