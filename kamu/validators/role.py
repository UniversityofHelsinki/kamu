"""
Custom validators for roles.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import ValidationError as DRFValidationError

if TYPE_CHECKING:
    from kamu.models.role import Role


def validate_role_hierarchy(
    error_class: type[ValidationError] | type[DRFValidationError],
    initial_role: Role | None,
    parent: Role | None,
) -> None:
    """
    Detects circular role hierarchy and hierarchy maximum depth.

    Cannot have circular hierarchy when creating a new role, only when changing the parent node.
    """
    n = 1
    while parent:
        n += 1
        if n > settings.ROLE_HIERARCHY_MAXIMUM_DEPTH:
            raise error_class(_("Role hierarchy cannot be more than maximum depth."))
        if initial_role and parent == initial_role:
            raise error_class(_("Role cannot be in its own hierarchy."))
        parent = parent.parent
