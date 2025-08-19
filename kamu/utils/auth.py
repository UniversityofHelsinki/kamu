"""
Helper functions
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType

if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser


def set_default_permissions(instance: AbstractBaseUser | Group, remove: bool = False) -> None:
    """
    Set default permissions for a group or user.
    """

    default_permissions = [
        ("kamu", "role", "search_roles"),
        ("kamu", "identity", "search_identities"),
        ("kamu", "identity", "view_basic_information"),
    ]
    for app, model, codename in default_permissions:
        content_type = ContentType.objects.get(app_label=app, model=model)
        permission = Permission.objects.get(content_type=content_type, codename=codename)
        if remove:
            if hasattr(instance, "permissions"):
                instance.permissions.remove(permission)
            elif hasattr(instance, "user_permissions"):
                instance.user_permissions.remove(permission)
        else:
            if hasattr(instance, "permissions"):
                instance.permissions.add(permission)
            elif hasattr(instance, "user_permissions"):
                instance.user_permissions.add(permission)
