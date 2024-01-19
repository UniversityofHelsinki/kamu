"""
Custom API classes for Kamu
"""

from rest_framework import permissions


class CustomDjangoModelPermissions(permissions.DjangoModelPermissions):
    """
    Custom DjangoModelPermissions class for Kamu. Default DjangoModelPermissions
    doesn't restrict view access. It'll be changed in the next major DRF release.
    DRF PR #8009
    """

    perms_map = {
        "GET": ["%(app_label)s.view_%(model_name)s"],
        "OPTIONS": [],
        "HEAD": ["%(app_label)s.view_%(model_name)s"],
        "POST": ["%(app_label)s.add_%(model_name)s"],
        "PUT": ["%(app_label)s.change_%(model_name)s"],
        "PATCH": ["%(app_label)s.change_%(model_name)s"],
        "DELETE": ["%(app_label)s.delete_%(model_name)s"],
    }
