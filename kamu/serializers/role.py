"""
Serializers for role models.
"""

import logging
from typing import Sequence

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils.translation import gettext as _
from rest_framework import serializers

from kamu.models.role import Permission, Role
from kamu.validators.role import validate_role_hierarchy

logger = logging.getLogger(__name__)


class PermissionSerializer(serializers.ModelSerializer[Permission]):
    """
    Serializer for :class:`kamu.models.role.Permission`.
    """

    class Meta:
        model = Permission
        fields = [
            "id",
            "identifier",
            "name_fi",
            "name_en",
            "name_sv",
            "description_fi",
            "description_en",
            "description_sv",
            "cost",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]


class RoleSerializer(serializers.ModelSerializer[Role]):
    """
    Serializer for :class:`kamu.models.role.Role`.
    """

    owner = serializers.SlugRelatedField(
        slug_field="username", required=False, queryset=get_user_model().objects.all()
    )
    parent = serializers.SlugRelatedField(
        slug_field="identifier", required=False, queryset=Role.objects.all()
    )  # type: ignore
    inviters = serializers.SlugRelatedField(slug_field="name", required=False, many=True, queryset=Group.objects.all())
    approvers = serializers.SlugRelatedField(
        slug_field="name", required=False, many=True, queryset=Group.objects.all()
    )
    permissions = serializers.SlugRelatedField(
        slug_field="identifier", required=False, many=True, queryset=Permission.objects.all()
    )

    class Meta:
        model = Role
        fields = [
            "id",
            "identifier",
            "name_fi",
            "name_en",
            "name_sv",
            "description_fi",
            "description_en",
            "description_sv",
            "parent",
            "owner",
            "organisation_unit",
            "notification_email_address",
            "notification_language",
            "inviters",
            "approvers",
            "permissions",
            "iam_group",
            "maximum_duration",
            "purge_delay",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]

    def validate_parent(self, value: Role | None) -> Role | None:
        """
        Validate parent for circular role hierarchy and hierarchy maximum depth.

        In a normal situations, sequence data is never validated as create and update deal in single instances.
        """
        if isinstance(self.instance, Sequence):
            raise ValueError(_("Cannot validate sequence data"))
        validate_role_hierarchy(serializers.ValidationError, self.instance, value)
        return value
