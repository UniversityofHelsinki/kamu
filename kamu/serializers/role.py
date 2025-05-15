"""
Serializers for role models.
"""

import logging
from typing import Sequence

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from kamu.models.organisation import Organisation
from kamu.models.role import Permission, Requirement, Role
from kamu.serializers.mixins import EagerLoadingMixin
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
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]


class RequirementSerializer(serializers.ModelSerializer[Requirement]):
    """
    Serializer for :class:`kamu.models.role.Requirement`.
    """

    class Meta:
        model = Requirement
        fields = [
            "id",
            "name_fi",
            "name_en",
            "name_sv",
            "type",
            "level",
            "grace",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]


class RoleSerializer(serializers.ModelSerializer[Role], EagerLoadingMixin):
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
    organisation = serializers.SlugRelatedField(slug_field="code", required=False, queryset=Organisation.objects.all())

    _PREFETCH_RELATED_FIELDS = ["inviters", "approvers", "permissions", "requirements", "organisation"]
    _SELECT_RELATED_FIELDS = ["owner", "parent"]

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
            "organisation",
            "notification_email_address",
            "notification_language",
            "inviters",
            "approvers",
            "permissions",
            "requirements",
            "iam_group",
            "maximum_duration",
            "purge_delay",
            "created_at",
            "updated_at",
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
            raise ValueError(_("Cannot validate sequence data."))
        validate_role_hierarchy(serializers.ValidationError, self.instance, value)
        return value
