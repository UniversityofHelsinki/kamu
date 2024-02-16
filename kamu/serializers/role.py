"""
Serializers for role models.
"""

import logging
from typing import Any, Sequence

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils.translation import gettext as _
from rest_framework import serializers

from kamu.models.role import Membership, Permission, Role
from kamu.validators.role import validate_membership, validate_role_hierarchy

logger = logging.getLogger(__name__)


class MembershipSerializer(serializers.ModelSerializer[Membership]):
    """
    Serializer for :model:`kamu.Membership`.
    """

    approver = serializers.SlugRelatedField(
        slug_field="username", queryset=get_user_model().objects.all(), required=False
    )
    inviter = serializers.SlugRelatedField(
        slug_field="username", queryset=get_user_model().objects.all(), required=False
    )

    def validate(self, data: Any) -> Any:
        """
        Validates role membership data.
        """

        def get_attribute(attribute: Any) -> Any:
            """
            Get attribute from data or instance.

            The attribute is required to exist in either the supplied attribute data,
            or the existing instance in case of a partial update.
            """
            if attribute in data:
                return data[attribute]
            elif self.instance and hasattr(self.instance, attribute):
                return getattr(self.instance, attribute)
            raise serializers.ValidationError(_("Field %(attribute)s is required") % {"attribute": attribute})

        role = get_attribute("role")
        start_date = get_attribute("start_date")
        expire_date = get_attribute("expire_date")
        validate_membership(serializers.ValidationError, role, start_date, expire_date)
        return data

    class Meta:
        model = Membership
        fields = [
            "id",
            "identity",
            "role",
            "approver",
            "inviter",
            "reason",
            "invite_email_address",
            "status",
            "start_date",
            "expire_date",
        ]
        read_only_fields = [
            "status",
            "created_at",
            "updated_at",
        ]


class PermissionSerializer(serializers.ModelSerializer[Permission]):
    """
    Serializer for :model:`kamu.Permission`.
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
    Serializer for :model:`kamu.Role`.
    """

    owner = serializers.SlugRelatedField(
        slug_field="username", required=False, queryset=get_user_model().objects.all()
    )
    parent = serializers.SlugRelatedField(slug_field="identifier", required=False, queryset=Role.objects.all())  # type: ignore
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