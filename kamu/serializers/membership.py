"""
Serializers for role models.
"""

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _
from rest_framework import serializers
from rest_framework.fields import Field

from kamu.models.membership import Membership
from kamu.models.role import Role
from kamu.serializers.mixins import EagerLoadingMixin
from kamu.validators.membership import validate_membership

logger = logging.getLogger(__name__)


class MembershipSerializer(serializers.ModelSerializer[Membership], EagerLoadingMixin):
    """
    Serializer for :class:`kamu.models.membership.Membership`.
    """

    approver = serializers.SlugRelatedField(
        slug_field="username", queryset=get_user_model().objects.all(), required=False
    )
    inviter = serializers.SlugRelatedField(
        slug_field="username", queryset=get_user_model().objects.all(), required=False
    )

    _SELECT_RELATED_FIELDS = ["approver", "inviter"]

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
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "status",
            "created_at",
            "updated_at",
        ]


class MembershipLimitedIdentitySerializer(serializers.ModelSerializer[Membership]):
    """
    Limited read only serializer for :class:`kamu.models.membership.Membership` to use with IdentitySerializer.
    """

    role: Field = serializers.SlugRelatedField(read_only=True, slug_field="identifier")

    class Meta:
        model = Membership
        fields = [
            "id",
            "role",
            "start_date",
            "expire_date",
            "status",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def to_representation(self, value: Membership) -> dict[str, Any]:
        """
        Build flat representation of the hierarchical role data.
        """
        iam_groups = set()
        permissions = set()
        parents = set()

        def get_role(role: Role) -> None:
            """
            Get roles and their permissions recursively.
            """
            if role is not value.role:
                parents.add(role.identifier)
            if role.iam_group:
                iam_groups.add(role.iam_group)
            for permission in role.permissions.all():
                permissions.add(permission.identifier)
            if role.parent and role.parent.identifier not in parents:
                get_role(role.parent)

        get_role(value.role)
        membership = {
            "id": value.id,
            "start_date": value.start_date,
            "expire_date": value.expire_date,
            "status": value.status,
            "role": value.role.identifier,
            "parents": list(parents),
            "permissions": list(permissions),
            "iam_groups": list(iam_groups),
            "created_at": value.created_at,
            "updated_at": value.updated_at,
        }
        return membership
