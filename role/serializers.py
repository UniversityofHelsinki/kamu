import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils.translation import gettext as _
from rest_framework import serializers

from identity.models import AttributeType
from role.models import (
    Membership,
    Permission,
    Role,
    validate_membership,
    validate_role_hierarchy,
)

logger = logging.getLogger(__name__)


class MembershipSerializer(serializers.ModelSerializer[Membership]):
    approver = serializers.SlugRelatedField(
        slug_field="username", queryset=get_user_model().objects.all(), required=False
    )
    inviter = serializers.SlugRelatedField(
        slug_field="username", queryset=get_user_model().objects.all(), required=False
    )

    def validate(self, data):
        def get_attribute(attribute) -> str:
            if attribute in data:
                return data[attribute]
            elif self.instance and hasattr(self.instance, attribute):
                return getattr(self.instance, attribute)
            raise serializers.ValidationError(_(f"Field {attribute} is required"))

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
            "start_date",
            "expire_date",
        ]
        read_only_fields = [
            "status",
            "created_at",
            "updated_at",
        ]


class PermissionSerializer(serializers.ModelSerializer[Permission]):
    requirements = serializers.SlugRelatedField(
        slug_field="identifier", required=False, many=True, queryset=AttributeType.objects.all()
    )

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
            "requirements",
            "cost",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]


class RoleSerializer(serializers.ModelSerializer[Role]):
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
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]

    def validate_parent(self, value):
        validate_role_hierarchy(serializers.ValidationError, self.instance, value)
        return value
