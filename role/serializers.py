import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils.translation import gettext as _
from rest_framework import serializers

from role.models import Membership, Permission, Role

logger = logging.getLogger(__name__)


class MembershipSerializer(serializers.ModelSerializer[Membership]):
    approver = serializers.SlugRelatedField(
        slug_field="username", queryset=get_user_model().objects.all(), required=False
    )

    def validate(self, data):
        if data["start_date"] > data["expire_date"]:
            raise serializers.ValidationError(_("Start date cannot be later than expire date"))
        if (data["expire_date"] - data["start_date"]).days > data["role"].maximum_duration:
            raise serializers.ValidationError(_("Role duration cannot be more than maximum duration"))
        return data

    class Meta:
        model = Membership
        fields = [
            "id",
            "identity",
            "role",
            "approver",
            "start_date",
            "expire_date",
        ]


class PermissionSerializer(serializers.ModelSerializer[Permission]):
    class Meta:
        model = Permission
        fields = [
            "id",
            "name",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]


class RoleSerializer(serializers.ModelSerializer[Role]):
    owner = serializers.SlugRelatedField(
        slug_field="username", required=False, queryset=get_user_model().objects.all()
    )
    parent = serializers.SlugRelatedField(slug_field="name", required=False, queryset=Role.objects.all())  # type: ignore
    inviters = serializers.SlugRelatedField(slug_field="name", required=False, many=True, queryset=Group.objects.all())
    approvers = serializers.SlugRelatedField(
        slug_field="name", required=False, many=True, queryset=Group.objects.all()
    )

    class Meta:
        model = Role
        fields = ["id", "name", "owner", "parent", "inviters", "approvers", "maximum_duration"]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]
