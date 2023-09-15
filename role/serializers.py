import logging

from rest_framework import serializers

from role.models import Membership, Role

logger = logging.getLogger(__name__)


class MembershipSerializer(serializers.ModelSerializer[Membership]):
    class Meta:
        model = Membership
        fields = [
            "id",
            "identity",
            "role",
            "start_date",
            "expiring_date",
        ]


class RoleSerializer(serializers.ModelSerializer[Role]):
    class Meta:
        model = Role
        fields = [
            "id",
            "name",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]
