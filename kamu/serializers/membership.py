"""
Serializers for role models.
"""

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _
from rest_framework import serializers

from kamu.models.membership import Membership
from kamu.validators.membership import validate_membership

logger = logging.getLogger(__name__)


class MembershipSerializer(serializers.ModelSerializer[Membership]):
    """
    Serializer for :class:`kamu.models.membership.Membership`.
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
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "status",
            "created_at",
            "updated_at",
        ]
