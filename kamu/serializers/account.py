"""
Serializers for account models.
"""

from rest_framework import serializers

from kamu.models.account import Account


class AccountSerializer(serializers.ModelSerializer[Account]):
    """
    Serializer for :class:`kamu.models.account.Account`.
    """

    class Meta:
        model = Account
        fields = [
            "id",
            "identity",
            "type",
            "status",
            "uid",
            "deactivated_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]


class AccountLimitedSerializer(serializers.ModelSerializer[Account]):
    """
    Limited read only serializer for :class:`kamu.models.account.Account` to use with IdentitySerializer.
    """

    class Meta:
        model = Account
        fields = [
            "id",
            "type",
            "status",
            "uid",
        ]
        read_only_fields = fields
