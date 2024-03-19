"""
Serializers for identity models.
"""

from django.conf import settings
from django.core.validators import EmailValidator
from django.utils.translation import gettext as _
from rest_framework import serializers
from rest_framework.fields import Field
from rest_framework.validators import UniqueTogetherValidator

from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import (
    EmailAddress,
    Identifier,
    Identity,
    Nationality,
    PhoneNumber,
)
from kamu.serializers.membership import MembershipLimitedIdentitySerializer
from kamu.serializers.mixins import EagerLoadingMixin
from kamu.validators.identity import FpicValidator


class ContractTemplateSerializer(serializers.ModelSerializer[Contract]):
    """
    Serializer for :class:`kamu.models.contract.ContractTemplate`.
    """

    class Meta:
        model = ContractTemplate
        fields = [
            "id",
            "type",
            "version",
            "name_en",
            "name_fi",
            "name_sv",
            "text_en",
            "text_fi",
            "text_sv",
            "public",
            "created_at",
        ]
        read_only_fields = [
            "created_at",
        ]


class ContractSerializer(serializers.ModelSerializer[Contract], EagerLoadingMixin):
    """
    Serializer for :class:`kamu.models.contract.Contract`.
    """

    template = ContractTemplateSerializer(read_only=True)

    _SELECT_RELATED_FIELDS = ["template"]

    class Meta:
        model = Contract
        fields = [
            "id",
            "identity",
            "template",
            "checksum",
            "lang",
            "created_at",
        ]
        read_only_fields = fields


class ContractLimitedSerializer(serializers.ModelSerializer[Contract]):
    """
    Limited read only serializer for :class:`kamu.models.contract.Contract` to use with IdentitySerializer.
    """

    template: Field = serializers.SlugRelatedField(read_only=True, slug_field="type")

    class Meta:
        model = Contract
        fields = [
            "id",
            "template",
            "created_at",
        ]
        read_only_fields = fields


class EmailAddressSerializer(serializers.ModelSerializer[EmailAddress]):
    """
    Serializer for :class:`kamu.models.identity.EmailAddress`.
    """

    class Meta:
        model = EmailAddress
        fields = [
            "id",
            "identity",
            "address",
            "priority",
            "verified",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]
        validators = [
            UniqueTogetherValidator(
                queryset=EmailAddress.objects.all(),
                fields=["identity", "address"],
                message=_("This identity already has the given email address."),
            )
        ]

    def validate_address(self, value: str) -> str:
        """
        Validates address with Django's built-in email validator.
        """
        validator = EmailValidator()
        validator(value)
        return value


class EmailAddressLimitedSerializer(serializers.ModelSerializer[EmailAddress]):
    """
    Limited read only serializer for :class:`kamu.models.identity.EmailAddress` to use with IdentitySerializer.
    """

    class Meta:
        model = EmailAddress
        fields = [
            "id",
            "address",
            "priority",
            "verified",
        ]
        read_only_fields = fields


class PhoneNumberSerializer(serializers.ModelSerializer[PhoneNumber]):
    """
    Serializer for :class:`kamu.models.identity.PhoneNumber`.
    """

    class Meta:
        model = PhoneNumber
        fields = [
            "id",
            "identity",
            "number",
            "priority",
            "verified",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]
        validators = [UniqueTogetherValidator(queryset=PhoneNumber.objects.all(), fields=["identity", "number"])]


class PhoneNumberLimitedSerializer(serializers.ModelSerializer[PhoneNumber]):
    """
    Limited read only serializer for :class:`kamu.models.identity.PhoneNumber` to use with IdentitySerializer.
    """

    class Meta:
        model = PhoneNumber
        fields = [
            "id",
            "number",
            "priority",
            "verified",
        ]
        read_only_fields = fields


class IdentifierSerializer(serializers.ModelSerializer[Identifier]):
    """
    Serializer for :class:`kamu.models.identity.Identifier`.
    """

    class Meta:
        model = Identifier
        fields = [
            "id",
            "identity",
            "type",
            "value",
            "verified",
            "deactivated_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]


class IdentifierLimitedSerializer(serializers.ModelSerializer[Identifier]):
    """
    Limited read only serializer for :class:`kamu.models.identity.Identifier` to use with IdentitySerializer.
    """

    class Meta:
        model = Identifier
        fields = [
            "id",
            "type",
            "value",
            "verified",
            "deactivated_at",
        ]
        read_only_fields = fields


class IdentitySerializer(serializers.ModelSerializer[Identity], EagerLoadingMixin):
    """
    Serializer for :class:`kamu.models.identity.Identity`.
    """

    contracts: Field = ContractLimitedSerializer(many=True, read_only=True)
    email_addresses: Field = EmailAddressLimitedSerializer(many=True, read_only=True)
    identifiers: Field = IdentifierLimitedSerializer(many=True, read_only=True)
    memberships: Field = MembershipLimitedIdentitySerializer(source="membership_set", many=True, read_only=True)
    nationality: Field = serializers.SlugRelatedField(
        many=True, queryset=Nationality.objects.all(), allow_null=True, slug_field="code"
    )
    phone_numbers: Field = PhoneNumberLimitedSerializer(many=True, read_only=True)

    @staticmethod
    def get_prefetch_fields() -> list[str]:
        """
        Create list of prefetch fields, taking into account the role hierarchy maximum depth.
        """
        max_depth = settings.ROLE_HIERARCHY_MAXIMUM_DEPTH
        fields = [
            "contracts",
            "contracts__template",
            "email_addresses",
            "identifiers",
            "nationality",
            "phone_numbers",
        ]
        parent = ""
        for i in range(max_depth):
            fields.append(f"membership_set__role{parent}")
            fields.append(f"membership_set__role{parent}__owner")
            fields.append(f"membership_set__role{parent}__approvers")
            fields.append(f"membership_set__role{parent}__inviters")
            fields.append(f"membership_set__role{parent}__permissions")
            fields.append(f"membership_set__role{parent}__permissions__requirements")
            fields.append(f"membership_set__role{parent}__requirements")
            parent += "__parent"
        return fields

    _PREFETCH_RELATED_FIELDS = get_prefetch_fields()

    class Meta:
        model = Identity
        fields = [
            "id",
            "assurance_level",
            "date_of_birth",
            "external",
            "fpic",
            "gender",
            "given_names",
            "given_name_display",
            "kamu_id",
            "preferred_language",
            "surname",
            "surname_display",
            "uid",
            "user",
            "contracts",
            "email_addresses",
            "identifiers",
            "memberships",
            "nationality",
            "phone_numbers",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]

    def validate_fpic(self, value: str) -> str:
        """
        Validates finnish personal identity code
        """
        validator = FpicValidator()
        validator(value)
        return value
