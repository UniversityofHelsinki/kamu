"""
Serializers for identity models.
"""

from django.core.validators import EmailValidator
from django.utils.translation import gettext as _
from rest_framework import serializers
from rest_framework.fields import Field
from rest_framework.validators import UniqueTogetherValidator

from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.validators.identity import FpicValidator


class ContractTemplateSerializer(serializers.ModelSerializer[Contract]):
    """
    Serializer for :model:`kamu.ContractTemplate`.
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


class ContractSerializer(serializers.ModelSerializer[Contract]):
    """
    Serializer for :model:`kamu.Contract`.
    """

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
    Serializer for :model:`kamu.Contract`.
    Limited information to use with IdentitySerializer.
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
    Serializer for :model:`kamu.EmailAddress`.
    """

    class Meta:
        model = EmailAddress
        fields = [
            "id",
            "identity",
            "address",
            "priority",
            "verified",
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


class PhoneNumberSerializer(serializers.ModelSerializer[PhoneNumber]):
    """
    Serializer for :model:`kamu.PhoneNumber`.
    """

    class Meta:
        model = PhoneNumber
        fields = [
            "id",
            "identity",
            "number",
            "priority",
            "verified",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]
        validators = [UniqueTogetherValidator(queryset=PhoneNumber.objects.all(), fields=["identity", "number"])]


class IdentifierSerializer(serializers.ModelSerializer[Identifier]):
    """
    Serializer for :model:`kamu.Identifier`.
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
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]


class IdentitySerializer(serializers.ModelSerializer[Identity]):
    """
    Serializer for :model:`kamu.Identity`.
    """

    contracts: Field = ContractLimitedSerializer(many=True, read_only=True)
    email_addresses: Field = serializers.SlugRelatedField(many=True, read_only=True, slug_field="address")
    phone_numbers: Field = serializers.SlugRelatedField(many=True, read_only=True, slug_field="number")
    roles: Field = serializers.SlugRelatedField(many=True, read_only=True, slug_field="identifier")

    class Meta:
        model = Identity
        fields = [
            "id",
            "kamu_id",
            "user",
            "external",
            "uid",
            "assurance_level",
            "given_names",
            "surname",
            "given_name_display",
            "surname_display",
            "date_of_birth",
            "gender",
            "nationality",
            "fpic",
            "preferred_language",
            "roles",
            "email_addresses",
            "phone_numbers",
            "contracts",
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
