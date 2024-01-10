"""
Serializers for identity app models.
"""

from django.core.validators import EmailValidator
from django.utils.translation import gettext as _
from rest_framework import serializers
from rest_framework.fields import Field
from rest_framework.validators import UniqueTogetherValidator

from identity.models import EmailAddress, Identifier, Identity, PhoneNumber
from identity.validators import FpicValidator


class EmailAddressSerializer(serializers.ModelSerializer[EmailAddress]):
    """
    Serializer for :model:`identity.EmailAddress`.
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
    Serializer for :model:`identity.PhoneNumber`.
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
    Serializer for :model:`identity.Identifier`.
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
    Serializer for :model:`identity.Identity`.
    """

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
