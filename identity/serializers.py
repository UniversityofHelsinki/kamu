import re

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from identity.models import (
    Attribute,
    AttributeType,
    Identifier,
    Identity,
    validate_attribute,
)


class AttributeSerializer(serializers.ModelSerializer[Attribute]):
    class Meta:
        model = Attribute
        fields = [
            "id",
            "identity",
            "attribute_type",
            "value",
            "source",
            "priority",
            "validated",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]

    def validate(self, data):
        def get_attribute(attribute) -> str:
            if attribute in data:
                return data[attribute]
            elif self.instance and hasattr(self.instance, attribute):
                return getattr(self.instance, attribute)
            raise serializers.ValidationError(_(f"Field {attribute} is required"))

        attribute_type = get_attribute("attribute_type")
        identity = get_attribute("identity")
        value = get_attribute("value")
        if self.instance and hasattr(self.instance, "pk"):
            pk = self.instance.pk
        else:
            pk = None
        validate_attribute(serializers.ValidationError, attribute_type, identity, value, pk)
        return data


class AttributeTypeSerializer(serializers.ModelSerializer[AttributeType]):
    class Meta:
        model = AttributeType
        fields = [
            "id",
            "identifier",
            "name_fi",
            "name_en",
            "name_sv",
            "description_fi",
            "description_en",
            "description_sv",
            "multi_value",
            "unique",
            "regex_pattern",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]

    def validate_regex_pattern(self, value):
        try:
            re.compile(value)
        except re.error:
            raise serializers.ValidationError(_("Invalid regex pattern"))
        return value


class IdentifierSerializer(serializers.ModelSerializer[Attribute]):
    class Meta:
        model = Identifier
        fields = [
            "id",
            "identity",
            "type",
            "value",
            "validated",
            "deactivated_at",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]


class IdentitySerializer(serializers.ModelSerializer[Identity]):
    attributes = AttributeSerializer(many=True, read_only=True)

    class Meta:
        model = Identity
        fields = [
            "id",
            "user",
            "name",
            "external",
            "roles",
            "attributes",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]
