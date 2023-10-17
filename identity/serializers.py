from rest_framework import serializers

from identity.models import Attribute, AttributeType, Identity


class AttributeSerializer(serializers.ModelSerializer[Attribute]):
    type = serializers.SlugRelatedField(slug_field="name", read_only=True, source="attribute_type")  # type: ignore

    class Meta:
        model = Attribute
        fields = [
            "id",
            "identity",
            "type",
            "value",
            "source",
            "validated",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]


class AttributeTypeSerializer(serializers.ModelSerializer[AttributeType]):
    class Meta:
        model = AttributeType
        fields = [
            "id",
            "name",
            "multi_value",
            "unique",
            "regex_pattern",
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
            "roles",
            "attributes",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]
