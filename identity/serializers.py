from rest_framework import serializers

from identity.models import Identity


class IdentitySerializer(serializers.ModelSerializer[Identity]):
    class Meta:
        model = Identity
        fields = [
            "id",
            "user",
            "roles",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
        ]
