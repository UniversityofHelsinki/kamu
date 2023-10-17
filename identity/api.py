from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from identity.models import Attribute, AttributeType, Identity
from identity.serializers import (
    AttributeSerializer,
    AttributeTypeSerializer,
    IdentitySerializer,
)


class AttributeViewSet(viewsets.ModelViewSet):
    """API endpoint for attribute values"""

    queryset = Attribute.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = AttributeSerializer

    def get_queryset(self):
        """
        Restricts queryset to authenticated user if user is not a superuser
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if user and user.is_superuser:
            return Attribute.objects.all()
        return Attribute.objects.filter(identity__user=user)


class AttributeTypeViewSet(viewsets.ModelViewSet):
    """API endpoint for attribute types"""

    queryset = AttributeType.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = AttributeTypeSerializer


class IdentityViewSet(viewsets.ModelViewSet):
    """API endpoint for identities"""

    queryset = Identity.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = IdentitySerializer

    def get_queryset(self):
        """
        Restricts queryset to authenticated user if user is not a superuser
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if user and user.is_superuser:
            return Identity.objects.all()
        return Identity.objects.filter(user=user)
