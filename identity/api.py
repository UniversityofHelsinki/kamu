"""
Identity app views for API endpoints.
"""

from rest_framework import viewsets

from base.api import CustomDjangoModelPermissions
from identity.models import EmailAddress, Identifier, Identity, PhoneNumber
from identity.serializers import (
    EmailAddressSerializer,
    IdentifierSerializer,
    IdentitySerializer,
    PhoneNumberSerializer,
)


class EmailAddressViewSet(viewsets.ModelViewSet):
    """
    API endpoint for email addresses.
    """

    queryset = EmailAddress.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = EmailAddressSerializer


class PhoneNumberViewSet(viewsets.ModelViewSet):
    """
    API endpoint for phone numbers.
    """

    queryset = PhoneNumber.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = PhoneNumberSerializer


class IdentifierViewSet(viewsets.ModelViewSet):
    """
    API endpoint for unique identifiers.
    """

    queryset = Identifier.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = IdentifierSerializer


class IdentityViewSet(viewsets.ModelViewSet):
    """
    API endpoint for identities.
    """

    queryset = Identity.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = IdentitySerializer
