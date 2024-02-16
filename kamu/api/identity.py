"""
Identity views for API endpoints.
"""

from rest_framework import viewsets

from kamu.api.generic import CustomDjangoModelPermissions
from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.serializers.identity import (
    ContractSerializer,
    ContractTemplateSerializer,
    EmailAddressSerializer,
    IdentifierSerializer,
    IdentitySerializer,
    PhoneNumberSerializer,
)


class ContractViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for contracts.
    """

    queryset = Contract.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = ContractSerializer


class ContractTemplateViewSet(viewsets.ModelViewSet):
    """
    API endpoint for contracts.
    """

    queryset = ContractTemplate.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = ContractTemplateSerializer


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
