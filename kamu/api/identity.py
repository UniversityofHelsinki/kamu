"""
Identity views for API endpoints.
"""

from django.db.models import QuerySet
from django_filters import rest_framework as filters
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

    def get_queryset(self) -> QuerySet:
        """
        Setup eager loading of related fields.
        """
        queryset = super().get_queryset()
        queryset = ContractSerializer.setup_eager_loading(queryset)
        return queryset


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


class IdentityFilter(filters.FilterSet):
    """
    Custom filters for identities.
    """

    member = filters.CharFilter(field_name="membership__role__identifier")
    updated = filters.DateTimeFilter(field_name="updated_at", lookup_expr="gte")

    class Meta:
        model = Identity
        fields = ["kamu_id", "uid", "fpic"]


class IdentityViewSet(viewsets.ModelViewSet):
    """
    API endpoint for identities.
    """

    queryset = Identity.objects.all()
    filterset_class = IdentityFilter
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = IdentitySerializer

    def get_queryset(self) -> QuerySet:
        """
        Setup eager loading of related fields.
        """
        queryset = super().get_queryset()
        queryset = IdentitySerializer.setup_eager_loading(queryset)
        return queryset
