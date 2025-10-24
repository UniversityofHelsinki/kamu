"""
Identity views for API endpoints.
"""

from django.db.models import QuerySet
from django_filters import rest_framework as filters

from kamu.api.generic import (
    AuditLogModelViewSet,
    AuditLogReadModelViewSet,
    CustomDjangoModelPermissions,
)
from kamu.models.contract import Contract, ContractTemplate
from kamu.models.identity import (
    EmailAddress,
    Identifier,
    Identity,
    Nationality,
    PhoneNumber,
)
from kamu.serializers.identity import (
    ContractSerializer,
    ContractTemplateSerializer,
    EmailAddressSerializer,
    IdentifierSerializer,
    IdentitySerializer,
    NationalitySerializer,
    PhoneNumberSerializer,
)


class ContractViewSet(AuditLogReadModelViewSet):
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


class ContractTemplateViewSet(AuditLogModelViewSet):
    """
    API endpoint for contracts.
    """

    queryset = ContractTemplate.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = ContractTemplateSerializer


class EmailAddressViewSet(AuditLogModelViewSet):
    """
    API endpoint for email addresses.
    """

    queryset = EmailAddress.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = EmailAddressSerializer


class NationalityViewSet(AuditLogModelViewSet):
    """
    API endpoint for nationalities.
    """

    queryset = Nationality.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = NationalitySerializer


class PhoneNumberViewSet(AuditLogModelViewSet):
    """
    API endpoint for phone numbers.
    """

    queryset = PhoneNumber.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = PhoneNumberSerializer


class IdentifierViewSet(AuditLogModelViewSet):
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


class IdentityViewSet(AuditLogModelViewSet):
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
