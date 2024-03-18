"""
Role views for API endpoints.
"""

from django.db.models import QuerySet
from rest_framework import viewsets

from kamu.api.generic import CustomDjangoModelPermissions
from kamu.models.membership import Membership
from kamu.serializers.membership import MembershipSerializer


class MembershipViewSet(viewsets.ModelViewSet):
    """
    API endpoint for role memberships.
    """

    queryset = Membership.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = MembershipSerializer

    def get_queryset(self) -> QuerySet:
        """
        Setup eager loading of related fields.
        """
        queryset = super().get_queryset()
        queryset = MembershipSerializer.setup_eager_loading(queryset)
        return queryset
