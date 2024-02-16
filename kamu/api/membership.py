"""
Role views for API endpoints.
"""

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
