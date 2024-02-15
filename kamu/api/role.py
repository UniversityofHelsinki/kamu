"""
Role views for API endpoints.
"""

from rest_framework import viewsets

from kamu.api.base import CustomDjangoModelPermissions
from kamu.models.role import Membership, Permission, Role
from kamu.serializers.role import (
    MembershipSerializer,
    PermissionSerializer,
    RoleSerializer,
)


class MembershipViewSet(viewsets.ModelViewSet):
    """
    API endpoint for role memberships.
    """

    queryset = Membership.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = MembershipSerializer


class PermissionViewSet(viewsets.ModelViewSet):
    """
    API endpoint for roles.
    """

    queryset = Permission.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = PermissionSerializer


class RoleViewSet(viewsets.ModelViewSet):
    """
    API endpoint for roles.
    """

    queryset = Role.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = RoleSerializer
