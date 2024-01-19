"""
Role app views for API endpoints.
"""

from rest_framework import viewsets

from base.api import CustomDjangoModelPermissions
from role.models import Membership, Permission, Role
from role.serializers import MembershipSerializer, PermissionSerializer, RoleSerializer


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
