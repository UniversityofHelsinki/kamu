"""
Role views for API endpoints.
"""

from rest_framework import viewsets

from kamu.api.generic import CustomDjangoModelPermissions
from kamu.models.role import Permission, Role
from kamu.serializers.role import PermissionSerializer, RoleSerializer


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
