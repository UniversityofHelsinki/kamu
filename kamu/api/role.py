"""
Role views for API endpoints.
"""

from django.db.models import QuerySet
from rest_framework import viewsets

from kamu.api.generic import CustomDjangoModelPermissions
from kamu.models.role import Permission, Requirement, Role
from kamu.serializers.role import (
    PermissionSerializer,
    RequirementSerializer,
    RoleSerializer,
)


class PermissionViewSet(viewsets.ModelViewSet):
    """
    API endpoint for Kamu permissions.
    """

    queryset = Permission.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = PermissionSerializer


class RequirementViewSet(viewsets.ModelViewSet):
    """
    API endpoint for requirements.
    """

    queryset = Requirement.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = RequirementSerializer


class RoleViewSet(viewsets.ModelViewSet):
    """
    API endpoint for roles.
    """

    queryset = Role.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = RoleSerializer

    def get_queryset(self) -> QuerySet:
        """
        Setup eager loading of related fields.
        """
        queryset = super().get_queryset()
        queryset = RoleSerializer.setup_eager_loading(queryset)
        return queryset
