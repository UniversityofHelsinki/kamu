"""
Role app views for API endpoints.
"""

from django.db.models import QuerySet
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from role.models import Membership, Permission, Role
from role.serializers import MembershipSerializer, PermissionSerializer, RoleSerializer


class MembershipViewSet(viewsets.ModelViewSet):
    """
    API endpoint for role memberships.
    """

    queryset = Membership.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = MembershipSerializer

    def get_queryset(self) -> QuerySet[Membership]:
        """
        Restricts queryset to authenticated user, if user is not a superuser.
        """
        user = self.request.user if self.request.user.is_authenticated else None
        if user and user.is_superuser:
            return Membership.objects.all()
        identity = user.identity if user and hasattr(user, "identity") else None
        return Membership.objects.filter(identity=identity)


class PermissionViewSet(viewsets.ModelViewSet):
    """
    API endpoint for roles.
    """

    queryset = Permission.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = PermissionSerializer


class RoleViewSet(viewsets.ModelViewSet):
    """
    API endpoint for roles.
    """

    queryset = Role.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = RoleSerializer
