"""
Account views for API endpoints.
"""

from kamu.api.generic import AuditLogModelViewSet, CustomDjangoModelPermissions
from kamu.models.account import Account
from kamu.serializers.account import AccountSerializer


class AccountViewSet(AuditLogModelViewSet[Account]):
    """
    API endpoint for role memberships.
    """

    queryset = Account.objects.all()
    permission_classes = [CustomDjangoModelPermissions]
    serializer_class = AccountSerializer
