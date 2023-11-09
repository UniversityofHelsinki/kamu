"""
Router configuration for the API endpoints.
"""

from rest_framework import routers

from identity.api import (
    AttributeTypeViewSet,
    AttributeViewSet,
    IdentifierViewSet,
    IdentityViewSet,
)
from role.api import MembershipViewSet, PermissionViewSet, RoleViewSet

router = routers.DefaultRouter()
router.register(r"attributes", AttributeViewSet)
router.register(r"attributetypes", AttributeTypeViewSet)
router.register(r"identifiers", IdentifierViewSet)
router.register(r"identities", IdentityViewSet)
router.register(r"memberships", MembershipViewSet)
router.register(r"permissions", PermissionViewSet)
router.register(r"roles", RoleViewSet)
