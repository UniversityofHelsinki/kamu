from rest_framework import routers

from identity.api import IdentityViewSet
from role.api import MembershipViewSet, RoleViewSet

router = routers.DefaultRouter()
router.register(r"identities", IdentityViewSet)
router.register(r"memberships", MembershipViewSet)
router.register(r"roles", RoleViewSet)
