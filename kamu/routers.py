"""
Router configuration for the API endpoints.
"""

from rest_framework import routers

from kamu.api.identity import (
    ContractTemplateViewSet,
    ContractViewSet,
    EmailAddressViewSet,
    IdentifierViewSet,
    IdentityViewSet,
    NationalityViewSet,
    PhoneNumberViewSet,
)
from kamu.api.membership import MembershipViewSet
from kamu.api.role import PermissionViewSet, RoleViewSet

router = routers.DefaultRouter()
router.register(r"contracts", ContractViewSet)
router.register(r"contracttemplates", ContractTemplateViewSet)
router.register(r"emailaddresses", EmailAddressViewSet)
router.register(r"identifiers", IdentifierViewSet)
router.register(r"identities", IdentityViewSet)
router.register(r"memberships", MembershipViewSet)
router.register(r"nationalities", NationalityViewSet)
router.register(r"permissions", PermissionViewSet)
router.register(r"phonenumbers", PhoneNumberViewSet)
router.register(r"roles", RoleViewSet)
