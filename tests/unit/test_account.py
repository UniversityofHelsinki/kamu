"""
Unit tests for accounts.
"""

from django.conf import settings
from django.utils import timezone

from kamu.models.account import Account
from kamu.models.identity import Identifier
from kamu.utils.account import get_account_data
from tests.setup import BaseTestCase


class AccountUnitTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.role = self.create_role("consultant")
        self.role2 = self.create_role("ext_employee")
        self.permission = self.create_permission("lightaccount")
        self.permission_service = self.create_permission("service")
        self.role.permissions.add(self.permission)
        self.role.permissions.add(self.permission_service)
        self.role2.permissions.add(self.permission)
        self.identity = self.create_identity(user=True, email=True)
        self.membership = self.create_membership(
            self.role, self.identity, start_delta_days=-2, expire_delta_days=1, approver=self.identity.user
        )
        self.membership2 = self.create_membership(
            self.role2, self.identity, start_delta_days=-2, expire_delta_days=5, approver=self.identity.user
        )
        self.identifier = Identifier.objects.create(
            identity=self.identity, type=Identifier.Type.EPPN, value="testuser@example.org"
        )
        self.identifier = Identifier.objects.create(
            identity=self.identity, type=Identifier.Type.MICROSOFT, value="123456789"
        )

    def test_account_data(self):
        data = get_account_data(self.identity, Account.Type.LIGHT)
        self.assertEqual(data.get("schacExpiryDate"), self.membership2.expire_date.isoformat())
        self.assertEqual(data.get("accountType"), 9)
        self.assertIn("affiliate", data.get("eduPersonAffiliation"))
        self.assertIn("service-identifier-1", data.get("lightAccountService"))
        self.assertIn(settings.LIGHT_ACCOUNT_DEFAULT_SERVICES[0], data.get("lightAccountService"))
        self.assertEqual(2, len(data.get("lightAccountExternalIdentifier")))
        self.assertIn("EPPN:testuser@example.org", data.get("lightAccountExternalIdentifier"))
        self.assertIn("MICROSOFT:123456789", data.get("lightAccountExternalIdentifier"))

    def test_account_data_ignore_deactivated_identifiers(self):
        self.identifier.deactivated_at = timezone.now()
        self.identifier.save()
        data = get_account_data(self.identity, Account.Type.LIGHT)
        self.assertEqual(1, len(data.get("lightAccountExternalIdentifier")))

    def test_account_data_gecos_normalised(self):
        self.identity.given_name_display = "Ääkköset"
        self.identity.surname_display = "Æaz-1-Д’at"
        self.identity.save()
        data = get_account_data(self.identity, Account.Type.LIGHT)
        self.assertEqual("Aakkoset az-1-at", data.get("gecos"))
