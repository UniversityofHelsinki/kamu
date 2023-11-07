import datetime

from django.test import TestCase, override_settings
from django.utils import timezone

from identity.models import Identity
from role.models import Membership, Permission, Role


class RoleModelTests(TestCase):
    def setUp(self):
        self.parent_role = Role.objects.create(identifier="parent", name_en="Parent Role", maximum_duration=20)
        self.role = Role.objects.create(
            identifier="testrole",
            name_en="Test Role",
            description_fi="Testirooli",
            maximum_duration=10,
            parent=self.parent_role,
        )
        self.account_permission = Permission.objects.create(identifier="account", name_en="Account permission", cost=5)
        self.licence_permission = Permission.objects.create(
            identifier="license", name_en="License permission", cost=15
        )
        self.parent_role.permissions.add(self.account_permission)
        self.role.permissions.add(self.licence_permission)

    def test_role_name(self):
        self.assertEqual(self.role.name(), "Test Role")

    def test_role_description(self):
        self.assertEqual(self.role.description(lang="fi"), "Testirooli")

    def test_role_hierarchy(self):
        self.assertEqual(self.parent_role.get_role_hierarchy().count(), 1)
        self.assertEqual(self.role.get_role_hierarchy().count(), 2)

    @override_settings(ROLE_HIERARCHY_MAXIMUM_DEPTH=1)
    def test_role_hierarchy_limit(self):
        self.assertEqual(self.role.get_role_hierarchy().count(), 1)

    def test_role_hierarchy_memberships(self):
        identity = Identity.objects.create(name="Test User")
        Membership.objects.create(
            role=self.parent_role,
            identity=identity,
            reason="Because",
            start_date=timezone.now().date(),
            expire_date=timezone.now().date() + datetime.timedelta(days=1),
        )
        self.assertEqual(self.role.get_hierarchy_memberships().count(), 1)

    def test_role_cost(self):
        self.assertEqual(self.parent_role.get_cost(), 5)
        self.assertEqual(self.role.get_cost(), 20)

    def test_role_permissions(self):
        self.assertEqual(self.parent_role.get_permissions().count(), 1)
        self.assertEqual(self.parent_role.get_permissions().first().name(), "Account permission")
        self.assertEqual(self.role.get_permissions().count(), 2)
