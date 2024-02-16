"""
Unit tests for authentication.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase

from kamu.utils.audit import AuditLog
from kamu.utils.auth import set_default_permissions

audit_log = AuditLog()


class SetPermissionTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="testuser")
        self.group = Group.objects.create(name="Test Group")

    def test_set_default_permissions_for_user(self):
        set_default_permissions(self.user)
        self.user.refresh_from_db()
        self.assertEqual(self.user.user_permissions.count(), 2)
        set_default_permissions(self.user, remove=True)
        self.user.refresh_from_db()
        self.assertEqual(self.user.user_permissions.count(), 0)

    def test_set_default_permissions_for_group(self):
        set_default_permissions(self.group)
        self.group.refresh_from_db()
        self.assertEqual(self.group.permissions.count(), 2)
        set_default_permissions(self.group, remove=True)
        self.group.refresh_from_db()
        self.assertEqual(self.group.permissions.count(), 0)
