"""
Print membership counts for role hierarchy.

Usage help: ./manage.py get_emails -h
"""

from typing import Any

from django.core.management.base import BaseCommand

from kamu.models.membership import Membership
from kamu.models.role import Role


class Command(BaseCommand):

    def print_role_members(self, role: Role, counter: int = 0) -> None:
        self.stdout.write(
            f"{'- ' * counter}{role.name()} ({role.identifier}) "
            f"direct members: {role.membership_set.filter(status=Membership.Status.ACTIVE).count()} "
            f"(including subrole members: {role.get_hierarchy_memberships_subroles().count()})"
        )
        for subrole in Role.objects.filter(parent=role):
            self.print_role_members(subrole, counter + 1)

    def handle(self, **options: Any) -> None:
        roles = Role.objects.filter(parent=None)
        for role in roles:
            self.print_role_members(role, 0)
