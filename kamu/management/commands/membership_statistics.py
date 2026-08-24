"""
Print membership counts for role hierarchy.

Usage help: ./manage.py get_emails -h
"""

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from kamu.models.membership import Membership
from kamu.models.organisation import Organisation
from kamu.models.role import Role


class Command(BaseCommand):

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "-o",
            "--organisation-memberships",
            default=False,
            action="store_true",
            dest="organisation_memberships",
            help="Print membership counts for organisation hierarchy.",
        )

        parser.add_argument(
            "-r",
            "--role-memberships",
            default=False,
            action="store_true",
            dest="role_memberships",
            help="Print membership counts for role hierarchy.",
        )

    def print_role_members(self, role: Role, counter: int = 0) -> None:
        """
        Print membership counts for a role and its subroles.
        """
        membership_count = role.membership_set.filter(
            status=Membership.Status.ACTIVE, start_date__lte=timezone.now(), expire_date__gte=timezone.now()
        ).count()
        sub_membership_count = role.get_hierarchy_memberships_subroles().count()
        self.stdout.write(
            f"{('>' * counter).ljust(5)} | {str(membership_count).rjust(6)} | "
            f"{str(sub_membership_count).rjust(6)} | {role.name().ljust(50)} | {role.identifier}"
        )
        for subrole in Role.objects.filter(parent=role):
            self.print_role_members(subrole, counter + 1)

    def get_sub_organisation_ids(self, organisation: Organisation) -> list[int]:
        """
        Get all sub-organisation IDs for a given organisation.
        """
        sub_orgs = Organisation.objects.filter(parent=organisation)
        sub_org_ids = [sub_org.id for sub_org in sub_orgs]
        for sub_org in sub_orgs:
            sub_org_ids.extend(self.get_sub_organisation_ids(sub_org))
        return sub_org_ids

    def print_organisation_members(self, organisation: Organisation, counter: int = 0) -> None:
        """
        Print membership counts for an organisation and its sub-organisations.
        """
        sub_org_ids = self.get_sub_organisation_ids(organisation)
        membership_count = Membership.objects.filter(
            role__organisation=organisation,
            status=Membership.Status.ACTIVE,
            start_date__lte=timezone.now(),
            expire_date__gte=timezone.now(),
        ).count()
        sub_membership_count = Membership.objects.filter(
            role__organisation__id__in=sub_org_ids,
            status=Membership.Status.ACTIVE,
            start_date__lte=timezone.now(),
            expire_date__gte=timezone.now(),
        ).count()
        if membership_count or sub_membership_count:
            self.stdout.write(
                f"{('>' * counter).ljust(5)} | {organisation.code.ljust(15)} | {str(membership_count).rjust(6)} | "
                f"{str(sub_membership_count + membership_count).rjust(6)} | {organisation.name().ljust(50)} | "
                f"{organisation.identifier}"
            )
        if sub_membership_count:
            for sub_org in Organisation.objects.filter(parent=organisation):
                self.print_organisation_members(sub_org, counter + 1)

    def handle(self, **options: Any) -> None:
        if options.get("role_memberships"):
            self.stdout.write("Membership counts for role hierarchy")
            self.stdout.write("LEVEL | DIRECT MEMBERS | MEMBERS INC. SUB ROLES | NAME | IDENTIFIER")
            self.stdout.write("----------------------------------------")
            roles = Role.objects.filter(parent=None)
            for role in roles:
                self.print_role_members(role, 0)

        if options.get("organisation_memberships"):
            self.stdout.write("Membership counts for organisation hierarchy")
            self.stdout.write("LEVEL | CODE | DIRECT MEMBERS | MEMBERS INC. SUB ORGANISATIONS | NAME | IDENTIFIER")
            self.stdout.write("----------------------------------------")
            organisations = Organisation.objects.filter(parent=None)
            for organisation in organisations:
                self.print_organisation_members(organisation, 0)
