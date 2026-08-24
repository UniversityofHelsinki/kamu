"""
Print membership counts for role hierarchy.

Usage help: ./manage.py get_emails -h
"""

from typing import Any

from django.core.management.base import BaseCommand
from django.db.models import Count, Max, Q
from django.db.models.functions import Length
from django.utils import timezone

from kamu.models.membership import Membership
from kamu.models.organisation import Organisation
from kamu.models.role import Role


class Command(BaseCommand):

    extended_statistics: bool = False
    org_name_len: int = 0
    org_code_len: int = 0
    org_identifier_len: int = 0
    role_name_len: int = 0
    role_identifier_len: int = 0
    lang: str = "en"

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
        parser.add_argument(
            "-l",
            "--lang",
            type=str,
            default="en",
            dest="lang",
            help="Language: en/fi/sv.",
        )
        parser.add_argument(
            "-e",
            "--extended",
            default=False,
            action="store_true",
            dest="extended_statistics",
            help="Extended statistics.",
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
            f"{('>' * counter).ljust(5)} | {str(membership_count).rjust(6)} | {str(sub_membership_count).rjust(6)} | "
            f"{role.name(self.lang).ljust(self.role_name_len)} | {role.identifier}"
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
        if self.extended_statistics:
            roles = (
                Role.objects.filter(organisation=organisation)
                .annotate(
                    membership_count=Count(
                        "membership",
                        filter=Q(
                            membership__status=Membership.Status.ACTIVE,
                            membership__start_date__lte=timezone.now(),
                            membership__expire_date__gte=timezone.now(),
                        ),
                    )
                )
                .filter(membership_count__gt=0)
                .order_by("-membership_count")
            )
        if membership_count or sub_membership_count:
            self.stdout.write(
                f"{('>' * counter).ljust(5)} | {organisation.code.ljust(self.org_code_len)} | "
                f"{str(membership_count).rjust(6)} | {str(sub_membership_count + membership_count).rjust(6)} | "
                f"{organisation.name(self.lang).ljust(self.org_name_len)} | {organisation.identifier}"
            )
        if self.extended_statistics:
            for role in roles:
                self.stdout.write(
                    f"{('-' * (counter + 1)).ljust(5)} | {'':{self.org_code_len}} | "
                    f"{str(role.membership_count).rjust(6)} | {'':6} | "
                    f"{('  ' + role.name(self.lang)).ljust(self.org_name_len)} | {('  ' + role.identifier)}"
                )
        if sub_membership_count:
            for sub_org in Organisation.objects.filter(parent=organisation):
                self.print_organisation_members(sub_org, counter + 1)

    def handle(self, **options: Any) -> None:
        if options.get("extended_statistics"):
            self.extended_statistics = True
        self.lang = options.get("lang", "en") if options.get("lang", "en") in ["en", "fi", "sv"] else "en"
        self.role_name_len = Role.objects.aggregate(max_len=Max(Length(f"name_{self.lang}")))["max_len"]
        self.role_identifier_len = max(Role.objects.aggregate(max_len=Max(Length("identifier")))["max_len"], 10)
        self.org_name_len = Organisation.objects.aggregate(max_len=Max(Length(f"name_{self.lang}")))["max_len"]
        self.org_identifier_len = max(Organisation.objects.aggregate(max_len=Max(Length("identifier")))["max_len"], 10)
        self.org_code_len = Organisation.objects.aggregate(max_len=Max(Length("code")))["max_len"]

        if options.get("role_memberships"):
            roles = Role.objects.filter(parent=None)
            self.stdout.write("Membership counts for role hierarchy")
            self.stdout.write(f"LEVEL | DIRECT | TOTAL  | {'NAME'.ljust(self.role_name_len)} | IDENTIFIER")
            self.stdout.write(
                f"------+--------+--------+-{'-' * self.role_name_len}-+-{'-' * self.role_identifier_len}"
            )
            for role in roles:
                self.print_role_members(role, 0)

        if options.get("organisation_memberships"):
            organisations = Organisation.objects.filter(parent=None)
            if self.extended_statistics:
                self.org_name_len = max(
                    self.org_name_len, Role.objects.aggregate(max_len=Max(Length(f"name_{self.lang}")))["max_len"] + 2
                )
                self.org_identifier_len = max(
                    self.org_identifier_len, Role.objects.aggregate(max_len=Max(Length("identifier")))["max_len"] + 2
                )
            self.stdout.write("Membership counts for organisation hierarchy")
            self.stdout.write(
                f"LEVEL | {'CODE'.ljust(self.org_code_len)} | DIRECT | TOTAL  | {'NAME'.ljust(self.org_name_len)} | "
                "IDENTIFIER"
            )
            self.stdout.write(
                f"------+-{'-' * self.org_code_len}-+--------+--------+-{'-' * self.org_name_len}-+-"
                f"{'-' * self.org_identifier_len}"
            )
            for organisation in organisations:
                self.print_organisation_members(organisation, 0)
