"""
Print primary email address for each identity, if verified email address exists.

Optionally include names and uids to list.

Usage help: ./manage.py get_emails -h
"""

import sys
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from kamu.models.identity import Identity
from kamu.models.role import Role


class Command(BaseCommand):

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "-r",
            "--role",
            type=str,
            default="",
            dest="role_identifier",
            help="Role identifier which email addresses are listed. List emails for all Kamu identities if not given.",
        )
        parser.add_argument(
            "-u",
            "--unverified",
            default=False,
            action="store_true",
            dest="unverified_emails",
            help="Unverified email addresses are listed if identity has no primary email.",
        )
        parser.add_argument(
            "-n",
            "--names",
            default=False,
            action="store_true",
            dest="include_names",
            help="Also list identity names.",
        )
        parser.add_argument(
            "-a",
            "--accounts",
            default=False,
            action="store_true",
            dest="include_accounts",
            help="Also list account names",
        )

    def handle(self, **options: Any) -> None:
        role_identifier = options["role_identifier"].strip()
        unverified_emails = options["unverified_emails"]
        include_accounts = options["include_accounts"]
        include_names = options["include_names"]

        email_count = 0
        if role_identifier:
            try:
                role = Role.objects.get(identifier=role_identifier)
            except Role.DoesNotExist:
                self.stderr.write(f"Role {role_identifier} does not exist")
                sys.exit(1)
            identities = Identity.objects.filter(
                membership__role=role,
                membership__start_date__lte=timezone.localdate(),
                membership__expire_date__gte=timezone.localdate(),
            )
        else:
            identities = Identity.objects.all()
        for identity in identities:
            email_address = identity.email_address(unverified=unverified_emails)
            name = f";{identity.display_name()}" if include_names else ""
            account = f";{identity.uid or ''}" if include_accounts else ""
            if email_address:
                self.stdout.write(f"{email_address}{name}{account}")
                email_count += 1
        self.stdout.write(f"Total identities: {identities.count()}")
        self.stdout.write(f"Email addresses: {email_count}")
