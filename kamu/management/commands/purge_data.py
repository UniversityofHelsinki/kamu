"""
Remove expired data (currently just memberships) X days after expiry.

Usage help: ./manage.py purge_data -h
"""

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from kamu.models.identity import (
    CustomUserManager,
    Identifier,
    IdentifierManager,
    Identity,
    IdentityManager,
)
from kamu.models.membership import Membership, MembershipManager


class UsageError(CommandError):
    pass


class Command(BaseCommand):
    types: dict[str, MembershipManager | IdentifierManager | IdentityManager | CustomUserManager] = {
        "membership": Membership.objects,
        "identifier": Identifier.objects,
        "identity": Identity.objects,
        "user": CustomUserManager(),
    }

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "-d",
            "--days",
            type=int,
            dest="grace_days",
            help="Force data purge after this many days since expiry (default varies by data type)",
        )
        parser.add_argument(
            "-l", "--list-types", default=False, action="store_true", help="List purgeable types for --type option"
        )
        parser.add_argument("-n", "--dry-run", default=False, action="store_true", help="Dry run (no action)")
        parser.add_argument(
            "-t",
            "--type",
            action="append",
            help="type(s) of data to purge (default: purge everything)",
        )

    def handle(self, **options: Any) -> None:
        if options["list_types"]:
            self.stdout.write(f"Supported types: {' '.join(self.types.keys())}")
            return

        types = options["type"] or self.types.keys()
        for t in types:
            if t not in self.types:
                raise UsageError(f"Invalid type '{t}' (use --list-types to show choices)")

        for t in types:
            if options["verbosity"] > 1:
                self.stdout.write(f"Purging {t} data")
            manager_class = self.types[t]
            stale = manager_class.get_stale(grace_days=options.get("grace_days"))
            if not stale.exists():
                if options["verbosity"] > 1:
                    self.stdout.write(f"Skipping {t}: nothing to purge")
                continue

            action = "Deleting" if not options["dry_run"] else "Would delete"
            for obj in stale:
                if options["verbosity"] > 0:
                    self.stdout.write(f"{action} {t} {obj}")
                if not options["dry_run"]:
                    obj.delete()
