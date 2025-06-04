"""
Update membership statuses.

Usage help: ./manage.py update_membership_statuses -h
"""

from datetime import date, timedelta
from typing import Any

from django.core.management.base import BaseCommand
from django.db.models import Q

from kamu.models.membership import Membership


class Command(BaseCommand):

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("-n", "--dry-run", default=False, action="store_true", help="Dry run (no action)")
        parser.add_argument(
            "-a",
            "--all",
            default=False,
            action="store_true",
            help="Update all memberships, not just those expiring or starting today",
        )
        parser.add_argument(
            "-d",
            "--days",
            type=int,
            default=0,
            help="Number of additional days in past to check for expiring memberships",
        )

    def handle(self, **options: Any) -> None:
        update_all = options["all"]
        days = options["days"]
        memberships = (
            Membership.objects.all()
            if update_all
            else Membership.objects.filter(
                (Q(start_date__lte=date.today()) & Q(start_date__gte=date.today() - timedelta(days=days)))
                | (
                    Q(expire_date__lte=date.today() - timedelta(days=1))
                    & Q(expire_date__gte=date.today() - timedelta(days=days + 1))
                )
            )
        )
        for membership in memberships:
            if membership.get_status() != membership.status:
                if options["verbosity"] > 1:
                    self.stdout.write(
                        f"Updating membership {membership} status from "
                        f"{membership.status} to {membership.get_status()}"
                    )
                if not options["dry_run"]:
                    membership.status = membership.get_status()
                    membership.save()
