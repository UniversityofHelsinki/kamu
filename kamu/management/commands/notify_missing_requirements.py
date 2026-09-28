"""
Check missing membership requirements and send notifications.

Usage help: ./manage.py notify_missing_requirements -h
"""

from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from kamu.connectors.email import send_missing_requirement_notification
from kamu.models.identity import Identity
from kamu.models.role import Requirement


class Command(BaseCommand):

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "-d",
            "--days",
            type=int,
            default=0,
            dest="notification_days",
            help="Include memberships starting N days in future (default: 0).",
        )
        parser.add_argument(
            "--dry-run",
            default=False,
            action="store_true",
            dest="dry_run",
            help="Do not send emails, just print according to verbosity level.",
        )

    def send_notification(self, identity: Identity, missing_requirement_pks: set[int]) -> None:
        """
        Send notification to identity about missing membership requirements for memberships.
        """
        email_address = identity.email_address(unverified=True)
        if email_address:
            send_missing_requirement_notification(
                requirements=Requirement.objects.filter(pk__in=missing_requirement_pks),
                email_address=email_address,
                lang=identity.preferred_language,
            )

    def handle(self, **options: Any) -> None:
        days = options["notification_days"]
        start_date_limit = timezone.localdate() + timedelta(days=days)
        dry_run = options["dry_run"]
        verbosity = options["verbosity"]
        if verbosity > 1:
            self.stdout.write("Checking missing membership requirements")
        identities = (
            Identity.objects.filter(
                membership__start_date__lte=start_date_limit, membership__expire_date__gte=timezone.localdate()
            )
            .distinct()
            .prefetch_related("membership_set", "membership_set__role")
        )
        for identity in identities:
            missing_requirement_pks = set()
            for membership in identity.membership_set.filter(
                start_date__lte=start_date_limit, expire_date__gte=timezone.localdate()
            ):
                for requirement in membership.role.get_requirements():
                    if not requirement.test(identity):
                        missing_requirement_pks.add(requirement.pk)
                        if verbosity > 1:
                            self.stdout.write(
                                f"Identity {identity} has missing requirement {requirement} for membership "
                                f"{membership}"
                            )
            if not dry_run and missing_requirement_pks:
                self.send_notification(identity, missing_requirement_pks)
