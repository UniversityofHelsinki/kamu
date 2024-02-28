"""
Check expiring memberships and send notifications.

Usage help: ./manage.py notify_expiring_memberships -h
"""

from datetime import date, timedelta
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from kamu.connectors.email import (
    send_expiration_notification_to_member,
    send_expiration_notification_to_role,
)
from kamu.models.membership import Membership
from kamu.models.role import Role


class Command(BaseCommand):
    expiring_limit_days = getattr(settings, "EXPIRING_LIMIT_DAYS", 30)

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "-d",
            "--days",
            type=int,
            default=self.expiring_limit_days,
            dest="notification_days",
            help=f"Send notification for memberships expiring in N days (default: {self.expiring_limit_days}).",
        )
        parser.add_argument(
            "-m",
            "--notify-member",
            default=False,
            action="store_true",
            dest="notify_member",
            help="Send notification to member whose membership is expiring at the set date.",
        )
        parser.add_argument(
            "-r",
            "--notify-role",
            default=False,
            action="store_true",
            dest="notify_role",
            help="Send notification to role notification address if there are expiring memberships within the set "
            "date.",
        )
        parser.add_argument(
            "--dry-run",
            default=False,
            action="store_true",
            dest="dry_run",
            help="Do not send emails, just print according to verbosity level.",
        )

    def notify_members(self, expire_date: date, verbosity: int, dry_run: bool = False) -> None:
        """
        Send notification emails to users whose membership is about to expire.

        Email is sent to primary (first) email address. Notification is only sent to members whose membership
        is expiring at the set expire_date.
        """
        expiring_memberships = Membership.objects.filter(expire_date=expire_date).exclude(identity=None)
        for membership in expiring_memberships:
            if verbosity > 1:
                self.stdout.write(f"Notifying member {membership.identity} of role {membership.role}")
            if not dry_run and membership.identity:
                email = membership.identity.email_addresses.first()
                if email:
                    send_expiration_notification_to_member(
                        membership=membership, email_address=email.address, lang=membership.identity.preferred_language
                    )

    def notify_roles(self, expire_period_end_date: date, verbosity: int, dry_run: bool = False) -> None:
        """
        Send notification emails to roles with expiring memberships.

        Email is sent if the role has a notification email address and there are expiring memberships within
        the expiration period.
        """
        roles = Role.objects.exclude(notification_email_address=None)
        for role in roles:
            expiring_memberships = (
                Membership.objects.filter(
                    Q(expire_date__lte=expire_period_end_date) & Q(expire_date__gte=timezone.now().date()),
                    role=role,
                )
                .exclude(identity=None)
                .distinct()
            )
            names = []
            if expiring_memberships.count() > 0:
                if not dry_run and role.notification_email_address:
                    send_expiration_notification_to_role(
                        role=role,
                        memberships=expiring_memberships,
                        email_address=role.notification_email_address,
                        lang=role.notification_language,
                    )
                if verbosity > 2:
                    for membership in expiring_memberships:
                        if membership.identity:
                            names.append(membership.identity.display_name())
                    self.stdout.write(
                        f"Notifying role {role} of {expiring_memberships.count()} members: {', '.join(names)}"
                    )
                elif verbosity > 1:
                    self.stdout.write(f"Notifying role {role} of {expiring_memberships.count()} members")

    def handle(self, **options: Any) -> None:
        notify_member = options["notify_member"]
        notify_role = options["notify_role"]
        notification_days = options["notification_days"]
        dry_run = options["dry_run"]
        expire_day = timezone.now().date() + timedelta(days=notification_days)
        if options["verbosity"] > 1:
            self.stdout.write(f"Checking memberships expiring in {notification_days} days")
        if notify_member:
            self.notify_members(expire_day, options["verbosity"], dry_run=dry_run)
        if notify_role:
            self.notify_roles(expire_day, options["verbosity"], dry_run=dry_run)
