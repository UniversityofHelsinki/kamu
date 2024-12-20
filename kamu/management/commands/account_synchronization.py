"""
Synchronize user accounts with external service.

Usage help: ./manage.py account_synchronization -h
"""

import time
from typing import Any

from django.core.management.base import BaseCommand

from kamu.connectors.account import AccountApiConnector
from kamu.models.account import AccountSynchronization


class Command(BaseCommand):

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("-n", "--dry-run", default=False, action="store_true", help="Dry run (no action)")
        parser.add_argument("-s", "--sleep", default=0, type=int, help="Time to wait between failures")

    def handle(self, **options: Any) -> None:
        sleep_time = options["sleep"]
        accounts = AccountSynchronization.objects.all().order_by("-created_at")
        connector = AccountApiConnector()
        for account in accounts:
            if options["verbosity"] > 1:
                if account.number_of_failures > 0:
                    self.stdout.write(f"Retrying account {account}, tries: {account.number_of_failures}")
                else:
                    self.stdout.write(f"Syncing account {account}")
            if not options["dry_run"]:
                try:
                    connector.update_account(account.account)
                except Exception as e:
                    if options["verbosity"] > 0:
                        self.stderr.write(f"Failed to synchronize account {account}: {e}")
                    account.number_of_failures += 1
                    account.save()
                    if sleep_time:
                        time.sleep(sleep_time)
                    continue
                AccountSynchronization.objects.filter(pk=account.pk, created_at__lte=account.created_at).delete()
