"""
Synchronize user accounts with external service.

Update account status based on permissions and disable accounts if needed.

Usage help: ./manage.py account_synchronization -h
"""

import time
from typing import Any

from django.core.management.base import BaseCommand

from kamu.connectors.account import AccountApiConnector
from kamu.models.account import Account, AccountSynchronization
from kamu.utils.audit import AuditLog

audit_log = AuditLog()


class Command(BaseCommand):

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("-n", "--dry-run", default=False, action="store_true", help="Dry run (no action)")
        parser.add_argument("-s", "--sleep", default=0, type=int, help="Time to wait between failures")

    def handle(self, **options: Any) -> None:
        sleep_time = options["sleep"]
        accounts_to_sync = AccountSynchronization.objects.all().order_by("-created_at")
        connector = AccountApiConnector()
        synced_accounts = set()
        for sync in accounts_to_sync:
            account = sync.account
            if account.uid in synced_accounts:
                continue
            synced_accounts.add(account.uid)
            if options["verbosity"] > 1:
                if sync.number_of_failures > 0:
                    self.stdout.write(f"Retrying account {account}, tries: {sync.number_of_failures}")
                else:
                    self.stdout.write(f"Syncing account {account}")
            if not options["dry_run"]:
                if account.update_status():
                    account.refresh_from_db()
                try:
                    connector.update_account(account)
                    if account.status in [Account.Status.DISABLED, Account.Status.EXPIRED]:
                        if options["verbosity"] > 0:
                            self.stdout.write(f"Disabling account {account}")
                        connector.disable_account(account)
                        audit_log.info(
                            f"Account disabled by management command: {account}",
                            category="account",
                            action="update",
                            outcome="success",
                            request=None,
                            objects=[account, account.identity],
                            log_to_db=False,
                        )
                except Exception as e:
                    if options["verbosity"] > 0:
                        self.stderr.write(f"Failed to synchronize account {account}: {e}")
                    sync.number_of_failures += 1
                    sync.save()
                    if sleep_time:
                        time.sleep(sleep_time)
                    continue
                AccountSynchronization.objects.filter(account=account, updated_at__lte=sync.updated_at).delete()
