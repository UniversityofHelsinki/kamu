"""
User account models.
"""

from django.db import models
from django.http import HttpRequest
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from kamu.models.role import Permission
from kamu.utils.audit import AuditLog

audit_log = AuditLog()


class Account(models.Model):
    """
    Stores information for the linked user account.
    """

    identity = models.ForeignKey(
        "kamu.Identity",
        on_delete=models.PROTECT,
        related_name="useraccount",
    )

    class Status(models.TextChoices):
        ENABLED = ("enabled", _("Enabled"))
        EXPIRED = ("expired", _("Expired"))
        DISABLED = ("disabled", _("Disabled"))

    class Type(models.TextChoices):
        ACCOUNT = ("account", _("Account"))
        LIGHT = ("lightaccount", _("Light Account"))

    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ENABLED, verbose_name=_("Status"))
    type = models.CharField(max_length=15, choices=Type.choices, default=Type.LIGHT, verbose_name=_("Account type"))

    uid = models.CharField(max_length=255, verbose_name=_("User ID"))

    deactivated_at = models.DateTimeField(blank=True, null=True, verbose_name=_("Deactivated at"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("User account")
        verbose_name_plural = _("User accounts")

    def __str__(self) -> str:
        return self.uid

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "account_id": self.pk,
            "account_type": self.type,
            "account_uid": self.uid,
        }

    def update_status(self, request: HttpRequest | None = None) -> bool:
        """
        Update account status if account permissions have changed.

        Returns True if status was changed, False otherwise.

        If account cannot be disabled via API, add it to synchronisation queue.
        """
        from kamu.connectors.account import AccountApiConnector

        account_permissions = self.identity.get_permissions(permission_type=Permission.Type.ACCOUNT).values_list(
            "identifier", flat=True
        )
        if self.type not in account_permissions:
            if self.status == Account.Status.ENABLED:
                connector = AccountApiConnector()
                try:
                    connector.disable_account(self)
                except Exception as e:
                    audit_log.warning(
                        f"Account disabling failed: {e}",
                        category="account",
                        action="update",
                        outcome="failure",
                        request=request,
                        objects=[self, self.identity],
                        log_to_db=False,
                    )
                    self.accountsynchronization_set.update_or_create()
                finally:
                    self.status = Account.Status.EXPIRED
                    self.deactivated_at = timezone.now()
                    self.save()
                    audit_log.info(
                        f"Changed enabled account status to expired: {self}",
                        category="account",
                        action="update",
                        outcome="success",
                        request=request,
                        objects=[self, self.identity],
                        log_to_db=True,
                    )
                return True
            elif self.status == Account.Status.DISABLED:
                audit_log.info(
                    f"Changed disabled account status to expired: {self}",
                    category="account",
                    action="update",
                    outcome="success",
                    request=request,
                    objects=[self, self.identity],
                    log_to_db=True,
                )
                self.status = Account.Status.EXPIRED
                self.save()
                return True
        elif self.status == Account.Status.EXPIRED:
            audit_log.info(
                f"Changed expired account status to disabled: {self}",
                category="account",
                action="update",
                outcome="success",
                request=request,
                objects=[self, self.identity],
                log_to_db=True,
            )
            self.status = Account.Status.DISABLED
            self.save()
            return True
        return False


class AccountSynchronization(models.Model):
    """
    Stores information for account synchronisation.
    """

    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    number_of_failures = models.IntegerField(default=0, verbose_name=_("Number of failures"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Account synchronisation")
        verbose_name_plural = _("Account synchronisations")

    def __str__(self) -> str:
        return self.account.uid
