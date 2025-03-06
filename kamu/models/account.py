"""
User account models.
"""

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class Account(models.Model):
    """
    Stores information for the linked user account.
    """

    identity = models.ForeignKey(
        "kamu.Identity",
        on_delete=models.CASCADE,
        related_name="useraccount",
    )

    class Status(models.TextChoices):
        ENABLED = ("enabled", _("Enabled"))
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


class AccountSynchronization(models.Model):
    """
    Stores information for account synchronisation.
    """

    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    number_of_failures = models.IntegerField(default=0, verbose_name=_("Number of failures"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))

    class Meta:
        verbose_name = _("Account synchronisation")
        verbose_name_plural = _("Account synchronisations")

    def __str__(self) -> str:
        return self.account.uid
