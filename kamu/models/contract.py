"""
Base models.
"""

from __future__ import annotations

import itertools
from hashlib import sha256
from typing import Any

from django.db import models
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _

from kamu.models.identity import Identifier, Identity


class ContractManager(models.Manager["Contract"]):
    """
    Manager methods for :class:`kamu.models.contract.Contract`.
    """

    def sign_contract(self, template: ContractTemplate, identity: Identity) -> "Contract":
        """
        Creates a contract for the given identity.
        """
        if template != ContractTemplate.objects.filter(type=template.type).order_by("-version").first():
            raise ValueError("Template is not the latest version.")
        time = timezone.now()
        lang = get_language()
        checksum = sha256(
            f"{template.text(lang=lang)}.{identity.kamu_id}.{time.isoformat()}".encode("utf-8")
        ).hexdigest()
        return self.create(identity=identity, template=template, checksum=checksum, created_at=time, lang=lang)


class Contract(models.Model):
    """
    Stores a contract, related to :class:`kamu.models.identity.Identity` and
    :class:`kamu.models.contract.ContractTemplate`.
    """

    identity = models.ForeignKey(
        "kamu.Identity",
        on_delete=models.CASCADE,
        related_name="contracts",
    )
    template = models.ForeignKey(
        "kamu.ContractTemplate",
        on_delete=models.PROTECT,
    )
    checksum = models.CharField(max_length=64, verbose_name=_("Checksum"))
    lang = models.CharField(max_length=2, verbose_name=_("Language"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))

    objects = ContractManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["identity", "template"], name="unique_contract"),
        ]
        verbose_name = _("Contract")
        verbose_name_plural = _("Contracts")

    def __str__(self) -> str:
        return f"{self.template.name()}.{self.template.version}: {self.identity.display_name()}"

    def validate(self) -> bool:
        """
        Validates the contract against all kamu_ids of the identity.
        """
        other_ids = (i.value for i in Identifier.objects.filter(type=Identifier.Type.KAMU, identity=self.identity))
        for kamu_id in itertools.chain([self.identity.kamu_id], other_ids):
            if (
                self.checksum
                == sha256(
                    f"{self.template.text(lang=self.lang)}.{kamu_id}.{self.created_at.isoformat()}".encode("utf-8")
                ).hexdigest()
            ):
                return True
        return False

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "contract_id": self.pk,
            "contract_checksum": self.checksum,
            "contract_time": self.created_at.isoformat(),
        }


class ContractTemplate(models.Model):
    """
    Stores a contract template.

    All contract templates are readable by all logged-in users. Public means the contract is listed
    in the UI, as signable contract.
    """

    type = models.CharField(max_length=50, verbose_name=_("Contract type"))
    version = models.SmallIntegerField(verbose_name=_("Contract version"))
    name_fi = models.CharField(max_length=200, verbose_name=_("Contract name (fi)"))
    name_en = models.CharField(max_length=200, verbose_name=_("Contract name (en)"))
    name_sv = models.CharField(max_length=200, verbose_name=_("Contract name (sv)"))
    text_fi = models.TextField(verbose_name=_("Contract text (fi)"))
    text_en = models.TextField(verbose_name=_("Contract text (en)"))
    text_sv = models.TextField(verbose_name=_("Contract text (sv)"))
    public = models.BooleanField(default=False, verbose_name=_("Public"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["type", "version"], name="unique_contract_template"),
        ]
        verbose_name = _("Contract template")
        verbose_name_plural = _("Contract templates")

    def __str__(self) -> str:
        return f"{self.type}-{self.version}"

    def name(self, lang: str | None = None) -> str:
        """
        Returns contract name in a given language (defaulting current language, or English).
        """
        if not lang:
            lang = get_language()
        if lang == "fi":
            return self.name_fi
        elif lang == "sv":
            return self.name_sv
        else:
            return self.name_en

    @staticmethod
    def get_ordering_by_name() -> list[str]:
        """
        Order by name in current language.
        """
        lang = get_language()
        if lang == "fi":
            return ["name_fi"]
        elif lang == "sv":
            return ["name_sv"]
        else:
            return ["name_en"]

    def text(self, lang: str | None = None) -> str:
        """
        Returns contract text in a given language (defaulting current language, or English).
        """
        if not lang:
            lang = get_language()
        if lang == "fi":
            return self.text_fi
        elif lang == "sv":
            return self.text_sv
        else:
            return self.text_en

    def save(self, *args: Any, **kwargs: Any) -> None:
        """
        Override save method to create a new version instead of updating the existing one.
        Version starts from one for each contract type.
        """
        last = ContractTemplate.objects.filter(type=self.type).order_by("-version").first()
        self.version = last.version + 1 if last else 1
        if self.pk:
            self.pk = None
            self.created_at = timezone.now()
        super().save(*args, **kwargs)

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "contract_template_id": self.pk,
            "contract_template_version": self.version,
            "contract_template_type": self.type,
        }
