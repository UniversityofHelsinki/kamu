"""
Organisation model.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _

from kamu.validators.organisation import validate_organisation_hierarchy


class Organisation(models.Model):
    """
    Stores an organisation, related to self.
    """

    identifier = models.CharField(max_length=20, unique=True, verbose_name=_("Organisation identifier"))
    abbreviation = models.CharField(max_length=20, verbose_name=_("Organisation abbreviation"))
    name_fi = models.CharField(max_length=255, verbose_name=_("Organisation name (fi)"))
    name_en = models.CharField(max_length=255, verbose_name=_("Organisation name (en)"))
    name_sv = models.CharField(max_length=255, verbose_name=_("Organisation name (sv)"))

    parent = models.ForeignKey("self", null=True, blank=True, default=None, on_delete=models.SET_NULL)

    code = models.CharField(max_length=50, verbose_name=_("Organisation code"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Organisation")
        verbose_name_plural = _("Organisations")

    def __str__(self) -> str:
        return self.name()

    def name(self, lang: str | None = None) -> str:
        """
        Returns Organisation name in a given language (defaulting current language, or English).
        """
        if not lang:
            lang = get_language()
        if lang == "fi":
            return self.name_fi
        elif lang == "sv":
            return self.name_sv
        else:
            return self.name_en

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "organisation_id": self.pk,
            "organisation": self.identifier,
        }

    def clean(self) -> None:
        """
        Validates organisation data.
        """
        if self.parent:
            validate_organisation_hierarchy(ValidationError, self, self.parent)
