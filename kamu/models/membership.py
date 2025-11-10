"""
Membership models.
"""

from __future__ import annotations

import datetime
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.db.models import Q, QuerySet
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _

from kamu.models.role import Requirement, Role
from kamu.models.shared import Char32UUIDField
from kamu.validators.identity import validate_phone_number
from kamu.validators.membership import validate_membership


class MembershipManager(models.Manager["Membership"]):
    """
    Manager methods for :class:`kamu.models.membership.Membership`.
    """

    def get_stale(self, grace_days: int | None = None) -> QuerySet[Membership]:
        """
        Returns a list of membership objects that have expired and a role
        specific grace period (or lacking that, settings.PURGE_DELAY_DAYS)
        has passed since. This grace period can optionally be overridden
        with the grace_days parameter
        """
        query = Q()
        for role in Role.objects.all():
            delay = grace_days or role.purge_delay or int(getattr(settings, "PURGE_DELAY_DAYS", 730))
            cutoff = timezone.now() - datetime.timedelta(delay)
            query |= Q(role=role, expire_date__lt=cutoff)
        return self.filter(query)


class Membership(models.Model):
    """
    Stores a membership between :class:`kamu.models.identity.Identity` and :class:`kamu.models.role.Role`,
    related to :class:`django.contrib.auth.models.User`.
    """

    identity = models.ForeignKey("kamu.Identity", blank=True, null=True, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Status(models.TextChoices):
        INVITED = ("invited", _("Invited"))
        REQUIRE = ("require", _("Missing requirements"))
        APPROVAL = ("approval", _("Waiting approval"))
        PENDING = ("pending", _("Pending"))
        ACTIVE = ("active", _("Active"))
        EXPIRED = ("expired", _("Expired"))
        CANCELLED = ("cancelled", _("Cancelled"))

    identifier = Char32UUIDField(
        unique=True,
        default=uuid4,
        verbose_name=_("Membership ID"),
        help_text=_("Unique identifier for this membership."),
    )
    invite_email_address = models.EmailField(blank=True, null=True, verbose_name=_("Invite email address"))
    verify_phone_number = models.CharField(
        max_length=20,
        blank=True,
        verbose_name=_("Verify phone number"),
        help_text=_(
            "Phone number to which the confirmation SMS will be sent, in the international format, e.g. "
            "+358123456789."
        ),
        validators=[validate_phone_number],
    )

    invite_language = models.CharField(
        max_length=2,
        default="en",
        choices=settings.LANGUAGES,
        verbose_name=_("Possible default email invitation replacement text"),
    )

    invite_text = models.TextField(
        blank=True,
        verbose_name=_("Invite text"),
        help_text=_(
            "If you wish, you can replace the beginning part of the default email invite with your own text (max. 70 "
            "characters). The invitation code and link are always added at the end of the message. Preview the "
            "message to see the finished email."
        ),
    )

    status = models.CharField(max_length=10, choices=Status.choices, verbose_name=_("Membership status"))
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="membership_approver", on_delete=models.SET_NULL, null=True, blank=True
    )
    inviter = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="membership_inviter", on_delete=models.SET_NULL, null=True, blank=True
    )
    reason = models.TextField(verbose_name=_("Reasons for membership"))
    start_date = models.DateField(verbose_name=_("Membership start date"))
    expire_date = models.DateField(verbose_name=_("Membership expiry date"))
    cancelled_at = models.DateTimeField(blank=True, null=True, verbose_name=_("Cancelled at"))

    requirements_failed_at = models.DateTimeField(blank=True, null=True, verbose_name=_("Requirements failed time"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    objects = MembershipManager()

    class Meta:
        ordering = ["role__identifier", "expire_date"]
        verbose_name = _("Membership")
        verbose_name_plural = _("Memberships")

    def __str__(self) -> str:
        if self.identity:
            return f"{self.role.name()} - {self.identity.display_name()}"
        return f"{self.role.name()} - {self.invite_email_address}"

    def clean(self) -> None:
        """
        Validates membership date limits.

        When validating during form creation, related form fields is picked from the kwargs and does
        not exist yet in the validated data. It is validated in the form validation.
        """
        if self.pk:
            validate_membership(
                ValidationError,
                self.role,
                self.start_date,
                self.expire_date,
                edit=True,
                old_start_date=Membership.objects.get(pk=self.pk).start_date,
            )
        else:
            try:
                validate_membership(ValidationError, self.role, self.start_date, self.expire_date, edit=False)
            except ObjectDoesNotExist:
                validate_membership(ValidationError, None, self.start_date, self.expire_date, edit=False)

    @staticmethod
    def get_ordering_by_role_name() -> list[str]:
        """
        Order by name in current language.
        """
        lang = get_language()
        if lang == "fi":
            return ["role__name_fi"]
        elif lang == "sv":
            return ["role__name_sv"]
        else:
            return ["role__name_en"]

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "membership_id": self.pk,
            "membership": self.__str__(),
        }

    def ending_in_future(self) -> bool:
        """
        Returns True if membership expiry date is in the future.
        """
        return self.expire_date > timezone.now().date()

    def get_absolute_url(self) -> str:
        """
        Returns url to current membership's detail view.
        """
        return reverse("membership-detail", kwargs={"pk": self.pk})

    def get_missing_requirements(self) -> QuerySet[Requirement]:
        """
        Test if the membership requirements are met.
        """
        missing = Requirement.objects.none()
        for requirement in self.role.get_requirements():
            if not requirement.test(self.identity):
                missing |= Requirement.objects.filter(pk=requirement.pk)
        return missing

    def test_requirements(self, allow_grace: bool = False) -> bool:
        """
        Test if the membership requirements are met.

        Set requirements_failed_at if not met, and it doesn't exist yet.
        If grace is allowed, pass requirements that are in the grace period.
        """
        grace_used = False
        for requirement in self.role.get_requirements():
            if not requirement.test(self.identity):
                if not self.requirements_failed_at:
                    self.requirements_failed_at = timezone.now()
                if not allow_grace:
                    return False
                if not requirement.grace or timezone.now() > self.requirements_failed_at + datetime.timedelta(
                    days=requirement.grace
                ):
                    return False
                grace_used = True
        if self.requirements_failed_at and not grace_used:
            self.requirements_failed_at = None
        return True

    def get_status(self) -> Membership.Status:
        """
        Returns the current membership status.
        """
        if self.cancelled_at:
            return Membership.Status.CANCELLED
        elif timezone.now().date() > self.expire_date:
            return Membership.Status.EXPIRED
        elif not self.identity:
            return Membership.Status.INVITED
        elif not self.test_requirements(allow_grace=self.status == Membership.Status.ACTIVE):
            return Membership.Status.REQUIRE
        elif not self.approver:
            return Membership.Status.APPROVAL
        elif timezone.now().date() < self.start_date:
            return Membership.Status.PENDING
        else:
            return Membership.Status.ACTIVE

    def set_status(self) -> None:
        """
        Sets membership status.
        """
        self.status = self.get_status()

    def save(self, *args: Any, **kwargs: Any) -> None:
        """
        Update status before saving membership.
        """
        self.set_status()
        super().save(*args, **kwargs)
