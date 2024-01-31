"""
Role app models.
"""

from __future__ import annotations

import datetime
from typing import Any

from django.conf import settings
from django.contrib.auth.models import User as UserType
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q, QuerySet
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _

from role.validators import validate_role_hierarchy


class Role(models.Model):
    """
    Stores a role, related to self, :model:`auth.Group` and :model:`role.Permission`.
    """

    identifier = models.CharField(max_length=20, unique=True, verbose_name=_("Role identifier"))
    name_fi = models.CharField(max_length=50, verbose_name=_("Role name (fi)"))
    name_en = models.CharField(max_length=50, verbose_name=_("Role name (en)"))
    name_sv = models.CharField(max_length=50, verbose_name=_("Role name (sv)"))
    description_fi = models.CharField(max_length=255, verbose_name=_("Role description (fi)"))
    description_en = models.CharField(max_length=255, verbose_name=_("Role description (en)"))
    description_sv = models.CharField(max_length=255, verbose_name=_("Role description (sv)"))

    parent = models.ForeignKey("self", null=True, blank=True, default=None, on_delete=models.SET_NULL)

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    organisation_unit = models.CharField(max_length=20, verbose_name=_("Organisation unit"))

    inviters = models.ManyToManyField(
        "auth.Group", related_name="role_inviters", verbose_name=_("Inviter groups"), blank=True
    )
    approvers = models.ManyToManyField(
        "auth.Group", related_name="role_approvers", verbose_name=_("Approver groups"), blank=True
    )

    permissions = models.ManyToManyField("role.Permission", verbose_name=_("Permissions"), blank=True)
    iam_group = models.CharField(max_length=20, blank=True, verbose_name=_("IAM Group"))

    maximum_duration = models.IntegerField(verbose_name=_("Maximum duration (days)"))

    purge_delay = models.IntegerField(
        verbose_name=_("Purge delay (days)"),
        help_text=_("Grace period from membership expiration to purge (days)"),
        blank=True,
        null=True,
    )

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        permissions = [
            ("search_roles", "Can search roles"),
        ]
        verbose_name = _("Role")
        verbose_name_plural = _("Roles")

    def __str__(self) -> str:
        return self.name()

    def name(self, lang: str | None = None) -> str:
        """
        Returns Role name in a given language (defaulting current language, or English).
        """
        if not lang:
            lang = get_language()
        if lang == "fi":
            return self.name_fi
        elif lang == "sv":
            return self.name_sv
        else:
            return self.name_en

    def description(self, lang: str | None = None) -> str:
        """
        Returns Role description in a given language (defaulting current language, or English).
        """
        if not lang:
            lang = get_language()
        if lang == "fi":
            return self.description_fi
        elif lang == "sv":
            return self.description_sv
        else:
            return self.description_en

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "role_id": self.pk,
            "role": self.identifier,
        }

    def clean(self) -> None:
        """
        Validates role data.
        """
        if self.parent:
            validate_role_hierarchy(ValidationError, self, self.parent)

    def get_absolute_url(self) -> str:
        """
        Returns url to current role's detail view.
        """
        return reverse("role-detail", kwargs={"pk": self.pk})

    def get_role_hierarchy(self) -> models.QuerySet:
        """
        Returns a hierarchy of all roles, following parents until maximum depth is reached.

        Role modification is validated against a circular hierarchy, but preparing for it anyway.
        """
        role = self
        roles = Role.objects.filter(pk=role.pk)
        n = 1
        while role.parent:
            n += 1
            if n > settings.ROLE_HIERARCHY_MAXIMUM_DEPTH:
                break
            role = role.parent
            roles = roles | Role.objects.filter(pk=role.pk)
        return roles

    def get_permissions(self) -> models.QuerySet:
        """
        Returns combined permissions of all distinct roles in hierarchy.
        """
        roles = self.get_role_hierarchy()
        return Permission.objects.filter(role__in=roles).distinct()

    def get_cost(self) -> int:
        """
        Returns combined cost of all distinct permissions in hierarchy.
        """
        roles = self.get_role_hierarchy()
        cost = Permission.objects.filter(role__in=roles).distinct().aggregate(models.Sum("cost"))["cost__sum"]
        return cost if cost else 0

    def get_hierarchy_memberships(self) -> models.QuerySet:
        """
        Returns all active memberships in the role hierarchy.
        """
        roles = self.get_role_hierarchy()
        return Membership.objects.filter(
            role__in=roles, start_date__lte=timezone.now(), expire_date__gte=timezone.now()
        )

    def is_approver(self, user: UserType) -> bool:
        """
        Check if user has approver permission to the role

        Superusers, approvers and the role owner have invite permission.
        """
        if user.is_superuser:
            return True
        groups = user.groups.all()
        try:
            Role.objects.filter(Q(approvers__in=groups) | Q(owner=user)).distinct().get(pk=self.pk)
            return True
        except Role.DoesNotExist:
            pass
        return False

    def is_inviter(self, user: UserType) -> bool:
        """
        Check if user has invite permission to the role

        Superusers, inviters, approvers and the role owner have invite permission.
        """
        if user.is_superuser:
            return True
        groups = user.groups.all()
        try:
            Role.objects.filter(Q(inviters__in=groups) | Q(approvers__in=groups) | Q(owner=user)).distinct().get(
                pk=self.pk
            )
            return True
        except Role.DoesNotExist:
            pass
        return False


class Permission(models.Model):
    """
    Stores a permission.
    """

    identifier = models.CharField(max_length=20, unique=True, verbose_name=_("Permission identifier"))
    name_fi = models.CharField(max_length=50, verbose_name=_("Permission name (fi)"))
    name_en = models.CharField(max_length=50, verbose_name=_("Permission name (en)"))
    name_sv = models.CharField(max_length=50, verbose_name=_("Permission name (sv)"))
    description_fi = models.CharField(max_length=255, verbose_name=_("Permission description (fi)"))
    description_en = models.CharField(max_length=255, verbose_name=_("Permission description (en)"))
    description_sv = models.CharField(max_length=255, verbose_name=_("Permission description (sv)"))

    cost = models.IntegerField(verbose_name=_("Permission cost"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        ordering = ["identifier"]
        verbose_name = _("Permission")
        verbose_name_plural = _("Permissions")

    def __str__(self) -> str:
        return self.name()

    def name(self, lang: str | None = None) -> str:
        """
        Returns Permission name in a given language (defaulting current language, or English).
        """
        if not lang:
            lang = get_language()
        if lang == "fi":
            return self.name_fi
        elif lang == "sv":
            return self.name_sv
        else:
            return self.name_en

    def description(self, lang: str | None = None) -> str:
        """
        Returns Permission description in a given language (defaulting current language, or English).
        """
        if not lang:
            lang = get_language()
        if lang == "fi":
            return self.description_fi
        elif lang == "sv":
            return self.description_sv
        else:
            return self.description_en

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "permission_id": self.pk,
            "permission": self.identifier,
        }


class MembershipManager(models.Manager["Membership"]):
    """
    Manager methods for :model:`role.Membership`.
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
    Stores a membership between :model:`identity.Identity` and :model:`identity.Role`, related to :model:`auth.User`.
    """

    identity = models.ForeignKey("identity.Identity", blank=True, null=True, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    STATUS_CHOICES = (
        ("invited", _("Invited")),
        ("require", _("Waiting requirements")),
        ("approval", _("Waiting approval")),
        ("pending", _("Pending")),
        ("active", _("Active")),
        ("expired", _("Expired")),
    )
    invite_email_address = models.EmailField(blank=True, null=True, verbose_name=_("Invite email address"))
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, verbose_name=_("Membership status"))
    approver = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="membership_approver", on_delete=models.SET_NULL, null=True, blank=True
    )
    inviter = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="membership_inviter", on_delete=models.SET_NULL, null=True, blank=True
    )
    reason = models.TextField(verbose_name=_("Membership reason"))
    start_date = models.DateField(verbose_name=_("Membership start date"))
    expire_date = models.DateField(verbose_name=_("Membership expire date"))

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

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "membership_id": self.pk,
            "membership": self.__str__(),
        }

    def get_absolute_url(self) -> str:
        """
        Returns url to current membership's detail view.
        """
        return reverse("membership-detail", kwargs={"pk": self.pk})

    def set_status(self) -> None:
        """
        Sets membership status.

        Requirements have not been implemented yet.
        """
        if timezone.now().date() > self.expire_date:
            self.status = "expired"
        elif not self.identity:
            self.status = "invited"
        elif not self.approver:
            self.status = "approval"
        elif timezone.now().date() < self.start_date:
            self.status = "pending"
        else:
            self.status = "active"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """
        Update status before saving membership.
        """
        self.set_status()
        super(Membership, self).save(*args, **kwargs)
