"""
Role models.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib.auth.models import User as UserType
from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.db import models
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _

from kamu.models.organisation import Organisation
from kamu.validators.role import validate_role_hierarchy

if TYPE_CHECKING:
    from kamu.models.identity import Identity as IdentityType


class Role(models.Model):
    """
    Stores a role, related to self, :class:`django.contrib.auth.models.Group`, :class:`kamu.models.role.Permission`.,
    :class:`kamu.models.role.Requirement` and :class:`kamu.models.organisation.Organisation`.
    """

    LANG_CHOICES = (
        ("en", _("English")),
        ("fi", _("Finnish")),
        ("sv", _("Swedish")),
    )

    identifier = models.CharField(max_length=20, unique=True, verbose_name=_("Role identifier"))
    name_fi = models.CharField(max_length=50, verbose_name=_("Role name (fi)"))
    name_en = models.CharField(max_length=50, verbose_name=_("Role name (en)"))
    name_sv = models.CharField(max_length=50, verbose_name=_("Role name (sv)"))
    description_fi = models.CharField(max_length=255, verbose_name=_("Role description (fi)"))
    description_en = models.CharField(max_length=255, verbose_name=_("Role description (en)"))
    description_sv = models.CharField(max_length=255, verbose_name=_("Role description (sv)"))

    parent = models.ForeignKey("self", null=True, blank=True, default=None, on_delete=models.SET_NULL)

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    organisation = models.ForeignKey(
        Organisation, on_delete=models.SET_NULL, null=True, blank=True, verbose_name=_("Organisation unit")
    )
    notification_email_address = models.EmailField(blank=True, null=True, verbose_name=_("Notification email address"))
    notification_language = models.CharField(
        max_length=2,
        choices=LANG_CHOICES,
        default="en",
        verbose_name=_("Notification language"),
    )
    inviters = models.ManyToManyField(
        "auth.Group", related_name="role_inviters", verbose_name=_("Inviter groups"), blank=True
    )
    approvers = models.ManyToManyField(
        "auth.Group", related_name="role_approvers", verbose_name=_("Approver groups"), blank=True
    )

    permissions = models.ManyToManyField("kamu.Permission", verbose_name=_("Permissions"), blank=True)
    requirements = models.ManyToManyField(
        "kamu.Requirement", related_name="role_requirements", verbose_name=_("Requirements"), blank=True
    )

    iam_group = models.CharField(max_length=20, blank=True, verbose_name=_("IAM Group"))

    require_sms_verification = models.BooleanField(default=False, verbose_name=_("Requires SMS verification"))
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

    def get_requirements(self) -> models.QuerySet:
        """
        Returns combined requirements of all distinct roles and permissions in hierarchy.
        """
        roles = self.get_role_hierarchy()
        permissions = Permission.objects.filter(role__in=roles).distinct()
        return Requirement.objects.filter(
            Q(role_requirements__in=roles) | Q(permission_requirements__in=permissions)
        ).distinct()

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
        from kamu.models.membership import Membership

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

    class Type(models.TextChoices):
        ACCOUNT = ("account", _("User account"))
        GENERIC = ("generic", _("Generic permission"))
        SERVICE = ("service", _("Service"))

    type = models.CharField(
        max_length=10, choices=Type.choices, default=Type.GENERIC, verbose_name=_("Permission type")
    )

    name_fi = models.CharField(max_length=50, verbose_name=_("Permission name (fi)"))
    name_en = models.CharField(max_length=50, verbose_name=_("Permission name (en)"))
    name_sv = models.CharField(max_length=50, verbose_name=_("Permission name (sv)"))
    description_fi = models.CharField(max_length=255, verbose_name=_("Permission description (fi)"))
    description_en = models.CharField(max_length=255, verbose_name=_("Permission description (en)"))
    description_sv = models.CharField(max_length=255, verbose_name=_("Permission description (sv)"))

    cost = models.IntegerField(verbose_name=_("Permission cost"))
    value = models.CharField(max_length=4000, blank=True, verbose_name=_("Permission value"))

    requirements = models.ManyToManyField(
        "kamu.Requirement", related_name="permission_requirements", verbose_name=_("Requirements"), blank=True
    )

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

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "permission_id": self.pk,
            "permission": self.identifier,
        }


class Requirement(models.Model):
    """
    Stores a requirement.
    """

    name_fi = models.CharField(max_length=50, verbose_name=_("Requirement name (fi)"))
    name_en = models.CharField(max_length=50, verbose_name=_("Requirement name (en)"))
    name_sv = models.CharField(max_length=50, verbose_name=_("Requirement name (sv)"))

    class Type(models.TextChoices):
        CONTRACT = ("contract", _("Requires a signed contract of type (value)"))
        ATTRIBUTE = ("attribute", _("User attribute (value) is defined"))
        ASSURANCE = ("assurance", _("Assurance level at least level"))
        EXTERNAL = ("external", _("External requirement"))

    type = models.CharField(max_length=20, choices=Type.choices, verbose_name=_("Requirement type"))
    value = models.CharField(
        blank=True,
        max_length=255,
        verbose_name=_("Requirement value"),
    )
    level = models.IntegerField(
        default=0,
        verbose_name=_("Level or version required"),
        help_text=_(
            "Require a minimum level of assurance or attribute verification level, or a minimum version of "
            "contract. Contract level must be a positive integer. Assurance levels are from 1 (low) to 3 (high) "
            "and attribute verification levels are from 1 (self assured) to 4 (strong electrical verification)"
        ),
    )
    grace = models.IntegerField(
        default=0,
        verbose_name=_("Grace period (days)"),
        help_text=_("Grace period (days) before membership status is changed."),
    )

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["type", "value", "grace"], name="unique_requirement"),
        ]
        ordering = ["type"]
        verbose_name = _("Requirement")
        verbose_name_plural = _("Requirements")

    def __str__(self) -> str:
        return self.name()

    def name(self, lang: str | None = None) -> str:
        """
        Returns requirement name in a given language (defaulting current language, or English).
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

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "requirement_id": self.pk,
            "requirement_type": self.type,
        }

    def clean(self) -> None:
        """
        Validates requirement data.
        """
        from kamu.models.identity import Identity

        if self.type == Requirement.Type.CONTRACT:
            if not self.value:
                raise ValidationError({"value": [_("Contract requirement needs contract type as a value.")]})
            if self.level and self.level < 0:
                raise ValidationError({"level": [_("Contract version must be a positive integer.")]})
        if self.type == Requirement.Type.ASSURANCE:
            min_assurance = Identity.AssuranceLevel.LOW
            max_assurance = Identity.AssuranceLevel.HIGH
            if min_assurance > int(self.level) or int(self.level) > max_assurance:
                raise ValidationError(
                    {
                        "level": [
                            _("Allowed assurance levels are from %(min)d (low) to %(max)d (high).")
                            % {"min": min_assurance, "max": max_assurance}
                        ]
                    }
                )
        if self.type == Requirement.Type.ATTRIBUTE:
            if self.value not in ["phone_number", "email_address"]:
                try:
                    Identity._meta.get_field(self.value)
                except FieldDoesNotExist:
                    raise ValidationError({"value": [_("Invalid attribute name.")]})
            if self.level:
                try:
                    Identity._meta.get_field(self.value + "_verification")
                except FieldDoesNotExist:
                    raise ValidationError({"level": [_("Attribute does not have verification level.")]})
                min_verification = Identity.VerificationMethod.SELF_ASSURED
                max_verification = Identity.VerificationMethod.STRONG
                if min_verification > int(self.level) or int(self.level) > max_verification:
                    raise ValidationError(
                        {
                            "level": [
                                _("Allowed levels are from %(min) to %(max).")
                                % {"min": min_verification.value, "max": max_verification.value}
                            ]
                        }
                    )

    def test(self, identity: IdentityType) -> bool:
        """
        Test if the requirement is met by the identity.
        """

        from kamu.models.identity import Identity

        if self.type == Requirement.Type.CONTRACT:
            return identity.has_contract(self.value, self.level)
        if self.type == Requirement.Type.ATTRIBUTE:
            if self.value == "phone_number":
                return identity.has_phone_number()
            if self.value == "email_address":
                return identity.has_email_address()
            return identity.has_attribute(self.value, self.level)
        if self.type == Requirement.Type.ASSURANCE:
            return identity.has_assurance(Identity.AssuranceLevel(self.level))
        return False
