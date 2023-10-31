from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _


class Role(models.Model):
    """
    Stores a role
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

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Role")
        verbose_name_plural = _("Roles")

    def __str__(self):
        return self.name()

    def name(self, lang=get_language()) -> str:
        """
        Returns Role name in a given language (defaulting current language, or English).
        """
        if lang == "fi":
            return self.name_fi
        elif lang == "sv":
            return self.name_sv
        else:
            return self.name_en

    def description(self, lang=get_language()) -> str:
        """
        Returns Role description in a given language (defaulting current language, or English).
        """
        if lang == "fi":
            return self.description_fi
        elif lang == "sv":
            return self.description_sv
        else:
            return self.description_en

    def get_absolute_url(self):
        return reverse("role-detail", kwargs={"pk": self.pk})


class Permission(models.Model):
    """
    Stores a permission, give by a Role
    """

    identifier = models.CharField(max_length=20, unique=True, verbose_name=_("Permission identifier"))
    name_fi = models.CharField(max_length=50, verbose_name=_("Permission name (fi)"))
    name_en = models.CharField(max_length=50, verbose_name=_("Permission name (en)"))
    name_sv = models.CharField(max_length=50, verbose_name=_("Permission name (sv)"))
    description_fi = models.CharField(max_length=255, verbose_name=_("Permission description (fi)"))
    description_en = models.CharField(max_length=255, verbose_name=_("Permission description (en)"))
    description_sv = models.CharField(max_length=255, verbose_name=_("Permission description (sv)"))

    cost = models.IntegerField(verbose_name=_("Permission cost"))
    requirements = models.ManyToManyField("identity.AttributeType", verbose_name=_("Requirements"), blank=True)

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Permission")
        verbose_name_plural = _("Permissions")

    def __str__(self):
        return self.name()

    def name(self, lang=get_language()) -> str:
        """
        Returns Permission name in a given language (defaulting current language, or English).
        """
        if lang == "fi":
            return self.name_fi
        elif lang == "sv":
            return self.name_sv
        else:
            return self.name_en

    def description(self, lang=get_language()) -> str:
        """
        Returns Permission description in a given language (defaulting current language, or English).
        """
        if lang == "fi":
            return self.description_fi
        elif lang == "sv":
            return self.description_sv
        else:
            return self.description_en


def validate_membership(error_class, role, start_date, expire_date) -> None:
    """
    Validates membership dates
    """
    if expire_date < start_date:
        raise error_class(_("Role expire date cannot be earlier than start date"))
    if (expire_date - start_date).days > role.maximum_duration:
        raise error_class(_("Role duration cannot be more than maximum duration"))
    if expire_date < timezone.now().date():
        raise error_class(_("Role expire date cannot be in the past"))
    if start_date < timezone.now().date():
        raise error_class(_("Role start date cannot be in the past"))


class Membership(models.Model):
    """
    Stores a membership between :model:`identity.Identity` and :model:`identity.Role`
    """

    identity = models.ForeignKey("identity.Identity", on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    STATUS_CHOICES = (
        ("require", _("Waiting requirements")),
        ("approval", _("Waiting approval")),
        ("pending", _("Pending")),
        ("active", _("Active")),
        ("expired", _("Expired")),
    )
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

    class Meta:
        verbose_name = _("Membership")
        verbose_name_plural = _("Memberships")

    def __str__(self) -> str:
        return f"{self.role.name()} - {self.identity.name}"

    def get_absolute_url(self):
        return reverse("membership-detail", kwargs={"pk": self.pk})
