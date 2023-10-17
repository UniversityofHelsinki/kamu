from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import Promise
from django.utils.translation import gettext_lazy as _


class Role(models.Model):
    """
    Stores a role
    """

    name = models.CharField(max_length=255, unique=True, verbose_name=_("Role name"))
    parent = models.ForeignKey("self", null=True, blank=True, default=None, on_delete=models.SET_NULL)

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    inviters = models.ManyToManyField(
        "auth.Group", related_name="role_inviters", verbose_name=_("Inviter groups"), blank=True
    )
    approvers = models.ManyToManyField(
        "auth.Group", related_name="role_approvers", verbose_name=_("Approver groups"), blank=True
    )
    permissions = models.ManyToManyField("role.Permission", verbose_name=_("Permissions"), blank=True)

    maximum_duration = models.IntegerField(verbose_name=_("Maximum duration (days)"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("role-detail", kwargs={"pk": self.pk})


class Permission(models.Model):
    """
    Stores a permission, give by a Role
    """

    name = models.CharField(max_length=255, unique=True, verbose_name=_("Permission name"))
    cost = models.IntegerField(verbose_name=_("Permission cost"))
    requirements = models.ManyToManyField("identity.AttributeType", verbose_name=_("Requirements"), blank=True)

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    def __str__(self):
        return self.name


class Membership(models.Model):
    """
    Stores a membership between :model:`identity.Identity` and :model:`identity.Role`
    """

    identity = models.ForeignKey("identity.Identity", on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    approver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    start_date = models.DateField(verbose_name=_("Membership start date"))
    expire_date = models.DateField(verbose_name=_("Membership expire date"))

    def __str__(self) -> str:
        return f"{self.role.name} - {self.identity.pk}"

    def status(self) -> Promise:
        if self.expire_date < timezone.now().date():
            return _("expired")
        elif self.start_date > timezone.now().date():
            return _("pending")
        else:
            return _("active")

    def get_absolute_url(self):
        return reverse("membership-detail", kwargs={"pk": self.pk})
