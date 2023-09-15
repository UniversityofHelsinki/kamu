from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import Promise
from django.utils.translation import gettext_lazy as _


class Role(models.Model):
    """
    Stores a role
    """

    name = models.CharField(max_length=255, verbose_name=_("Role name"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("role-detail", kwargs={"pk": self.pk})


class Membership(models.Model):
    """
    Stores a membership between :model:`identity.Identity` and :model:`identity.Role`
    """

    identity = models.ForeignKey("identity.Identity", on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    start_date = models.DateField(verbose_name=_("Membership start date"))
    expiring_date = models.DateField(verbose_name=_("Membership expiring date"))

    def __str__(self) -> str:
        return self.identity.user.get_full_name() + " : " + self.role.name

    def status(self) -> Promise:
        if self.expiring_date < timezone.now().date():
            return _("expired")
        elif self.start_date > timezone.now().date():
            return _("pending")
        else:
            return _("active")

    def get_absolute_url(self):
        return reverse("membership-detail", kwargs={"pk": self.pk})
