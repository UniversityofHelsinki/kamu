from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class Identity(models.Model):
    """
    Stores an identity, extending :model:`auth.User`, related to :model:`identity.Role`
    """

    user = models.OneToOneField("auth.User", on_delete=models.CASCADE)
    roles = models.ManyToManyField("role.Role", through="role.Membership")
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    def __str__(self):
        return self.user.get_full_name()
