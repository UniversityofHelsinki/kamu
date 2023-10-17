from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class Identity(models.Model):
    """
    Stores an identity, extending :model:`auth.User`, related to :model:`identity.Role`
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    roles = models.ManyToManyField("role.Role", through="role.Membership")
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    def __str__(self):
        if hasattr(self, "user") and self.user is not None:
            return self.user.get_full_name()
        return str(self.pk)


class Attribute(models.Model):
    """
    Stores a user attribute value, related to :model:`identity.Identity` and :model:`identity.AttributeType`
    """

    identity = models.ForeignKey(
        "identity.Identity",
        on_delete=models.CASCADE,
        related_name="attributes",
    )
    attribute_type = models.ForeignKey("identity.AttributeType", on_delete=models.RESTRICT)
    value = models.CharField(max_length=255, verbose_name=_("Attribute value"))
    source = models.CharField(max_length=20, verbose_name=_("Attribute source"))
    validated = models.BooleanField(default=False, verbose_name=_("Validated"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    def __str__(self):
        return f"{self.identity.pk}-{self.attribute_type.name}"


class AttributeType(models.Model):
    """
    Stores an attribute type
    """

    name = models.CharField(max_length=255, unique=True, verbose_name=_("Attribute name"))
    multi_value = models.BooleanField(default=False, verbose_name=_("Multi value attribute"))
    unique = models.BooleanField(default=False, verbose_name=_("Require Unique value"))
    regex_pattern = models.CharField(max_length=255, verbose_name=_("Regex validation pattern"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    def __str__(self):
        return self.name
