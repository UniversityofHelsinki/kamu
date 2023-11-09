"""
Identity app models.
"""

import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _


class Identity(models.Model):
    """
    Stores an identity, extending :model:`auth.User`, related to :model:`identity.Role`.
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    roles = models.ManyToManyField("role.Role", through="role.Membership")
    name = models.CharField(max_length=255, verbose_name=_("Display name"))
    external = models.BooleanField(default=False, verbose_name=_("External identity"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Identity")
        verbose_name_plural = _("Identities")

    def __str__(self):
        return self.name

    def get_attributes(self):
        """
        Returns all attributes linked to the identity.
        """
        attributes = {}
        for attribute in self.attributes.all().prefetch_related("attribute_type"):
            attributes[attribute.attribute_type.identifier] = attribute.value
        return attributes


def validate_attribute_duplicates(error_class, attribute_type, identity, value, pk) -> None:
    """
    Validation checks to prevent duplicates.
    """
    if attribute_type.multi_value is False:
        if pk:
            if Attribute.objects.filter(identity=identity, attribute_type=attribute_type).exclude(pk=pk).exists():
                raise error_class(_(f"An attribute of type {attribute_type.name()} already exists for this identity"))
        elif Attribute.objects.filter(identity=identity, attribute_type=attribute_type).exists():
            raise error_class(_(f"An attribute of type {attribute_type.name()} already exists for this identity"))
    elif Attribute.objects.filter(identity=identity, attribute_type=attribute_type, value=value).exists():
        raise error_class(_("An attribute with the same value already exists for this identity"))


def validate_attribute_uniqueness(error_class, attribute_type, value, pk) -> None:
    """
    Validates unique attribute values.
    """
    if attribute_type.unique is True:
        if pk:
            if Attribute.objects.filter(attribute_type=attribute_type, value=value).exclude(pk=pk).exists():
                raise error_class(_(f"An attribute of type {attribute_type.name()} with value {value} already exists"))
        elif Attribute.objects.filter(attribute_type=attribute_type, value=value).exists():
            raise error_class(_(f"An attribute of type {attribute_type.name()} with value {value} already exists"))


def validate_attribute(error_class, attribute_type, identity, value, pk) -> None:
    """
    Validates an attribute value against its constraints and type regex pattern.
    """
    validate_attribute_duplicates(error_class, attribute_type, identity, value, pk)
    validate_attribute_uniqueness(error_class, attribute_type, value, pk)
    try:
        if not re.match(attribute_type.regex_pattern, value):
            raise error_class(f"Attribute {attribute_type.name()} value {value} does not match validation pattern")
    except re.error:
        raise error_class(_(f"Invalid validation configuration for attribute {attribute_type.name()}"))


class Attribute(models.Model):
    """
    Stores a user attribute value, related to :model:`identity.Identity` and :model:`identity.AttributeType`.
    """

    identity = models.ForeignKey(
        "identity.Identity",
        on_delete=models.CASCADE,
        related_name="attributes",
    )
    attribute_type = models.ForeignKey("identity.AttributeType", on_delete=models.RESTRICT)
    value = models.CharField(max_length=255, verbose_name=_("Attribute value"))
    source = models.CharField(max_length=20, verbose_name=_("Attribute source"))
    priority = models.SmallIntegerField(default=0, verbose_name=_("Attribute priority"))
    validated = models.BooleanField(default=False, verbose_name=_("Validated"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Attribute")
        verbose_name_plural = _("Attributes")

    def __str__(self):
        return f"{self.identity.name}-{self.attribute_type.name()}"

    def clean(self):
        """
        Data validation for attributes.
        """
        validate_attribute(ValidationError, self.attribute_type, self.identity, self.value, self.pk)


class AttributeType(models.Model):
    """
    Stores an attribute type.
    """

    identifier = models.CharField(max_length=20, unique=True, verbose_name=_("Attribute identifier"))
    name_fi = models.CharField(max_length=20, verbose_name=_("Attribute name (fi)"))
    name_en = models.CharField(max_length=20, verbose_name=_("Attribute name (en)"))
    name_sv = models.CharField(max_length=20, verbose_name=_("Attribute name (sv)"))
    description_fi = models.CharField(max_length=255, verbose_name=_("Attribute description (fi)"))
    description_en = models.CharField(max_length=255, verbose_name=_("Attribute description (en)"))
    description_sv = models.CharField(max_length=255, verbose_name=_("Attribute description (sv)"))

    multi_value = models.BooleanField(default=False, verbose_name=_("Multi value attribute"))
    unique = models.BooleanField(default=False, verbose_name=_("Require Unique value"))
    regex_pattern = models.CharField(max_length=255, verbose_name=_("Regex validation pattern"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Attribute type")
        verbose_name_plural = _("Attribute types")

    def __str__(self):
        return self.name()

    def name(self, lang=get_language()) -> str:
        """
        Returns attribute name in a given language (defaulting current language, or English).
        """
        if lang == "fi":
            return self.name_fi
        elif lang == "sv":
            return self.name_sv
        else:
            return self.name_en

    def description(self, lang=get_language()) -> str:
        """
        Returns attribute description in a given language (defaulting current language, or English).
        """
        if lang == "fi":
            return self.description_fi
        elif lang == "sv":
            return self.description_sv
        else:
            return self.description_en

    def clean(self):
        """
        Validates that pattern is valid regex.
        """
        try:
            re.compile(self.regex_pattern)
        except re.error:
            raise ValidationError(_("Invalid regex pattern"))


class Identifier(models.Model):
    """
    Stores a unique identifier, related to :model:`identity.Identity`.
    """

    identity = models.ForeignKey(
        "identity.Identity",
        on_delete=models.CASCADE,
        related_name="identifiers",
    )

    IDENTIFIER_CHOICES = (
        ("hetu", _("Finnish national identification number")),
        ("eidas", _("eIDAS identifier")),
        ("eppn", _("eduPersonPrincipalName")),
        ("google", _("Google account")),
        ("microsoft", _("Microsoft account")),
    )
    type = models.CharField(max_length=10, choices=IDENTIFIER_CHOICES, verbose_name=_("Identifier type"))
    value = models.CharField(max_length=255, verbose_name=_("Identifier value"))
    validated = models.BooleanField(default=False, verbose_name=_("Validated"))

    deactivated_at = models.DateTimeField(blank=True, null=True, verbose_name=_("Deactivated at"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Identifier")
        verbose_name_plural = _("Identifiers")

    def __str__(self):
        return f"{self.identity.name}-{self.type}"
