"""
Identity app models.
"""

from django.conf import settings
from django.core.validators import validate_email
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class Identity(models.Model):
    """
    Stores an identity, extending :model:`auth.User`, related to :model:`identity.Role`.
    """

    LANG_CHOICES = (
        ("en", _("English")),
        ("fi", _("Finnish")),
        ("sv", _("Swedish")),
    )
    GENDER_CHOICES = (
        ("M", _("Male")),
        ("F", _("Female")),
        ("O", _("Other")),
        ("U", _("Unknown")),
    )
    ASSURANCE_CHOICES = (
        ("none", _("No assurance level")),
        ("low", _("Low, self-asserted with a verified email-address")),
        ("medium", _("Medium, verified from a government issued photo-ID")),
        ("high", _("High, eIDAS substantial level or similar")),
    )
    VERIFICATION_CHOICES = (
        (0, _("No verification")),
        (1, _("Self assurance")),
        (2, _("External source")),
        (3, _("Verified from a government issued photo-ID")),
        (4, _("Strong electrical verification")),
    )
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    roles = models.ManyToManyField("role.Role", through="role.Membership")
    external = models.BooleanField(default=False, verbose_name=_("External identity"))
    assurance_level = models.CharField(
        max_length=10, default="none", choices=ASSURANCE_CHOICES, verbose_name=_("Assurance level")
    )
    given_names = models.CharField(blank=True, max_length=255, verbose_name=_("Given names"))
    given_names_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("Given names verification method")
    )
    surname = models.CharField(blank=True, max_length=255, verbose_name=_("Surname"))
    surname_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("Surname verification method")
    )
    nickname = models.CharField(blank=True, max_length=255, verbose_name=_("Nickname"))
    nickname_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("Nickname verification method")
    )
    date_of_birth = models.DateField(blank=True, null=True, verbose_name=_("Date of birth"))
    date_of_birth_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("Date of birth verification method")
    )
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, default="U", verbose_name=_("Gender"))
    gender_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("Gender verification method")
    )
    nationality = models.CharField(blank=True, max_length=255, verbose_name=_("Nationality"))
    nationality_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("Nationality verification method")
    )
    preferred_language = models.CharField(
        max_length=2, choices=LANG_CHOICES, default="en", verbose_name=_("Preferred language")
    )
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Identity")
        verbose_name_plural = _("Identities")

    def __str__(self):
        return self.display_name()

    def display_name(self) -> str:
        return f"{self.nickname} {self.surname}"


class EmailAddress(models.Model):
    """
    Stores an email address, related to :model:`identity.Identity`.
    """

    identity = models.ForeignKey(
        "identity.Identity",
        on_delete=models.CASCADE,
        related_name="email_addresses",
    )
    address = models.CharField(max_length=320, verbose_name=_("Email address"), validators=[validate_email])
    priority = models.SmallIntegerField(default=0, verbose_name=_("Priority"))
    verified = models.BooleanField(default=False, verbose_name=_("Verified"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        constraints = [models.UniqueConstraint(fields=["identity", "address"], name="unique_email_address")]
        verbose_name = _("E-mail address")
        verbose_name_plural = _("E-mail addresses")

    def __str__(self):
        return f"{self.address}"


class PhoneNumber(models.Model):
    """
    Stores a phone number, related to :model:`identity.Identity`.
    """

    identity = models.ForeignKey(
        "identity.Identity",
        on_delete=models.CASCADE,
        related_name="phone_numbers",
    )
    number = models.CharField(max_length=20, verbose_name=_("Phone number"))
    priority = models.SmallIntegerField(default=0, verbose_name=_("Priority"))
    verified = models.BooleanField(default=False, verbose_name=_("Verified"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        constraints = [models.UniqueConstraint(fields=["identity", "number"], name="unique_phone_number")]
        verbose_name = _("Phone number")
        verbose_name_plural = _("Phone numbers")

    def __str__(self):
        return f"{self.number}"


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
    verified = models.BooleanField(default=False, verbose_name=_("Verified"))

    deactivated_at = models.DateTimeField(blank=True, null=True, verbose_name=_("Deactivated at"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Identifier")
        verbose_name_plural = _("Identifiers")

    def __str__(self):
        return f"{self.identity.display_name()}-{self.type}"
