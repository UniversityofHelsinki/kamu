"""
Identity app models.
"""

from django.conf import settings
from django.core.validators import validate_email
from django.db import models
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _

from identity.validators import validate_fpic


class Nationality(models.Model):
    """
    Stores a nationality.
    """

    code = models.CharField(max_length=2, unique=True, verbose_name=_("Country code"))
    name_fi = models.CharField(max_length=100, verbose_name=_("Country name (fi)"))
    name_en = models.CharField(max_length=100, verbose_name=_("Country name (en)"))
    name_sv = models.CharField(max_length=100, verbose_name=_("Country name (sv)"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        verbose_name = _("Nationality")
        verbose_name_plural = _("Nationalities")

    def __str__(self):
        return self.name()

    def name(self, lang=get_language()) -> str:
        """
        Returns nationality name in a given language (defaulting current language, or English).
        """
        if lang == "fi":
            return self.name_fi
        elif lang == "sv":
            return self.name_sv
        else:
            return self.name_en


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
    uid = models.CharField(
        blank=True,
        max_length=11,
        verbose_name=_("HY user account name"),
        help_text=_("University of Helsinki user account name."),
    )
    external = models.BooleanField(
        default=False,
        verbose_name=_("External identity"),
        help_text=_("This identity is managed in another registry."),
    )
    assurance_level = models.CharField(
        max_length=10,
        default="none",
        choices=ASSURANCE_CHOICES,
        verbose_name=_("Assurance level"),
        help_text=_("How strongly this user identity is identified."),
    )
    given_names = models.CharField(
        blank=True, max_length=200, verbose_name=_("Given names"), help_text=_("All official first names.")
    )
    given_names_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("Given names verification method")
    )
    surname = models.CharField(
        blank=True, max_length=200, verbose_name=_("Surname"), help_text=_("Official surname(s).")
    )
    surname_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("Surname verification method")
    )
    given_name_display = models.CharField(
        blank=True,
        max_length=200,
        verbose_name=_("Displayed given name"),
        help_text=_("A given name or nickname part of the user's display name."),
    )
    surname_display = models.CharField(
        blank=True,
        max_length=200,
        verbose_name=_("Displayed surname"),
        help_text=_("A surname part of the user's display name."),
    )
    date_of_birth = models.DateField(
        blank=True,
        null=True,
        verbose_name=_("Date of birth"),
        help_text=_("Required for the user identification from the official identity documents."),
    )
    date_of_birth_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("Date of birth verification method")
    )
    gender = models.CharField(
        max_length=1,
        choices=GENDER_CHOICES,
        default="U",
        verbose_name=_("Gender"),
        help_text=_("Used for statistical purposes."),
    )
    nationality = models.ManyToManyField(
        Nationality,
        help_text=_("Required for the user identification from the official identity documents."),
    )
    nationality_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("Nationality verification method")
    )
    fpic = models.CharField(
        blank=True,
        max_length=11,
        verbose_name=_("Finnish personal identity code"),
        validators=[validate_fpic],
        help_text=_("Used for the strong electrical identification."),
    )
    fpic_verification = models.SmallIntegerField(
        choices=VERIFICATION_CHOICES, default=0, verbose_name=_("FPIC verification method")
    )
    preferred_language = models.CharField(
        max_length=2,
        choices=LANG_CHOICES,
        default="en",
        verbose_name=_("Preferred language"),
        help_text=_("Preferred service language."),
    )
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        permissions = [
            ("view_basic_information", "Can view basic information"),
            ("change_basic_information", "Can change basic information"),
            ("view_restricted_information", "Can view restricted information"),
            ("change_restricted_information", "Can change restricted information"),
            ("view_contacts", "Can view contact information"),
            ("change_contacts", "Can change contact information"),
            ("view_identifiers", "Can view identifiers"),
            ("change_identifiers", "Can change identifiers"),
        ]
        verbose_name = _("Identity")
        verbose_name_plural = _("Identities")

    def __str__(self):
        return self.display_name()

    def display_name(self) -> str:
        return f"{self.given_name_display} {self.surname_display}"

    @staticmethod
    def basic_fields() -> list[str]:
        return ["given_names", "surname", "given_name_display", "surname_display", "preferred_language"]

    @staticmethod
    def basic_verification_fields() -> list[str]:
        return ["given_names_verification", "surname_verification"]

    @staticmethod
    def restricted_fields() -> list[str]:
        return ["date_of_birth", "gender", "nationality", "fpic"]

    @staticmethod
    def restricted_verification_fields() -> list[str]:
        return ["date_of_birth_verification", "nationality_verification", "fpic_verification"]

    def verifiable_fields(self) -> list[str]:
        """
        Return all fields with a verification field.
        """
        return [
            attr.removesuffix("_verification")
            for attr in self.basic_verification_fields() + self.restricted_verification_fields()
        ]

    def save(self, *args, **kwargs) -> None:
        """
        Override save method to update the user's display names if they are not given.
        """
        if not self.given_name_display:
            self.given_name_display = self.given_names.split(" ")[0]
        if not self.surname_display:
            self.surname_display = self.surname.split(" ")[0]
        super(Identity, self).save(*args, **kwargs)


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
