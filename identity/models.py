"""
Identity app models.
"""

import datetime
import itertools
from hashlib import sha256
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User as UserType
from django.core.validators import validate_email
from django.db import models
from django.db.models import Q, QuerySet
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _
from django_stubs_ext import StrOrPromise

from identity.validators import validate_fpic
from role.models import Permission, Requirement, Role


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

    def __str__(self) -> str:
        return self.name()

    def name(self, lang: str | None = None) -> str:
        """
        Returns nationality name in a given language (defaulting current language, or English).
        """
        if not lang:
            lang = get_language()
        if lang == "fi":
            return self.name_fi
        elif lang == "sv":
            return self.name_sv
        else:
            return self.name_en

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "nationality_id": self.pk,
            "nationality_code": self.code,
        }


class CustomUserManager:
    """
    Custom manager methods for User. As the user model is dynamically
    determined, this is not the real manager class, just a place to
    hold the methods. They need to be explicitly called.
    """

    @staticmethod
    def get_stale(grace_days: int | None = None) -> QuerySet["UserType"]:
        """
        Returns a list of user objects that don't have a linked identity,
        own no roles, are not involved in any active memberships, and
        and grace_days (defaulting to the PURGE_DELAY_DAYS setting)
        have passed since last login time.
        """
        delay = grace_days or int(getattr(settings, "PURGE_DELAY_DAYS", 730))
        cutoff = timezone.now() - datetime.timedelta(days=delay)
        return get_user_model().objects.filter(
            identity=None, role__owner=None, membership_inviter=None, membership_approver=None, last_login__lt=cutoff
        )


class IdentityManager(models.Manager["Identity"]):
    """
    Manager methods for :model:`identity.Identity`.
    """

    def get_stale(self, grace_days: int | None = None) -> QuerySet["Identity"]:
        """
        Returns a list of identity objects that don't have any role
        memberships and grace_days (defaulting to the PURGE_DELAY_DAYS
        setting) have passed since creation and last login times.
        """
        delay = grace_days or int(getattr(settings, "PURGE_DELAY_DAYS", 730))
        cutoff = timezone.now() - datetime.timedelta(days=delay)
        return self.filter(Q(membership=None, created_at__lt=cutoff) & (Q(user=None) | Q(user__last_login__lt=cutoff)))


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
        (0, _("No assurance level")),
        (1, _("Low, self-asserted with a verified email-address")),
        (2, _("Medium, verified from a government issued photo-ID")),
        (3, _("High, eIDAS substantial level or similar")),
    )
    VERIFICATION_CHOICES = (
        (0, _("No verification")),
        (1, _("Self assurance")),
        (2, _("External source")),
        (3, _("Verified from a government issued photo-ID")),
        (4, _("Strong electrical verification")),
    )
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    kamu_id = models.UUIDField(
        unique=True,
        default=uuid4,
        verbose_name=_("Kamu ID"),
        help_text=_("Unique identifier for this identity."),
    )
    roles = models.ManyToManyField("role.Role", through="role.Membership")
    uid = models.CharField(
        unique=True,
        blank=True,
        null=True,
        max_length=11,
        verbose_name=_("HY user account name"),
        help_text=_("University of Helsinki user account name."),
    )
    external = models.BooleanField(
        default=False,
        verbose_name=_("External identity"),
        help_text=_("This identity is managed in another registry."),
    )
    assurance_level = models.SmallIntegerField(
        default=0,
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
        unique=True,
        blank=True,
        null=True,
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

    objects = IdentityManager()

    class Meta:
        permissions = [
            ("view_basic_information", "Can view basic information"),
            ("change_basic_information", "Can change basic information"),
            ("view_restricted_information", "Can view restricted information"),
            ("change_restricted_information", "Can change restricted information"),
            ("view_contacts", "Can view contact information"),
            ("change_contacts", "Can change contact information"),
            ("view_contracts", "Can view contract information"),
            ("view_identifiers", "Can view identifiers"),
            ("change_identifiers", "Can change identifiers"),
            ("search_identities", "Can search identities"),
            ("combine_identities", "Can combine identities"),
        ]
        verbose_name = _("Identity")
        verbose_name_plural = _("Identities")

    def __str__(self) -> str:
        return self.display_name()

    def display_name(self) -> str:
        return f"{self.given_name_display} {self.surname_display}"

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "identity_id": self.pk,
            "identity": self.display_name(),
        }

    @staticmethod
    def get_verification_level_display_by_value(value: int) -> StrOrPromise:
        for level, name in Identity.VERIFICATION_CHOICES:
            if level == value:
                return name
        return ""

    @staticmethod
    def get_assurance_level_display_by_value(value: int) -> StrOrPromise:
        for level, name in Identity.ASSURANCE_CHOICES:
            if level == value:
                return name
        return ""

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

    def save(self, *args: Any, **kwargs: Any) -> None:
        """
        Override save method to update the user's display names if they are not given.
        """
        if not self.given_name_display:
            self.given_name_display = self.given_names.split(" ")[0]
        if not self.surname_display:
            self.surname_display = self.surname.split(" ")[0]
        if self.user and (
            self.user.first_name != self.given_name_display or self.user.last_name != self.surname_display
        ):
            self.user.first_name = self.given_name_display
            self.user.last_name = self.surname_display
            self.user.save()
        super(Identity, self).save(*args, **kwargs)

    def has_attribute(self, name: str, level: int = 0) -> bool:
        """
        Returns True if the identity has attribute value defined.

        If level is given and attribute is verifiable, require at least that level of verification.
        """
        value = getattr(self, name, None)
        if value is not None and (value or isinstance(value, int)):
            if name not in self.verifiable_fields() or getattr(self, f"{name}_verification") >= level:
                return True
        return False

    def has_assurance(self, level: int) -> bool:
        """
        Returns True if the identity has at least assurance level.
        """
        return self.assurance_level >= level

    def has_contract(self, contract_type: str, version: int = 0) -> bool:
        """
        Returns True if the identity has signed the contract.

        If version is given, require at least that version of the contract.
        """
        return self.contracts.filter(template__type=contract_type, template__version__gte=version).exists()

    def has_email_address(self) -> bool:
        """
        Returns True if the identity has at least one verified email address.
        """
        return self.email_addresses.filter(verified=True).exists()

    def has_phone_number(self) -> bool:
        """
        Returns True if the identity has at least one verified phone number.
        """
        return self.phone_numbers.filter(verified=True).exists()

    def get_requirements(self) -> QuerySet[Requirement]:
        """
        Returns combined requirements of all roles of the identity.
        """
        all_roles = Role.objects.none()
        for role in self.roles.all():
            all_roles |= role.get_role_hierarchy()
        roles = all_roles.distinct()
        permissions = Permission.objects.filter(role__in=roles).distinct()
        return Requirement.objects.filter(
            Q(role_requirements__in=roles) | Q(permission_requirements__in=permissions)
        ).distinct()

    def get_missing_requirements(self) -> QuerySet[Requirement]:
        """
        Returns requirements that are not met by the identity.
        """
        requirements = self.get_requirements()
        missing = Requirement.objects.none()
        for requirement in requirements:
            if not requirement.test(self):
                missing |= Requirement.objects.filter(pk=requirement.pk)
        return missing


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
        ordering = ["identity", "verified", "priority"]
        verbose_name = _("E-mail address")
        verbose_name_plural = _("E-mail addresses")

    def __str__(self) -> str:
        return f"{self.address}"

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "email_address_id": self.pk,
            "email_address": self.address,
        }


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
        ordering = ["identity", "verified", "priority"]
        verbose_name = _("Phone number")
        verbose_name_plural = _("Phone numbers")

    def __str__(self) -> str:
        return f"{self.number}"

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "phone_number_id": self.pk,
            "phone_number": self.number,
        }


class IdentifierManager(models.Manager["Identifier"]):
    """
    Manager methods for :model:`identity.Identifier`.
    """

    def get_stale(self, grace_days: int | None = None) -> QuerySet["Identifier"]:
        """
        Returns a list of identifier objects that were deactivated at
        least grace_days (defaulting to the PURGE_DELAY_DAYS setting) ago.
        """
        delay = grace_days or int(getattr(settings, "PURGE_DELAY_DAYS", 730))
        cutoff = timezone.now() - datetime.timedelta(days=delay)
        return self.filter(deactivated_at__lt=cutoff)


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
        ("fpic", _("Finnish national identification number")),
        ("eidas", _("eIDAS identifier")),
        ("eppn", _("eduPersonPrincipalName")),
        ("google", _("Google account")),
        ("microsoft", _("Microsoft account")),
        ("kamu", _("Kamu identifier")),
    )
    type = models.CharField(max_length=10, choices=IDENTIFIER_CHOICES, verbose_name=_("Identifier type"))
    value = models.CharField(max_length=255, verbose_name=_("Identifier value"))
    verified = models.BooleanField(default=False, verbose_name=_("Verified"))

    deactivated_at = models.DateTimeField(blank=True, null=True, verbose_name=_("Deactivated at"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    objects = IdentifierManager()

    class Meta:
        verbose_name = _("Identifier")
        verbose_name_plural = _("Identifiers")

    def __str__(self) -> str:
        return f"{self.identity.display_name()}-{self.type}"

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "identifier_id": self.pk,
            "identifier_type": self.type,
        }


class ContractTemplate(models.Model):
    """
    Stores a contract template.

    All contract templates are readable by all logged-in users. Public means the contract is listed
    in the UI, as signable contract.
    """

    type = models.CharField(max_length=20, verbose_name=_("Contract type"))
    version = models.SmallIntegerField(verbose_name=_("Contract version"))
    name_fi = models.CharField(max_length=100, verbose_name=_("Contract name (fi)"))
    name_en = models.CharField(max_length=100, verbose_name=_("Contract name (en)"))
    name_sv = models.CharField(max_length=100, verbose_name=_("Contract name (sv)"))
    text_fi = models.TextField(verbose_name=_("Contract text (fi)"))
    text_en = models.TextField(verbose_name=_("Contract text (en)"))
    text_sv = models.TextField(verbose_name=_("Contract text (sv)"))
    public = models.BooleanField(default=False, verbose_name=_("Public"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["type", "version"], name="unique_contract_template"),
        ]
        verbose_name = _("Contract template")
        verbose_name_plural = _("Contract templates")

    def __str__(self) -> str:
        return f"{self.type}-{self.version}"

    def name(self, lang: str | None = None) -> str:
        """
        Returns contract name in a given language (defaulting current language, or English).
        """
        if not lang:
            lang = get_language()
        if lang == "fi":
            return self.name_fi
        elif lang == "sv":
            return self.name_sv
        else:
            return self.name_en

    def text(self, lang: str | None = None) -> str:
        """
        Returns contract text in a given language (defaulting current language, or English).
        """
        if not lang:
            lang = get_language()
        if lang == "fi":
            return self.text_fi
        elif lang == "sv":
            return self.text_sv
        else:
            return self.text_en

    def save(self, *args: Any, **kwargs: Any) -> None:
        """
        Override save method to create a new version instead of updating the existing one.
        Version starts from one for each contract type.
        """
        last = ContractTemplate.objects.filter(type=self.type).order_by("-version").first()
        self.version = last.version + 1 if last else 1
        if self.pk:
            self.pk = None
        super(ContractTemplate, self).save(*args, **kwargs)

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "contract_template_id": self.pk,
            "contract_template_version": self.type,
            "contract_template_type": self.type,
        }


class ContractManager(models.Manager["Contract"]):
    """
    Manager methods for :model:`identity.Contract`.
    """

    def sign_contract(self, template: ContractTemplate, identity: Identity) -> "Contract":
        """
        Creates a contract for the given identity.
        """
        if template != ContractTemplate.objects.filter(type=template.type).order_by("-version").first():
            raise ValueError("Template is not the latest version.")
        time = timezone.now()
        lang = get_language()
        checksum = sha256(
            f"{template.text(lang=lang)}.{identity.kamu_id}.{time.isoformat()}".encode("utf-8")
        ).hexdigest()
        return self.create(identity=identity, template=template, checksum=checksum, created_at=time, lang=lang)


class Contract(models.Model):
    """
    Stores a contract, related to :model:`identity.Identity` and :model:`identity.ContractTemplate`.
    """

    identity = models.ForeignKey(
        "identity.Identity",
        on_delete=models.CASCADE,
        related_name="contracts",
    )
    template = models.ForeignKey(
        "identity.ContractTemplate",
        on_delete=models.CASCADE,
    )
    checksum = models.CharField(max_length=64, verbose_name=_("Checksum"))
    lang = models.CharField(max_length=2, verbose_name=_("Language"))
    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))

    objects = ContractManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["identity", "template"], name="unique_contract"),
        ]
        verbose_name = _("Contract")
        verbose_name_plural = _("Contracts")

    def __str__(self) -> str:
        return f"{ self.template.name() }.{ self.template.version }: { self.identity.display_name() }"

    def validate(self) -> bool:
        """
        Validates the contract against all kamu_ids of the identity.
        """
        other_ids = (i.value for i in Identifier.objects.filter(type="kamu", identity=self.identity))
        for kamu_id in itertools.chain([self.identity.kamu_id], other_ids):
            if (
                self.checksum
                == sha256(
                    f"{self.template.text(lang=self.lang)}.{kamu_id}.{self.created_at.isoformat()}".encode("utf-8")
                ).hexdigest()
            ):
                return True
        return False

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "contract_id": self.pk,
            "contract_checksum": self.checksum,
            "contract_time": self.created_at.isoformat(),
        }
