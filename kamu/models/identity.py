"""
Identity models.
"""

import datetime
from typing import Any, Sequence
from uuid import uuid4

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User as UserType
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import models
from django.db.models import Q, QuerySet
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _
from django_stubs_ext import StrOrPromise

from kamu.models.membership import Membership
from kamu.models.role import Permission, Requirement, Role
from kamu.validators.identity import (
    validate_eidas_identifier,
    validate_fpic,
    validate_phone_number,
)


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
    Manager methods for :class:`kamu.models.identity.Identity`.
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
    Stores an identity, extending :class:`django.contrib.auth.models.User`, related to :class:`kamu.models.role.Role`.
    """

    LANG_CHOICES = (
        ("en", _("English")),
        ("fi", _("Finnish")),
        ("sv", _("Swedish")),
    )

    class Gender(models.TextChoices):
        MALE = ("M", _("Male"))
        FEMALE = ("F", _("Female"))
        OTHER = ("O", _("Other"))
        UNKNOWN = ("U", _("Unknown"))

    class AssuranceLevel(models.IntegerChoices):
        NONE = (0, _("No assurance level"))
        LOW = (1, _("Low, self-asserted with a verified email-address"))
        MEDIUM = (2, _("Medium, verified from a government issued photo-ID"))
        HIGH = (3, _("High, eIDAS substantial level or similar"))

    class VerificationMethod(models.IntegerChoices):
        UNVERIFIED = (0, _("No verification"))
        SELF_ASSURED = (1, _("Self assurance"))
        EXTERNAL = (2, _("External source"))
        PHOTO_ID = (3, _("Verified from a government issued photo-ID"))
        STRONG = (4, _("Strong electrical verification"))

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    kamu_id = models.UUIDField(
        unique=True,
        default=uuid4,
        verbose_name=_("Kamu ID"),
        help_text=_("Unique identifier for this identity."),
    )
    roles = models.ManyToManyField("kamu.Role", through="kamu.Membership")
    uid = models.CharField(
        unique=True,
        blank=True,
        null=True,
        max_length=255,
        verbose_name=_("User identifier"),
    )
    external = models.BooleanField(
        default=False,
        verbose_name=_("External identity"),
        help_text=_("This identity is managed in another registry."),
    )
    assurance_level = models.SmallIntegerField(
        default=0,
        choices=AssuranceLevel.choices,
        verbose_name=_("Assurance level"),
        help_text=_("How strongly this user identity is identified."),
    )
    given_names = models.CharField(
        blank=True, max_length=200, verbose_name=_("Given names"), help_text=_("All official first names.")
    )
    given_names_verification = models.SmallIntegerField(
        choices=VerificationMethod.choices,
        default=VerificationMethod.UNVERIFIED,
        verbose_name=_("Given names verification method"),
    )
    surname = models.CharField(
        blank=True, max_length=200, verbose_name=_("Surname"), help_text=_("Official surname(s).")
    )
    surname_verification = models.SmallIntegerField(
        choices=VerificationMethod.choices,
        default=VerificationMethod.UNVERIFIED,
        verbose_name=_("Surname verification method"),
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
        choices=VerificationMethod.choices,
        default=VerificationMethod.UNVERIFIED,
        verbose_name=_("Date of birth verification method"),
    )
    gender = models.CharField(
        max_length=1,
        choices=Gender.choices,
        default=Gender.UNKNOWN,
        verbose_name=_("Gender"),
        help_text=_("Used for statistical purposes."),
    )
    nationality = models.ManyToManyField(
        Nationality,
        help_text=_("Required for the user identification from the official identity documents."),
    )
    nationality_verification = models.SmallIntegerField(
        choices=VerificationMethod.choices,
        default=VerificationMethod.UNVERIFIED,
        verbose_name=_("Nationality verification method"),
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
        choices=VerificationMethod.choices,
        default=VerificationMethod.UNVERIFIED,
        verbose_name=_("FPIC verification method"),
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

    def email_address(self) -> str | None:
        """
        Returns the highest priority verified email address, if available.
        """
        email_address = self.email_addresses.filter(verified=True).order_by("priority").first()
        return email_address.address if email_address else None

    def phone_number(self) -> str | None:
        """
        Returns the highest priority verified phone number, if available.
        """
        phone_number = self.phone_numbers.filter(verified=True).order_by("priority").first()
        return phone_number.number if phone_number else None

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
        try:
            return Identity.VerificationMethod(value).label
        except ValueError:
            return ""

    @staticmethod
    def get_assurance_level_display_by_value(value: int) -> StrOrPromise:
        try:
            return Identity.AssuranceLevel(value).label
        except ValueError:
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
        Add linked accounts to synchronization queue.
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
        super().save(*args, **kwargs)
        accounts = self.useraccount.filter(status="enabled")
        for account in accounts:
            account.accountsynchronization_set.create()

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

    def has_assurance(self, level: AssuranceLevel) -> bool:
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

    def get_roles(self, membership_statuses: Sequence[Membership.Status] | None = None) -> QuerySet[Role]:
        """
        Returns combined roles of the identity, including hierarchical roles.

        Include only active memberships by default.
        """
        if membership_statuses is None:
            membership_statuses = [Membership.Status.ACTIVE]
        all_roles = Role.objects.none()
        for role in self.roles.filter(membership__status__in=membership_statuses):
            all_roles |= role.get_role_hierarchy()
        return all_roles.distinct()

    def get_permissions(self, permission_type: Permission.Type | None = None) -> QuerySet[Permission]:
        """Returns active permissions of the identity"""
        roles = self.get_roles()
        if permission_type:
            return Permission.objects.filter(role__in=roles, type=permission_type).distinct()
        return Permission.objects.filter(role__in=roles).distinct()

    def get_requirements(self) -> QuerySet[Requirement]:
        """
        Returns combined requirements of all roles of the identity, excluding expired memberships.
        """
        roles = self.get_roles(
            membership_statuses=[
                Membership.Status.REQUIRE,
                Membership.Status.APPROVAL,
                Membership.Status.PENDING,
                Membership.Status.ACTIVE,
            ]
        )
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
    Stores an email address, related to :class:`kamu.models.identity.Identity`.
    """

    identity = models.ForeignKey(
        "kamu.Identity",
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
    Stores a phone number, related to :class:`kamu.models.identity.Identity`.
    """

    identity = models.ForeignKey(
        "kamu.Identity",
        on_delete=models.CASCADE,
        related_name="phone_numbers",
    )
    number = models.CharField(max_length=20, validators=[validate_phone_number], verbose_name=_("Phone number"))
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
    Manager methods for :class:`kamu.models.identity.Identifier`.
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
    Stores a unique identifier, related to :class:`kamu.models.identity.Identity`.
    """

    identity = models.ForeignKey(
        "kamu.Identity",
        on_delete=models.CASCADE,
        related_name="identifiers",
    )

    class Type(models.TextChoices):
        FPIC = ("fpic", _("Finnish national identification number"))
        EIDAS = ("eidas", _("eIDAS identifier"))
        EPPN = ("eppn", _("eduPersonPrincipalName"))
        GOOGLE = ("google", _("Google account"))
        MICROSOFT = ("microsoft", _("Microsoft account"))
        KAMU = ("kamu", _("Kamu identifier"))

    type = models.CharField(max_length=10, choices=Type.choices, verbose_name=_("Identifier type"))
    value = models.CharField(max_length=4000, verbose_name=_("Identifier value"))
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

    def clean(self) -> None:
        """
        Validates identifier values.
        """
        if self.type == self.Type.FPIC:
            validate_fpic(self.value)
        if self.type == self.Type.EIDAS:
            validate_eidas_identifier(self.value)
        if self.type == self.Type.EPPN:
            try:
                validate_email(self.value)
            except ValidationError:
                raise ValidationError(_("Invalid eduPersonPrincipalName format"), code="invalid")

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "identifier_id": self.pk,
            "identifier_type": self.type,
        }
