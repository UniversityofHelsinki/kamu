"""
Base app models.
"""

import hashlib
import secrets
import string
from datetime import timedelta

from django.conf import settings
from django.core.validators import validate_email
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from identity.models import EmailAddress as EmailAddressType
from identity.models import PhoneNumber as PhoneNumberType
from role.models import Membership as MembershipType


class TimeLimitError(Exception):
    """
    Time limit error for token creation.
    """

    pass


class TokenManager(models.Manager["Token"]):
    """
    Manager methods for :model:`base.Token`.
    """

    @staticmethod
    def _generate_secret(length: int = 8, alphabet: str = string.ascii_letters + string.digits) -> str:
        """
        Generate a new secret of chosen length
        """
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def _get_secret_key() -> str:
        """
        Get a secret key for the token. Use TOKEN_SECRET_KEY if available, else SECRET_KEY.
        """
        return getattr(settings, "TOKEN_SECRET_KEY", settings.SECRET_KEY)

    def _create_token(
        self,
        token_type,
        membership: MembershipType | None = None,
        email_object: EmailAddressType | None = None,
        phone_object: PhoneNumberType | None = None,
        email_address: str = "",
        phone_number: str = "",
        length: int = 8,
    ) -> str:
        """
        Create a new token. Removes existing tokens of the same type and linked object.

        Raises TimeLimitError if token creation is attempted too soon.
        Raises ValueError if linked object or token_type is missing.
        """
        if (not any([membership, email_object, phone_object, email_address, phone_number])) or not token_type:
            raise ValueError("Missing attributes.")
        create_time_limit = getattr(settings, "TOKEN_TIME_LIMIT_NEW", 60)
        verification_tries = getattr(settings, "TOKEN_VERIFICATION_TRIES", 3)
        try:
            token = self.get(
                membership=membership,
                email_object=email_object,
                phone_object=phone_object,
                email_address=email_address,
                phone_number=phone_number,
                token_type=token_type,
            )
        except Token.DoesNotExist:
            token = None
        except Token.MultipleObjectsReturned:
            self.filter(
                membership=membership,
                email_object=email_object,
                phone_object=phone_object,
                email_address=email_address,
                phone_number=phone_number,
                token_type=token_type,
            ).delete()
            token = None
        if token:
            if token.created_at < timezone.now() - timedelta(seconds=create_time_limit):
                token.delete()
            else:
                raise TimeLimitError
        secret = self._generate_secret(length=length)
        token = Token(
            tries_left=verification_tries,
            token_type=token_type,
            email_object=email_object,
            phone_object=phone_object,
            membership=membership,
            email_address=email_address,
            phone_number=phone_number,
        )
        salt = self._generate_secret(length=64, alphabet=string.printable)
        token.hash = salt + (hashlib.sha256(f"{self._get_secret_key()}{salt}{secret}".encode()).hexdigest())
        if membership:
            secret = f"{membership.pk}:{secret}"
        token.save()
        return secret

    def create_email_object_verification_token(self, email: EmailAddressType) -> str:
        """
        Create a new email verification token.
        """
        return self._create_token("emailobjectverif", email_object=email)

    def create_phone_object_verification_token(self, phone: PhoneNumberType) -> str:
        """
        Create a new SMS verification token.
        """
        return self._create_token("phoneobjectverif", phone_object=phone)

    def create_email_login_token(self, email: EmailAddressType) -> str:
        """
        Create a new email login token.
        """
        return self._create_token("emaillogin", email_object=email)

    def create_phone_login_token(self, phone: PhoneNumberType) -> str:
        """
        Create a new SMS login token.
        """
        return self._create_token("phonelogin", phone_object=phone)

    def create_email_address_verification_token(self, email_address: str) -> str:
        """
        Create a new email address verification token.
        """
        return self._create_token("emailaddrverif", email_address=email_address)

    def create_phone_number_verification_token(self, phone_number: str) -> str:
        """
        Create a new phone number verification token.
        """
        return self._create_token("phonenumberverif", phone_number=phone_number)

    def create_invite_token(self, membership: MembershipType) -> str:
        """
        Create a new invite token.
        """
        return self._create_token("invite", membership=membership, length=32)

    def _validate_token(
        self,
        secret,
        token_type,
        membership=None,
        email_object=None,
        phone_object=None,
        email_address="",
        phone_number="",
        remove_token=True,
    ) -> bool:
        """
        Validates a token.

        Removes a token if verification is successful, max tries has been reached or time limit is exceeded.

        Reject tokens shorter than 4 characters.
        """
        if len(secret) < 4:
            return False
        if not membership:
            verification_time_limit = getattr(settings, "TOKEN_LIFETIME", 30 * 60)
        else:
            verification_time_limit = getattr(settings, "TOKEN_LIFETIME_INVITE", 30 * 24 * 60 * 60)
        try:
            token = self.get(
                membership=membership,
                email_object=email_object,
                phone_object=phone_object,
                email_address=email_address,
                phone_number=phone_number,
                token_type=token_type,
            )
        except Token.DoesNotExist:
            return False
        except Token.MultipleObjectsReturned:
            self.filter(
                membership=membership,
                email_object=email_object,
                phone_object=phone_object,
                email_address=email_address,
                phone_number=phone_number,
                token_type=token_type,
            ).delete()
            return False
        salt = token.hash[:64]
        secret_hash = token.hash[64:]
        token_hash = hashlib.sha256(f"{self._get_secret_key()}{salt}{secret}".encode()).hexdigest()
        if token.created_at < timezone.now() - timedelta(seconds=verification_time_limit):
            token.delete()
            return False
        if token.tries_left > 0 and secrets.compare_digest(secret_hash.encode(), token_hash.encode()):
            if remove_token:
                token.delete()
            return True
        token.tries_left -= 1
        token.save()
        if token.tries_left <= 0:
            token.delete()
        return False

    def validate_email_object_verification_token(self, secret: str, email: EmailAddressType) -> bool:
        """
        Validates a email verification token.
        """
        return self._validate_token(secret, "emailobjectverif", email_object=email)

    def validate_phone_object_verification_token(self, secret: str, phone: PhoneNumberType) -> bool:
        """
        Validates an SMS verification token.
        """
        return self._validate_token(secret, "phoneobjectverif", phone_object=phone)

    def validate_email_login_token(self, secret: str, email: EmailAddressType) -> bool:
        """
        Validates a email login token.
        """
        return self._validate_token(secret, "emaillogin", email_object=email)

    def validate_phone_login_token(self, secret: str, phone: PhoneNumberType) -> bool:
        """
        Validates an SMS login token.
        """
        return self._validate_token(secret, "phonelogin", phone_object=phone)

    def validate_email_address_verification_token(self, secret: str, email_address: str) -> bool:
        """
        Validates an email address verification token.
        """
        return self._validate_token(secret, "emailaddrverif", email_address=email_address)

    def validate_phone_number_verification_token(self, secret: str, phone_number: str) -> bool:
        """
        Validates a phone number verification token.
        """
        return self._validate_token(secret, "phonenumberverif", phone_number=phone_number)

    def validate_invite_token(self, secret: str, membership: MembershipType, remove_token: bool = True) -> bool:
        """
        Validates a invite login token.
        """
        return self._validate_token(secret, "invite", membership=membership, remove_token=remove_token)


class Token(models.Model):
    """
    Stores a token, related to :model:`auth.User`, :model:`identity.EmailAddress` and :model:`identity.PhoneNumber`.
    """

    membership = models.ForeignKey("role.Membership", null=True, on_delete=models.CASCADE)
    email_object = models.ForeignKey("identity.EmailAddress", null=True, on_delete=models.CASCADE)
    phone_object = models.ForeignKey("identity.PhoneNumber", null=True, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20, blank=True, verbose_name=_("Phone number"))
    email_address = models.CharField(
        max_length=320, blank=True, verbose_name=_("Email address"), validators=[validate_email]
    )

    TOKEN_TYPE_CHOICES = (
        ("emaillogin", _("E-mail login token")),
        ("phonelogin", _("SMS login token")),
        ("emailobjectverif", _("E-mail object verification token")),
        ("phoneobjectverif", _("Phone object verification token")),
        ("emailaddrverif", _("E-mail address verification token")),
        ("phonenumberverif", _("Phone number verification token")),
        ("invite", _("Invite token")),
    )
    token_type = models.CharField(max_length=17, choices=TOKEN_TYPE_CHOICES, verbose_name=_("Token type"))

    hash = models.CharField(max_length=128, verbose_name=_("Salt and a hashed token"))
    tries_left = models.SmallIntegerField(verbose_name=_("Number of tries left"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    objects = TokenManager()

    class Meta:
        verbose_name = _("Login token")
        verbose_name_plural = _("Login tokens")

    def __str__(self):
        return f"{self.token_type}: {self.created_at}"
