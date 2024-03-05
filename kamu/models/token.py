"""
Base models.
"""

from __future__ import annotations

import hashlib
import secrets
import string
from datetime import timedelta
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.validators import validate_email
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from kamu.models.membership import Membership

if TYPE_CHECKING:
    from kamu.models.identity import EmailAddress, PhoneNumber


class TimeLimitError(Exception):
    """
    Time limit error for token creation.
    """

    pass


class TokenManager(models.Manager["Token"]):
    """
    Manager methods for :class:`kamu.models.token.Token`.
    """

    @staticmethod
    def get_readable_alphabet() -> str:
        """
        Get alphabet for tokens, without ambiguous characters "01lIO".
        """
        return "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

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
        token_type: "Token.Type",
        membership: Membership | None = None,
        email_object: EmailAddress | None = None,
        phone_object: PhoneNumber | None = None,
        email_address: str = "",
        phone_number: str = "",
        length: int = 8,
        readable_token: bool = False,
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
        if readable_token:
            secret = self._generate_secret(length=length, alphabet=self.get_readable_alphabet())
        else:
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

    def create_email_object_verification_token(self, email: EmailAddress) -> str:
        """
        Create a new email verification token.
        """
        return self._create_token(Token.Type.EMAIL_OBJECT_VERIFICATION, email_object=email, readable_token=True)

    def create_phone_object_verification_token(self, phone: PhoneNumber) -> str:
        """
        Create a new SMS verification token.
        """
        return self._create_token(Token.Type.PHONE_OBJECT_VERIFICATION, phone_object=phone, readable_token=True)

    def create_email_login_token(self, email: EmailAddress) -> str:
        """
        Create a new email login token.
        """
        return self._create_token(Token.Type.EMAIL_LOGIN, email_object=email, readable_token=True)

    def create_phone_login_token(self, phone: PhoneNumber) -> str:
        """
        Create a new SMS login token.
        """
        return self._create_token(Token.Type.PHONE_LOGIN, phone_object=phone, readable_token=True)

    def create_email_address_verification_token(self, email_address: str) -> str:
        """
        Create a new email address verification token.
        """
        return self._create_token(
            Token.Type.EMAIL_ADDRESS_VERIFICATION, email_address=email_address, readable_token=True
        )

    def create_phone_number_verification_token(self, phone_number: str) -> str:
        """
        Create a new phone number verification token.
        """
        return self._create_token(Token.Type.PHONE_NUMBER_VERIFICATION, phone_number=phone_number, readable_token=True)

    def create_invite_token(self, membership: Membership) -> str:
        """
        Create a new invite token.
        """
        return self._create_token(Token.Type.INVITE, membership=membership, length=32)

    def _validate_token(
        self,
        secret: str,
        token_type: "Token.Type",
        membership: Membership | None = None,
        email_object: EmailAddress | None = None,
        phone_object: PhoneNumber | None = None,
        email_address: str = "",
        phone_number: str = "",
        remove_token: bool = True,
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

    def validate_email_object_verification_token(
        self, secret: str, email: EmailAddress, remove_token: bool = True
    ) -> bool:
        """
        Validates a email verification token.
        """
        return self._validate_token(
            secret, Token.Type.EMAIL_OBJECT_VERIFICATION, email_object=email, remove_token=remove_token
        )

    def validate_phone_object_verification_token(
        self, secret: str, phone: PhoneNumber, remove_token: bool = True
    ) -> bool:
        """
        Validates an SMS verification token.
        """
        return self._validate_token(
            secret, Token.Type.PHONE_OBJECT_VERIFICATION, phone_object=phone, remove_token=remove_token
        )

    def validate_email_login_token(self, secret: str, email: EmailAddress) -> bool:
        """
        Validates a email login token.
        """
        return self._validate_token(secret, Token.Type.EMAIL_LOGIN, email_object=email)

    def validate_phone_login_token(self, secret: str, phone: PhoneNumber) -> bool:
        """
        Validates an SMS login token.
        """
        return self._validate_token(secret, Token.Type.PHONE_LOGIN, phone_object=phone)

    def validate_email_address_verification_token(self, secret: str, email_address: str) -> bool:
        """
        Validates an email address verification token.
        """
        return self._validate_token(secret, Token.Type.EMAIL_ADDRESS_VERIFICATION, email_address=email_address)

    def validate_phone_number_verification_token(self, secret: str, phone_number: str) -> bool:
        """
        Validates a phone number verification token.
        """
        return self._validate_token(secret, Token.Type.PHONE_NUMBER_VERIFICATION, phone_number=phone_number)

    def validate_invite_token(self, secret: str, membership: Membership, remove_token: bool = True) -> bool:
        """
        Validates a invite login token.
        """
        return self._validate_token(secret, Token.Type.INVITE, membership=membership, remove_token=remove_token)


class Token(models.Model):
    """
    Stores a token, related to :class:`kamu.models.membership.Membership`, :class:`kamu.models.identity.EmailAddress`
    and :class:`kamu.models.identity.PhoneNumber`.
    """

    membership = models.ForeignKey("kamu.Membership", null=True, on_delete=models.CASCADE)
    email_object = models.ForeignKey("kamu.EmailAddress", null=True, on_delete=models.CASCADE)
    phone_object = models.ForeignKey("kamu.PhoneNumber", null=True, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20, blank=True, verbose_name=_("Phone number"))
    email_address = models.CharField(
        max_length=320, blank=True, verbose_name=_("Email address"), validators=[validate_email]
    )

    class Type(models.TextChoices):
        EMAIL_LOGIN = ("emaillogin", _("E-mail login token"))
        PHONE_LOGIN = ("phonelogin", _("SMS login token"))
        EMAIL_OBJECT_VERIFICATION = ("emailobjectverif", _("E-mail object verification token"))
        PHONE_OBJECT_VERIFICATION = ("phoneobjectverif", _("Phone object verification token"))
        EMAIL_ADDRESS_VERIFICATION = ("emailaddrverif", _("E-mail address verification token"))
        PHONE_NUMBER_VERIFICATION = ("phonenumberverif", _("Phone number verification token"))
        INVITE = ("invite", _("Invite token"))

    token_type = models.CharField(max_length=17, choices=Type.choices, verbose_name=_("Token type"))

    hash = models.CharField(max_length=128, verbose_name=_("Salt and a hashed token"))
    tries_left = models.SmallIntegerField(verbose_name=_("Number of tries left"))

    created_at = models.DateTimeField(default=timezone.now, verbose_name=_("Created at"))
    objects = TokenManager()

    class Meta:
        verbose_name = _("Login token")
        verbose_name_plural = _("Login tokens")

    def __str__(self) -> str:
        return f"{self.token_type}: {self.created_at}"

    def log_values(self) -> dict[str, str | int]:
        """
        Return values for audit log.
        """
        return {
            "token_id": self.pk,
            "token_type": self.token_type,
        }
