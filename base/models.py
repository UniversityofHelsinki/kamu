"""
Base app models.
"""

import hashlib
import secrets
import string
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


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

    def _create_token(self, token_type, membership=None, email=None, phone=None, length=8) -> str:
        """
        Create a new token. Removes existing tokens of the same type and linked object.

        Raises TimeLimitError if token creation is attempted too soon.
        Raises ValueError if linked object or token_type is missing.
        """
        if (not membership and not email and not phone) or not token_type:
            raise ValueError("Missing attributes.")
        create_time_limit = getattr(settings, "TOKEN_TIME_LIMIT_NEW", 60)
        verification_tries = getattr(settings, "TOKEN_VERIFICATION_TRIES", 3)
        try:
            token = self.get(membership=membership, email=email, phone=phone, token_type=token_type)
        except Token.DoesNotExist:
            token = None
        except Token.MultipleObjectsReturned:
            self.filter(membership=membership, email=email, phone=phone, token_type=token_type).delete()
            token = None
        if token:
            if token.created_at < timezone.now() - timedelta(seconds=create_time_limit):
                token.delete()
            else:
                raise TimeLimitError
        secret = self._generate_secret(length=length)
        token = Token()
        salt = self._generate_secret(length=64, alphabet=string.printable)
        token.hash = salt + (hashlib.sha256(f"{self._get_secret_key()}{salt}{secret}".encode()).hexdigest())
        token.tries_left = verification_tries
        token.token_type = token_type
        token.email = email
        token.phone = phone
        token.membership = membership
        token.save()
        return secret

    def create_email_verification_token(self, email) -> str:
        """
        Create a new email verification token.
        """
        return self._create_token("emailverification", email=email)

    def create_sms_verification_token(self, phone) -> str:
        """
        Create a new SMS verification token.
        """
        return self._create_token("smsverification", phone=phone)

    def create_email_login_token(self, email) -> str:
        """
        Create a new email login token.
        """
        return self._create_token("emaillogin", email=email)

    def create_sms_login_token(self, phone) -> str:
        """
        Create a new SMS login token.
        """
        return self._create_token("smslogin", phone=phone)

    def create_invite_token(self, membership) -> str:
        """
        Create a new invite token.
        """
        return self._create_token("invite", membership=membership, length=32)

    def _validate_token(self, secret, token_type, membership=None, email=None, phone=None) -> bool:
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
            token = self.get(membership=membership, email=email, phone=phone, token_type=token_type)
        except Token.DoesNotExist:
            return False
        except Token.MultipleObjectsReturned:
            self.filter(membership=membership, email=email, phone=phone, token_type=token_type).delete()
            return False
        salt = token.hash[:64]
        secret_hash = token.hash[64:]
        token_hash = hashlib.sha256(f"{self._get_secret_key()}{salt}{secret}".encode()).hexdigest()
        if token.created_at < timezone.now() - timedelta(seconds=verification_time_limit):
            token.delete()
            return False
        if token.tries_left > 0 and secrets.compare_digest(secret_hash.encode(), token_hash.encode()):
            token.delete()
            return True
        token.tries_left -= 1
        token.save()
        if token.tries_left <= 0:
            token.delete()
        return False

    def validate_email_verification_token(self, secret, email) -> bool:
        """
        Validates a email verification token.
        """
        return self._validate_token(secret, "emailverification", email=email)

    def validate_sms_verification_token(self, secret, phone) -> bool:
        """
        Validates an SMS verification token.
        """
        return self._validate_token(secret, "smsverification", phone=phone)

    def validate_email_login_token(self, secret, email) -> bool:
        """
        Validates a email login token.
        """
        return self._validate_token(secret, "emaillogin", email=email)

    def validate_sms_login_token(self, secret, phone) -> bool:
        """
        Validates an SMS login token.
        """
        return self._validate_token(secret, "smslogin", phone=phone)

    def validate_invite_token(self, secret, membership) -> bool:
        """
        Validates a invite login token.
        """
        return self._validate_token(secret, "invite", membership=membership)


class Token(models.Model):
    """
    Stores a token, related to :model:`auth.User`, :model:`identity.EmailAddress` and :model:`identity.PhoneNumber`.
    """

    membership = models.ForeignKey("role.Membership", null=True, on_delete=models.CASCADE)
    email = models.ForeignKey("identity.EmailAddress", null=True, on_delete=models.CASCADE)
    phone = models.ForeignKey("identity.PhoneNumber", null=True, on_delete=models.CASCADE)

    TOKEN_TYPE_CHOICES = (
        ("emailverification", _("E-mail verification token")),
        ("smsverification", _("SMS verification token")),
        ("emaillogin", _("E-mail login token")),
        ("smslogin", _("SMS login token")),
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
