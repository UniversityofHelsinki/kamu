"""
Authentication backends
"""
import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import Group
from django.contrib.auth.models import User as UserType
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from identity.models import EmailAddress, Identifier, Identity

UserModel = get_user_model()
logger = logging.getLogger(__name__)


class LocalBaseBackend(BaseBackend):
    """
    Local authentication backend base with some custom functions.
    """

    def get_user(self, user_id: int) -> UserType | None:
        """
        Return user object if it exists and is active.
        """
        try:
            user = UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
        return user if user.is_active else None

    @staticmethod
    def create_identity(user: UserType) -> Identity:
        """
        Create a new identity for user.
        """
        identity = Identity.objects.create(user=user, given_names=user.first_name, surname=user.last_name)
        if user.email:
            EmailAddress.objects.create(address=user.email, identity=identity)
        return identity

    @staticmethod
    def create_user(username: str, email: str, given_names: str, surname: str) -> UserType:
        """
        Create a new user with unusable password.
        """
        user = UserModel.objects.create_user(
            username,
            email=email,
            password=None,
            first_name=given_names,
            last_name=surname,
        )
        user.set_unusable_password()
        user.save()
        return user

    def link_identifier(self, user: UserType, identifier_type: str, identifier_value: str) -> None:
        """
        Link identifier to the current user identity. Create identity if the user is authenticated and
        doesn't have an identity.
        """
        if hasattr(user, "identity"):
            identity = user.identity
        else:
            identity = self.create_identity(user)
        Identifier.objects.get_or_create(type=identifier_type, value=identifier_value, identity=identity)
        return None


class ShibbolethBackend(LocalBaseBackend):
    """
    Backend for Shibboleth authentication.

    If Shibboleth eduPersonPrincipalName attribute is found.
    - Creates a new user if user does not exist.
    - Updates groups with prefixes in SAML_ATTR_GROUPS.
    """

    def authenticate(self, request, create_user=False, **kwargs) -> UserType | None:
        username = request.META.get(settings.SAML_ATTR_EPPN, "")
        given_names = request.META.get(settings.SAML_ATTR_GIVEN_NAMES, "")
        surname = request.META.get(settings.SAML_ATTR_SURNAME, "")
        email = request.META.get(settings.SAML_ATTR_EMAIL, "")
        groups = request.META.get(settings.SAML_ATTR_GROUPS, "").split(";")

        if not username:
            return None
        try:
            # Check that username follows eduPersonPrincipalName syntax, similar to email.
            validate_email(username)
        except ValidationError:
            return None
        try:
            user = UserModel.objects.get(username=username)
        except UserModel.DoesNotExist:
            if create_user:
                user = self.create_user(username=username, email=email, given_names=given_names, surname=surname)
            else:
                return None
        self.update_groups(user, groups, settings.SAML_GROUP_PREFIXES)
        return user

    @staticmethod
    def update_groups(user: UserType, groups: list, prefixes=None) -> None:
        """
        Set users groups to provided groups

        If list of prefixes is given, only groups with those prefixes are updated.
        """
        login_groups = set(Group.objects.filter(name__in=groups))
        user_groups = set(user.groups.all())
        removed = user_groups - login_groups
        added = login_groups - user_groups
        for group in removed:
            if not prefixes or group.name.startswith(tuple(prefixes)):
                user.groups.remove(group)
        for group in added:
            if not prefixes or group.name.startswith(tuple(prefixes)):
                user.groups.add(group)


class GoogleBackend(LocalBaseBackend):
    """
    Backend for Google authentication.

    Set create_user True to create user if it does not exist.

    Set link_identifier True to link a Google account to the current user identity,
    if same identifier does not already exist in the database for some other user.
    """

    def authenticate(self, request, create_user=False, link_identifier=False, **kwargs) -> UserType | None:
        unique_identifier = request.META.get(settings.OIDC_GOOGLE_SUB, "")
        given_names = request.META.get(settings.OIDC_GOOGLE_GIVEN_NAME, "")
        surname = request.META.get(settings.OIDC_GOOGLE_FAMILY_NAME, "")
        email = request.META.get(settings.OIDC_GOOGLE_EMAIL, None)
        if not unique_identifier:
            return None
        try:
            identity = Identifier.objects.get(type="google", value=unique_identifier).identity
        except Identifier.DoesNotExist:
            if link_identifier:
                # Identifier does not exist, link if user is authenticated
                if isinstance(request.user, UserType) and request.user.is_authenticated:
                    self.link_identifier(request.user, "google", unique_identifier)
                    return request.user
            if create_user and not request.user.is_authenticated:
                # Identifier and user do not exist. Create a new user with a linked identifier.
                username = f"{unique_identifier}@accounts.google.com"
                user = self.create_user(username=username, email=email, given_names=given_names, surname=surname)
                self.link_identifier(user, "google", unique_identifier)
                return user
            return None
        if identity.user:
            return identity.user
        if create_user and not request.user.is_authenticated:
            # Create a new user and link existing identifier to it.
            username = f"{unique_identifier}@accounts.google.com"
            user = self.create_user(username=username, email=email, given_names=given_names, surname=surname)
            identity.user = user
            identity.save()
            return user
        return None


class EmailSMSBackend(LocalBaseBackend):
    """
    Backend to authenticate with email address and phone number.

    Authenticate only if exactly one address and number is found, and they are for the same identity.
    """

    def authenticate(self, request, email=None, phone=None, **kwargs) -> UserType | None:
        if not email or not phone:
            return None
        email_identities = Identity.objects.filter(email_addresses__address=email, email_addresses__verified=True)
        phone_identities = Identity.objects.filter(phone_numbers__number=phone, phone_numbers__verified=True)
        if email_identities.count() == 1 and phone_identities.count() == 1:
            email_identity = email_identities[0]
            phone_identity = phone_identities[0]
            if email_identity.user and email_identity.user == phone_identity.user:
                return email_identity.user
        return None
