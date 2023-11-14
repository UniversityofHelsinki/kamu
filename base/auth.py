"""
Authentication backends
"""
import logging
import re

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import Group
from django.contrib.auth.models import User as UserType
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from identity.models import Identity

UserModel = get_user_model()
logger = logging.getLogger(__name__)


class ShibbolethBackend(BaseBackend):
    """
    Backend for Shibboleth authentication.

    If Shibboleth eduPersonPrincipalName attribute is found.
    - Creates a new user if user does not exist.
    - Updates groups with prefixes in SAML_ATTR_GROUPS.
    """

    def authenticate(self, request, create_user=False, **kwargs) -> UserType | None:
        username = request.META.get(settings.SAML_ATTR_USERNAME, "")
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
            if not create_user:
                return None
            user = UserModel.objects.create_user(
                username,
                email=email,
                password=None,
                first_name=given_names,
                last_name=surname,
            )
        self.update_groups(user, groups, settings.SAML_GROUP_PREFIXES)
        return user

    def get_user(self, user_id):
        try:
            user = UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
        return user if user.is_active else None

    @staticmethod
    def update_groups(user, groups, prefixes=None) -> None:
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


class EmailSMSBackend(BaseBackend):
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

    def get_user(self, user_id):
        try:
            user = UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
        return user if user.is_active else None
