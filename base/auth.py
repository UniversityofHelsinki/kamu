"""
Authentication backends
"""
import logging
import re
from datetime import datetime
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.contrib.auth.backends import BaseBackend, ModelBackend
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Group
from django.contrib.auth.models import User as UserType
from django.core.exceptions import (
    MultipleObjectsReturned,
    ObjectDoesNotExist,
    ValidationError,
)
from django.core.validators import validate_email
from django.http import HttpRequest

from base.models import Token
from identity.models import EmailAddress, Identifier, Identity, PhoneNumber
from identity.validators import validate_fpic
from role.models import Role

UserModel = get_user_model()
logger = logging.getLogger(__name__)


def post_login_tasks(request: HttpRequest) -> None:
    """
    Checks user information and sets certain session parameters.
    """
    if not request.user.is_authenticated:
        return
    request.session["is_owner"] = (
        True if request.user.is_superuser or Role.objects.filter(owner=request.user).exists() else False
    )
    request.session["has_groups"] = True if request.user.is_superuser or request.user.groups.all().exists() else False


def auth_login(request: HttpRequest, user: AbstractBaseUser | None, backend: type[ModelBackend] | str | None) -> None:
    """
    Custom login function with post login tasks
    """
    login(request, user, backend)
    post_login_tasks(request)


class LocalBaseBackend(BaseBackend):
    """
    Local authentication backend base with some custom functions.
    """

    def _get_identifier_type(self, request: HttpRequest) -> str:
        """
        Get identifier type. Values from the Identifier model choices.
        """
        return ""

    @staticmethod
    def _get_username_suffix() -> str:
        """
        Get username suffix.
        """
        return settings.AUTH_DEFAULT_USERNAME_SUFFIX

    @staticmethod
    def _get_assurance_level(request: HttpRequest) -> str:
        """
        Get assurance level for the login method. Values from the Identity model choices.
        """
        return settings.AUTH_DEFAULT_ASSURANCE_LEVEL

    @staticmethod
    def _get_verification_level(request: HttpRequest) -> int:
        """
        Get attribute verification level for the login method. Values from the Identity model choices.
        """
        return settings.AUTH_DEFAULT_VERIFICATION_LEVEL

    def _get_request_data(self, request: HttpRequest) -> tuple[str, str, str, str | None, str | None]:
        """
        Get external login parameters from request.META.
        """
        unique_identifier = request.META.get("sub", "")
        given_names = request.META.get("given_name", "")
        surname = request.META.get("family_name", "")
        email = request.META.get("email", None)
        preferred_username = request.META.get("preferred_username", None)
        return unique_identifier, given_names, surname, email, preferred_username

    def get_user(self, user_id: int) -> UserType | None:
        """
        Return user object if it exists and is active.
        """
        try:
            user = UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
        return user if user.is_active else None

    def _create_identity(self, request: HttpRequest, user: UserType) -> Identity:
        """
        Create a new identity for user.
        """
        verification_level = self._get_verification_level(request)
        assurance_level = self._get_assurance_level(request)
        identity = Identity.objects.create(
            user=user,
            assurance_level=assurance_level,
            given_names=user.first_name,
            given_names_verification=verification_level,
            surname=user.last_name,
            surname_verification=verification_level,
        )
        if user.email:
            EmailAddress.objects.create(address=user.email, identity=identity)
        return identity

    @staticmethod
    def _create_user(username: str, email: str | None, given_names: str, surname: str) -> UserType:
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

    def _link_identifier(
        self, request: HttpRequest, user: UserType, identifier_type: str, identifier_value: str
    ) -> None:
        """
        Link identifier to the current user identity. Create identity if the user is authenticated and
        doesn't have an identity.
        """
        if hasattr(user, "identity"):
            identity = user.identity
        else:
            identity = self._create_identity(request, user)
        Identifier.objects.get_or_create(
            type=identifier_type, value=identifier_value, identity=identity, deactivated_at=None
        )
        return None

    def _get_username(self, preferred_username: str | None, unique_identifier: str) -> str:
        """
        Get username from preferred_username if it is available and not already in use.

        Otherwise, use unique_identifier with a suffix.
        """
        suffix = self._get_username_suffix()
        if preferred_username and not UserModel.objects.filter(username=preferred_username).exists():
            username = preferred_username
        else:
            username = f"{unique_identifier}{suffix}"
        return username

    @staticmethod
    def update_groups(user: UserType, groups: list, prefixes: list[str] | None = None) -> None:
        """
        Set users groups to provided groups.
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

    def _post_tasks(self, request: HttpRequest, user: UserType) -> None:
        """
        Tasks to run after getting the user.
        """
        pass

    def _identifier_validation(self, request: HttpRequest, identifier: str) -> bool:
        """
        Validates identifier.
        """
        if not identifier:
            return False
        return True

    def authenticate(
        self, request: HttpRequest | None, create_user: bool = False, link_identifier: bool = False, **kwargs: Any
    ) -> UserType | None:
        """
        Set create_user True to create user if it does not exist.

        Set link_identifier True to link a user account to the current user identity,
        if same identifier does not already exist in the database for some other user.
        """
        if not request:
            return None
        unique_identifier, given_names, surname, email, preferred_username = self._get_request_data(request)
        identifier_type = self._get_identifier_type(request)
        if not self._identifier_validation(request, unique_identifier):
            return None
        try:
            identity = Identifier.objects.get(
                type=identifier_type, value=unique_identifier, deactivated_at=None
            ).identity
        except Identifier.DoesNotExist:
            if link_identifier:
                # Identifier does not exist, link if user is authenticated.
                if isinstance(request.user, UserType) and request.user.is_authenticated:
                    self._link_identifier(request, request.user, identifier_type, unique_identifier)
                    self._post_tasks(request, request.user)
                    return request.user
            if create_user and not request.user.is_authenticated:
                # Identifier and user do not exist. Create a new user with a linked identifier.
                username = self._get_username(preferred_username, unique_identifier)
                user = self._create_user(username=username, email=email, given_names=given_names, surname=surname)
                self._link_identifier(request, user, identifier_type, unique_identifier)
                self._post_tasks(request, user)
                return user
            return None
        if identity.user:
            # Identifier exists and is linked to a user.
            self._post_tasks(request, identity.user)
            return identity.user
        elif create_user and not request.user.is_authenticated:
            # Create a new user and link existing identifier to it.
            username = self._get_username(preferred_username, unique_identifier)
            user = self._create_user(username=username, email=email, given_names=given_names, surname=surname)
            identity.user = user
            identity.save()
            self._post_tasks(request, user)
            return user
        return None


class ShibbolethBackend(LocalBaseBackend):
    """
    Backend for Shibboleth authentication.

    If Shibboleth eduPersonPrincipalName attribute is found.
    - Creates a new user if user does not exist.
    - Updates groups with prefixes in SAML_ATTR_GROUPS.
    """

    def _get_identifier_type(self, request: HttpRequest) -> str:
        """
        Get identifier type. Values from the Identifier model choices.
        """
        return "eppn"

    @staticmethod
    def _get_assurance_level(request: HttpRequest) -> str:
        """
        Get assurance level for the login method, using Identity model choices.
        """
        assurance_level = request.META.get(settings.SAML_ATTR_ASSURANCE, "").split(";")
        if "https://refeds.org/assurance/IAP/high" in assurance_level:
            return "high"
        elif "https://refeds.org/assurance/IAP/medium" in assurance_level:
            return "medium"
        else:
            return "low"

    def _get_request_data(self, request: HttpRequest) -> tuple[str, str, str, str | None, str | None]:
        """
        Get META parameters for generic SAML authentication.
        """
        unique_identifier = request.META.get(settings.SAML_ATTR_EPPN, "")
        given_names = request.META.get(settings.SAML_ATTR_GIVEN_NAMES, "")
        surname = request.META.get(settings.SAML_ATTR_SURNAME, "")
        email = request.META.get(settings.SAML_ATTR_EMAIL, None)
        preferred_username = request.META.get(settings.SAML_ATTR_EPPN, None)
        return unique_identifier, given_names, surname, email, preferred_username

    def _identifier_validation(self, request: HttpRequest, identifier: str) -> bool:
        """
        Custom identifier validation. EPPN must be in email format.
        """
        if not identifier:
            return False
        try:
            validate_email(identifier)
        except ValidationError:
            return False
        return True

    @staticmethod
    def _set_uid(user: UserType, unique_identifier: str) -> None:
        """
        Set identity uid if it is not set and uid is in correct format.
        """
        uid = unique_identifier.removesuffix(settings.LOCAL_EPPN_SUFFIX)
        if uid and len(uid) < 12 and not re.match(settings.LOCAL_UID_IGNORE_REGEX, uid):
            if hasattr(user, "identity"):
                if not user.identity.uid:
                    user.identity.uid = uid
                    user.identity.save()

    def _post_tasks(self, request: HttpRequest, user: UserType) -> None:
        """
        Set groups if user is using local authentication.
        """
        unique_identifier = request.META.get(settings.SAML_ATTR_EPPN, "")
        if unique_identifier.endswith(settings.LOCAL_EPPN_SUFFIX):
            groups = request.META.get(settings.SAML_ATTR_GROUPS, "").split(";")
            self.update_groups(user, groups, settings.SAML_GROUP_PREFIXES)
            self._set_uid(user, unique_identifier)


class SuomiFiBackend(LocalBaseBackend):
    """
    Backend for Suomi.fi and eIDAS authentication.
    """

    @staticmethod
    def _get_type(request: HttpRequest) -> str:
        """
        Get login type. Suomi.fi and eIDAS have different attributes.
        """
        suomi_fi_identifier = request.META.get(settings.SAML_SUOMIFI_SSN, "")
        eidas_identifier = request.META.get(settings.SAML_EIDAS_IDENTIFIER, "")
        if suomi_fi_identifier:
            return "suomifi"
        elif eidas_identifier:
            return "eidas"
        return ""

    def _get_identifier_type(self, request: HttpRequest) -> str:
        """
        Get identifier type. Values from the Identifier model choices.
        """
        identifier_type = self._get_type(request)
        if identifier_type == "suomifi":
            return "hetu"
        elif identifier_type == "eidas":
            return "eidas"
        return ""

    @staticmethod
    def _get_assurance_level(request: HttpRequest) -> str:
        """
        Get assurance level for  the login method. Values from the Identity model choices.
        """
        assurance_level = set(request.META.get(settings.SAML_SUOMIFI_ASSURANCE, "").split(";"))
        if set(settings.SUOMIFI_ASSURANCE_HIGH).intersection(assurance_level):
            return "high"
        elif set(settings.SUOMIFI_ASSURANCE_MEDIUM).intersection(assurance_level):
            return "medium"
        else:
            return "low"

    @staticmethod
    def _get_verification_level(request: HttpRequest) -> int:
        """
        Get attribute verification level for the login method. Values from the Identity model choices.
        """
        return 4

    def _get_request_data(self, request: HttpRequest) -> tuple[str, str, str, str | None, str | None]:
        """
        Get user attributes from META. Suomi.fi and eIDAS have different attribute sets.
        """
        identifier_type = self._get_type(request)
        email = None
        if identifier_type == "suomifi":
            unique_identifier = request.META.get(settings.SAML_SUOMIFI_SSN, "")
            given_names = request.META.get(settings.SAML_SUOMIFI_GIVEN_NAMES, "")
            surname = request.META.get(settings.SAML_SUOMIFI_SURNAME, "")
        elif identifier_type == "eidas":
            unique_identifier = request.META.get(settings.SAML_EIDAS_IDENTIFIER, "")
            given_names = request.META.get(settings.SAML_EIDAS_GIVEN_NAMES, "")
            surname = request.META.get(settings.SAML_EIDAS_SURNAME, "")
        else:
            unique_identifier = ""
            given_names = ""
            surname = ""
        preferred_username = f"{ unique_identifier }@{ identifier_type }"
        return unique_identifier, given_names, surname, email, preferred_username

    def _get_username(self, preferred_username: str | None, unique_identifier: str) -> str:
        """
        Create username with UUID and prefix.

        Preferred username is only used for suffix, when creating a new user with Suomi.fi or eIDAS.
        """
        identifier = uuid4()
        suffix = preferred_username.split("@")[-1] if preferred_username else ""
        return f"{identifier}@{suffix}"

    def _identifier_validation(self, request: HttpRequest, identifier: str) -> bool:
        """
        Custom identifier validation.

        Validate fpic for Suomi.fi and regex for eIDAS.
        """
        if not identifier:
            return False
        identifier_type = self._get_type(request)
        if identifier_type == "suomifi":
            try:
                validate_fpic(identifier)
            except ValidationError:
                return False
        elif identifier_type == "eidas":
            if not re.match(settings.EIDAS_IDENTIFIER_REGEX, identifier):
                return False
        else:
            return False
        return True

    def _post_tasks(self, request: HttpRequest, user: UserType) -> None:
        """
        Set fpic and date of birth if available.
        """
        identity = user.identity if hasattr(user, "identity") else None
        if not identity:
            return None
        verification_level = self._get_verification_level(request)
        identifier_type = self._get_type(request)
        if identifier_type == "suomifi":
            fpic = request.META.get(settings.SAML_SUOMIFI_SSN, "")
            try:
                validate_fpic(fpic)
            except ValidationError:
                return None
            if fpic[6] == "+":
                date_string = f"{ fpic[:4] }18{ fpic[4:6] }"
            elif fpic[6] in "-YXWVU":
                date_string = f"{ fpic[:4] }19{ fpic[4:6] }"
            else:
                date_string = f"{ fpic[:4] }20{ fpic[4:6] }"
            identity.date_of_birth = datetime.strptime(date_string, "%d%m%Y")
            identity.date_of_birth_verification = verification_level
            identity.fpic = fpic
            identity.fpic_verification = verification_level
            identity.save()
        elif identifier_type == "eidas":
            date_string = request.META.get(settings.SAML_EIDAS_DATEOFBIRTH, None)
            if date_string:
                try:
                    identity.date_of_birth = datetime.strptime(date_string, "%Y-%m-%d")
                    identity.date_of_birth_verification = verification_level
                    identity.save()
                except ValueError:
                    pass
        return None


class GoogleBackend(LocalBaseBackend):
    """
    Backend for Google authentication.

    Set create_user True to create user if it does not exist.

    Set link_identifier True to link a Google account to the current user identity,
    if same identifier does not already exist in the database for some other user.
    """

    def _get_identifier_type(self, request: HttpRequest) -> str:
        """
        Get identifier type. Values from the Identifier model choices.
        """
        return "google"

    @staticmethod
    def _get_username_suffix() -> str:
        """
        Custom username suffix.
        """
        return settings.ACCOUNT_SUFFIX_GOOGLE

    def _get_request_data(self, request: HttpRequest) -> tuple[str, str, str, str | None, str | None]:
        """
        Get META parameters for Google authentication.
        """
        unique_identifier = request.META.get(settings.OIDC_CLAIM_SUB, "")
        given_names = request.META.get(settings.OIDC_CLAIM_GIVEN_NAME, "")
        surname = request.META.get(settings.OIDC_CLAIM_FAMILY_NAME, "")
        email = request.META.get(settings.OIDC_CLAIM_EMAIL, None)
        preferred_username = request.META.get(settings.OIDC_CLAIM_EMAIL, None)
        return unique_identifier, given_names, surname, email, preferred_username


class MicrosoftBackend(LocalBaseBackend):
    """
    Backend for Microsoft authentication.
    """

    def _get_identifier_type(self, request: HttpRequest) -> str:
        """
        Get identifier type. Values from the Identifier model choices.
        """
        return "microsoft"

    @staticmethod
    def _get_username_suffix() -> str:
        """
        Custom username suffix.
        """
        return settings.ACCOUNT_SUFFIX_MICROSOFT

    def _get_request_data(self, request: HttpRequest) -> tuple[str, str, str, str | None, str | None]:
        """
        Get META parameters for Microsoft authentication.
        """
        issuer = request.META.get(settings.OIDC_MICROSOFT_ISSUER, "")
        if not issuer.startswith("https://login.microsoftonline.com/"):
            return "", "", "", None, None
        unique_identifier = request.META.get(settings.OIDC_MICROSOFT_IDENTIFIER, "")
        given_names = request.META.get(settings.OIDC_MICROSOFT_GIVEN_NAME, "")
        surname = request.META.get(settings.OIDC_MICROSOFT_FAMILY_NAME, "")
        email = request.META.get(settings.OIDC_MICROSOFT_EMAIL, None)
        preferred_username = request.META.get(settings.OIDC_MICROSOFT_PREFERRED_USERNAME, None)
        return unique_identifier, given_names, surname, email, preferred_username


class EmailSMSBackend(LocalBaseBackend):
    """
    Backend to authenticate with email address and phone number.

    Authenticate only if exactly one address and number is found, they are for the same identity, and tokens match.
    """

    def authenticate(
        self,
        request: HttpRequest | None,
        create_user: bool = False,
        link_identifier: bool = False,
        email_address: str | None = None,
        email_token: str | None = None,
        phone_number: str | None = None,
        phone_token: str | None = None,
        **kwargs: Any,
    ) -> UserType | None:
        if not email_address or not email_token or not phone_number or not phone_token:
            return None
        try:
            email_obj = EmailAddress.objects.get(address=email_address, verified=True)
            phone_obj = PhoneNumber.objects.get(number=phone_number, verified=True)
        except (ObjectDoesNotExist, MultipleObjectsReturned):
            return None
        if email_obj.identity.user and email_obj.identity.user == phone_obj.identity.user:
            if Token.objects.validate_email_object_verification_token(
                email_token, email_obj
            ) and Token.objects.validate_phone_object_verification_token(phone_token, phone_obj):
                return email_obj.identity.user
        return None
