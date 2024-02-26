"""
Authentication backends
"""

import logging
import re
from datetime import datetime
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Group
from django.contrib.auth.models import User as UserType
from django.core.exceptions import (
    ImproperlyConfigured,
    MultipleObjectsReturned,
    ObjectDoesNotExist,
    ValidationError,
)
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.http import Http404, HttpRequest
from django.utils.translation import gettext as _

from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.models.role import Role
from kamu.models.token import Token
from kamu.utils.audit import AuditLog
from kamu.utils.auth import set_default_permissions
from kamu.validators.identity import validate_fpic

audit_log = AuditLog()
logger = logging.getLogger(__name__)
UserModel = get_user_model()


class AuthenticationError(Exception):
    """
    Custom Exception for failed Authentication.
    """

    pass


def post_login_tasks(request: HttpRequest) -> None:
    """
    Tasks to do after user has logged in.

    Give user default permissions if user owns at least one role, remove them otherwise.
    """
    if request.user and request.user.is_authenticated:
        if Role.objects.filter(owner=request.user).exists():
            set_default_permissions(request.user)
        else:
            set_default_permissions(request.user, remove=True)


def auth_login(request: HttpRequest, user: AbstractBaseUser | None, backend: type[ModelBackend] | str | None) -> None:
    """
    Custom login function with post login tasks
    """
    login(request, user, backend)
    audit_log.info(
        f"User { request.user } logged in with { backend }",
        category="authentication",
        action="login",
        outcome="success",
        backend=backend,
        request=request,
        objects=[request.user],
    )
    post_login_tasks(request)


class LocalBaseBackend(ModelBackend):
    """
    Local authentication backend base with some custom functions.
    """

    error_messages = {
        "identifier_not_found": _("Identifier not found."),
        "identifier_missing": _("Valid identifier not found. This is probably a configuration error."),
        "identity_already_exists": _("Identifier is already linked to another user."),
        "invalid_identifier_format": _("Invalid identifier format."),
        "generic": _("Could not authenticate. Please try again."),
        "invalid_issuer": _("Identity provider is not authorized."),
        "unexpected": _("Unexpected error."),
        "invalid_parameters": _("Missing required parameters. Please try again with an another browser."),
        "invalid_email_or_phone": _("Invalid email address or phone number."),
        "user_authenticated": _("You are already logged in."),
        "link_user_not_authenticated": _("User must be authenticated to link identifier."),
    }

    def check_enabled(self) -> None:
        """
        Check if authentication backend is enabled in settings.
        """
        backend = f"{self.__class__.__module__}.{self.__class__.__name__}"
        if backend not in settings.AUTHENTICATION_BACKENDS:
            raise Http404

    def _get_identifier_type(self, request: HttpRequest) -> Identifier.Type:
        """
        Get identifier type. Values from the Identifier model choices.
        """
        raise ImproperlyConfigured("LocalBaseBackend should not be used directly")

    @staticmethod
    def _get_username_suffix() -> str:
        """
        Get username suffix.
        """
        return settings.AUTH_DEFAULT_USERNAME_SUFFIX

    @staticmethod
    def _get_assurance_level(request: HttpRequest) -> Identity.AssuranceLevel:
        """
        Get assurance level for the login method. Values from the Identity model choices.
        """
        return Identity.AssuranceLevel[settings.AUTH_DEFAULT_ASSURANCE_LEVEL]

    @staticmethod
    def _get_verification_level(request: HttpRequest) -> Identity.VerificationMethod:
        """
        Get attribute verification level for the login method. Values from the Identity model choices.
        """
        return Identity.VerificationMethod[settings.AUTH_DEFAULT_VERIFICATION_LEVEL]

    def _get_meta_unique_identifier(self, request: HttpRequest) -> str:
        """
        Get unique identifier from request.META.
        """
        unique_identifier = request.META.get("sub", "")
        return unique_identifier

    def _get_meta_user_info(self, request: HttpRequest) -> tuple[str, str, str | None, str | None]:
        """
        Get external login parameters from request.META.
        """
        given_names = request.META.get("given_name", "")
        surname = request.META.get("family_name", "")
        email = request.META.get("email", None)
        preferred_username = request.META.get("preferred_username", None)
        return given_names, surname, email, preferred_username

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
        audit_log.info(
            f"Identity created for { user }",
            category="identity",
            action="create",
            outcome="success",
            request=request,
            objects=[identity, user],
            log_to_db=True,
        )
        if user.email:
            email_address = EmailAddress.objects.create(address=user.email, identity=identity)
            audit_log.info(
                f"Email address added to identity { identity }",
                category="email_address",
                action="create",
                outcome="success",
                request=request,
                objects=[identity, email_address],
                log_to_db=True,
            )
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
        audit_log.info(
            f"Created user { user }",
            category="user",
            action="create",
            outcome="success",
            objects=[user],
        )
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
        created = False
        with transaction.atomic():
            identifier = Identifier.objects.filter(
                type=identifier_type, value=identifier_value, deactivated_at=None
            ).first()
            if not identifier:
                identifier = Identifier.objects.create(
                    type=identifier_type, value=identifier_value, identity=identity, deactivated_at=None
                )
                created = True
        if created:
            audit_log.info(
                f"Linked { identifier.type } identifier to identity { identity }",
                category="identifier",
                action="create",
                outcome="success",
                request=request,
                objects=[identifier, identity],
                log_to_db=True,
            )
        if identifier.identity != identity:
            audit_log.warning(
                "Suspected duplicate user. Identifier already exists for another identity.",
                category="identifier",
                action="create",
                outcome="failure",
                request=request,
                objects=[identifier, identity],
                extra={"sensitive": f"{identifier_type}: {identifier_value}"},
            )
            raise AuthenticationError(self.error_messages["identity_already_exists"])
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

    def _validate_issuer(self, request: HttpRequest) -> bool:
        """
        Validates authentication data issuer.
        """
        return True

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
                audit_log.info(
                    f"Group { group } removed from user { user }",
                    category="group",
                    action="unlink",
                    outcome="success",
                    objects=[group, user],
                )
        for group in added:
            if not prefixes or group.name.startswith(tuple(prefixes)):
                user.groups.add(group)
                audit_log.info(
                    f"Group { group } added to user { user }",
                    category="group",
                    action="link",
                    outcome="success",
                    objects=[group, user],
                )

    def _post_tasks(self, request: HttpRequest, user: UserType) -> None:
        """
        Tasks to run after getting the user.
        """
        pass

    def _identifier_validation(self, request: HttpRequest, identifier: str) -> None:
        """
        Validates identifier.
        """
        if not identifier:
            raise AuthenticationError(self.error_messages["identifier_missing"])

    def _authenticate_login(self, request: HttpRequest, identifier_type: str, unique_identifier: str) -> UserType:
        """
        Log in with existing user.
        """
        try:
            identifier = Identifier.objects.get(type=identifier_type, value=unique_identifier, deactivated_at=None)
        except Identifier.DoesNotExist:
            raise AuthenticationError(self.error_messages["identifier_not_found"])
        if not identifier.identity.user:
            # Identifier exists but is not linked to a user. Should not happen.
            raise AuthenticationError(self.error_messages["unexpected"])
        if not isinstance(request.user, UserType) or not request.user.is_authenticated:
            # Identifier exists and is linked to an unauthenticated user.
            self._post_tasks(request, identifier.identity.user)
            return identifier.identity.user
        if request.user == identifier.identity.user:
            # Identifier exists and is linked to the current user.
            self._post_tasks(request, request.user)
            return request.user
        # Identifier exists for different user.
        audit_log.warning(
            "User tried to login with different user's identifier.",
            category="authentication",
            action="login",
            outcome="failure",
            request=request,
            objects=[identifier],
            extra={"sensitive": f"{identifier.type}: {identifier.value}"},
        )
        raise AuthenticationError(self.error_messages["identity_already_exists"])

    def _authenticate_create_user(
        self, request: HttpRequest, identifier_type: Identifier.Type, unique_identifier: str
    ) -> UserType:
        """
        Creating a new user, or logging in with an existing user.
        - User must be unauthenticated.
        """
        given_names, surname, email, preferred_username = self._get_meta_user_info(request)
        username = self._get_username(preferred_username, unique_identifier)
        if isinstance(request.user, UserType) and request.user.is_authenticated:
            raise AuthenticationError(self.error_messages["user_authenticated"])
        try:
            identity = Identifier.objects.get(
                type=identifier_type, value=unique_identifier, deactivated_at=None
            ).identity
        except Identifier.DoesNotExist:
            # Identifier does not exist. Create user and link identifier.
            user = self._create_user(username=username, email=email, given_names=given_names, surname=surname)
            self._link_identifier(request, user, identifier_type, unique_identifier)
            self._post_tasks(request, user)
            return user
        if identity.user:
            # Identifier exists and is linked to a user. Log in.
            self._post_tasks(request, identity.user)
            return identity.user
        # Identifier exists but is not linked to a user. Should not happen.
        raise AuthenticationError(self.error_messages["unexpected"])

    def _authenticate_link_identifier(
        self, request: HttpRequest, identifier_type: Identifier.Type, unique_identifier: str
    ) -> UserType:
        """
        Link identifier to user
        - User must be authenticated.
        - Identifier must not exist for another user.

        Return current user if trying to link an identifier that already exists for the current user.
        """
        if not isinstance(request.user, UserType) or not request.user.is_authenticated:
            raise AuthenticationError(self.error_messages["link_user_not_authenticated"])
        try:
            identifier = Identifier.objects.get(type=identifier_type, value=unique_identifier, deactivated_at=None)
        except Identifier.DoesNotExist:
            # Identifier does not exist. Link it to the current user.
            self._link_identifier(request, request.user, identifier_type, unique_identifier)
            self._post_tasks(request, request.user)
            return request.user
        if identifier.identity.user == request.user:
            # Identifier exists for the current user. Run post login tasks and continue with the current user.
            self._post_tasks(request, request.user)
            return request.user
        # Identifier exists for different user.
        audit_log.warning(
            "Suspected duplicate user. Identifier already exists for another identity.",
            category="identifier",
            action="link",
            outcome="failure",
            request=request,
            objects=[identifier],
            extra={"sensitive": f"{identifier.type}: {identifier.value}"},
        )
        raise AuthenticationError(self.error_messages["identity_already_exists"])

    def authenticate(
        self,
        request: HttpRequest | None,
        username: str | None = None,
        password: str | None = None,
        create_user: bool = False,
        link_identifier: bool = False,
        **kwargs: Any,
    ) -> UserType:
        """
        Set create_user True to create user if it does not exist.

        Set link_identifier True to link a user account to the current user identity,
        if same identifier does not already exist in the database for some other user.

        username and password fields are not used, but are included because superclass requires them.
        """
        if not request:
            raise AuthenticationError(self.error_messages["unexpected"])
        self.check_enabled()
        if not self._validate_issuer(request):
            raise AuthenticationError(self.error_messages["invalid_issuer"])
        unique_identifier = self._get_meta_unique_identifier(request)
        identifier_type = self._get_identifier_type(request)
        self._identifier_validation(request, unique_identifier)
        if link_identifier:
            user = self._authenticate_link_identifier(request, identifier_type, unique_identifier)
            return user
        if create_user:
            user = self._authenticate_create_user(request, identifier_type, unique_identifier)
            return user
        user = self._authenticate_login(request, identifier_type, unique_identifier)
        return user


class ShibbolethBaseBackend(LocalBaseBackend):
    """
    Backend for Shibboleth authentication.

    If Shibboleth eduPersonPrincipalName attribute is found.
    - Creates a new user if user does not exist.
    - Updates groups with prefixes in SAML_ATTR_GROUPS.
    """

    def _get_identifier_type(self, request: HttpRequest) -> Identifier.Type:
        """
        Get identifier type. Values from the Identifier model choices.
        """
        return Identifier.Type.EPPN

    @staticmethod
    def _get_assurance_level(request: HttpRequest) -> Identity.AssuranceLevel:
        """
        Get assurance level for the login method, using Identity model choices.
        """
        assurance_level = request.META.get(settings.SAML_ATTR_ASSURANCE, "").split(";")
        if "https://refeds.org/assurance/IAP/high" in assurance_level:
            return Identity.AssuranceLevel.HIGH
        elif "https://refeds.org/assurance/IAP/medium" in assurance_level:
            return Identity.AssuranceLevel.MEDIUM
        else:
            return Identity.AssuranceLevel.LOW

    def _get_meta_unique_identifier(self, request: HttpRequest) -> str:
        """
        Get unique identifier from request.META.
        """
        unique_identifier = request.META.get(settings.SAML_ATTR_EPPN, "")
        return unique_identifier

    def _get_meta_user_info(self, request: HttpRequest) -> tuple[str, str, str | None, str | None]:
        """
        Get external login parameters from request.META.
        """
        given_names = request.META.get(settings.SAML_ATTR_GIVEN_NAMES, "")
        surname = request.META.get(settings.SAML_ATTR_SURNAME, "")
        email = request.META.get(settings.SAML_ATTR_EMAIL, None)
        preferred_username = request.META.get(settings.SAML_ATTR_EPPN, None)
        return given_names, surname, email, preferred_username

    def _identifier_validation(self, request: HttpRequest, identifier: str) -> None:
        """
        Custom identifier validation. EPPN must be in email format.
        """
        if not identifier:
            raise AuthenticationError(self.error_messages["identifier_missing"])
        try:
            validate_email(identifier)
        except ValidationError:
            raise AuthenticationError(self.error_messages["invalid_identifier_format"])

    def _set_uid(self, request: HttpRequest, user: UserType, unique_identifier: str) -> None:
        """
        Set identity uid if it is not set and uid is in correct format.
        """
        uid = unique_identifier.removesuffix(settings.LOCAL_EPPN_SUFFIX)
        if uid and len(uid) < 12 and not re.match(settings.LOCAL_UID_IGNORE_REGEX, uid):
            if hasattr(user, "identity"):
                if not user.identity.uid:
                    try:
                        user.identity.uid = uid
                        user.identity.save()
                    except IntegrityError:
                        audit_log.warning(
                            "UID already exists in the database",
                            category="identity",
                            action="update",
                            outcome="failure",
                            request=request,
                            objects=[user.identity],
                            extra={"sensitive": uid},
                        )
                        messages.error(
                            request,
                            _("Suspected duplicate user. Username already exists in the database: ") + uid,
                        )
                elif user.identity.uid != uid:
                    audit_log.warning(
                        "User UID has changed",
                        category="identity",
                        action="update",
                        outcome="failure",
                        request=request,
                        objects=[user.identity],
                        extra={"sensitive": uid},
                    )
                    messages.error(
                        request,
                        _("Suspected duplicate user. Identity already has a different username: ") + uid,
                    )


class ShibbolethLocalBackend(ShibbolethBaseBackend):
    """
    Backend for local Shibboleth authentication.
    """

    def _identifier_validation(self, request: HttpRequest, identifier: str) -> None:
        """
        Validates identifier.
        """
        if not identifier.endswith(settings.LOCAL_EPPN_SUFFIX):
            raise AuthenticationError(self.error_messages["invalid_identifier_format"])

    def _post_tasks(self, request: HttpRequest, user: UserType) -> None:
        """
        Set groups if user is using local authentication.
        """
        groups = request.META.get(settings.SAML_ATTR_GROUPS, "").split(";")
        self.update_groups(user, groups, settings.SAML_GROUP_PREFIXES)
        self._set_uid(request, user, self._get_meta_unique_identifier(request))


class ShibbolethHakaBackend(ShibbolethBaseBackend):
    """
    Backend for Haka Shibboleth authentication.
    """

    pass


class ShibbolethEdugainBackend(ShibbolethBaseBackend):
    """
    Backend for eduGAIN Shibboleth authentication.
    """

    pass


class SuomiFiBackend(LocalBaseBackend):
    """
    Backend for Suomi.fi and eIDAS authentication.
    """

    def _get_type(self, request: HttpRequest) -> str:
        """
        Get login type. Suomi.fi and eIDAS have different attributes.
        """
        suomi_fi_identifier = request.META.get(settings.SAML_SUOMIFI_SSN, "")
        eidas_identifier = request.META.get(settings.SAML_EIDAS_IDENTIFIER, "")
        if suomi_fi_identifier:
            return "suomifi"
        elif eidas_identifier:
            return "eidas"
        raise AuthenticationError(self.error_messages["identifier_missing"])

    def _get_identifier_type(self, request: HttpRequest) -> Identifier.Type:
        """
        Get identifier type. Values from the Identifier model choices.
        """
        identifier_type = self._get_type(request)
        if identifier_type == "suomifi":
            return Identifier.Type.FPIC
        else:
            return Identifier.Type(identifier_type)

    @staticmethod
    def _get_assurance_level(request: HttpRequest) -> Identity.AssuranceLevel:
        """
        Get assurance level for  the login method. Values from the Identity model choices.
        """
        assurance_level = set(request.META.get(settings.SAML_SUOMIFI_ASSURANCE, "").split(";"))
        if set(settings.SUOMIFI_ASSURANCE_HIGH).intersection(assurance_level):
            return Identity.AssuranceLevel.HIGH
        elif set(settings.SUOMIFI_ASSURANCE_MEDIUM).intersection(assurance_level):
            return Identity.AssuranceLevel.MEDIUM
        else:
            return Identity.AssuranceLevel.LOW

    @staticmethod
    def _get_verification_level(request: HttpRequest) -> Identity.VerificationMethod:
        """
        Get attribute verification level for the login method. Values from the Identity model choices.
        """
        return Identity.VerificationMethod.STRONG

    def _get_meta_unique_identifier(self, request: HttpRequest) -> str:
        """
        Get unique identifier from request.META.
        """
        identifier_type = self._get_type(request)
        if identifier_type == "suomifi":
            unique_identifier = request.META.get(settings.SAML_SUOMIFI_SSN, "")
        elif identifier_type == "eidas":
            unique_identifier = request.META.get(settings.SAML_EIDAS_IDENTIFIER, "")
        else:
            raise AuthenticationError(self.error_messages["identifier_missing"])
        return unique_identifier

    def _get_meta_user_info(self, request: HttpRequest) -> tuple[str, str, str | None, str | None]:
        """
        Get user attributes from META. Suomi.fi and eIDAS have different attribute sets.
        """
        identifier_type = self._get_type(request)
        email = None
        username_identifier = uuid4()
        if identifier_type == "suomifi":
            given_names = request.META.get(settings.SAML_SUOMIFI_GIVEN_NAMES, "")
            surname = request.META.get(settings.SAML_SUOMIFI_SURNAME, "")
        elif identifier_type == "eidas":
            given_names = request.META.get(settings.SAML_EIDAS_GIVEN_NAMES, "")
            surname = request.META.get(settings.SAML_EIDAS_SURNAME, "")
        else:
            raise AuthenticationError(self.error_messages["identifier_missing"])
        preferred_username = f"{ username_identifier }@{ identifier_type }"
        return given_names, surname, email, preferred_username

    def _identifier_validation(self, request: HttpRequest, identifier: str) -> None:
        """
        Custom identifier validation.

        Validate fpic for Suomi.fi and regex for eIDAS.
        """
        if not identifier:
            raise AuthenticationError(self.error_messages["identifier_missing"])
        identifier_type = self._get_type(request)
        if identifier_type == "suomifi":
            try:
                validate_fpic(identifier)
            except ValidationError:
                raise AuthenticationError(self.error_messages["invalid_identifier_format"])
        else:
            if not re.match(settings.EIDAS_IDENTIFIER_REGEX, identifier):
                raise AuthenticationError(self.error_messages["invalid_identifier_format"])

    def _parse_date_from_fpic(self, fpic: str) -> datetime | None:
        if fpic[6] == "+":
            date_string = f"{ fpic[:4] }18{ fpic[4:6] }"
        elif fpic[6] in "-YXWVU":
            date_string = f"{ fpic[:4] }19{ fpic[4:6] }"
        else:
            date_string = f"{ fpic[:4] }20{ fpic[4:6] }"
        try:
            return datetime.strptime(date_string, "%d%m%Y")
        except ValueError:
            return None

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
            identity.date_of_birth = self._parse_date_from_fpic(fpic)
            identity.date_of_birth_verification = verification_level
            identity.fpic = fpic
            identity.fpic_verification = verification_level
            try:
                identity.save()
            except IntegrityError:
                audit_log.warning(
                    "FPIC already exists in the database",
                    category="identity",
                    action="update",
                    outcome="failure",
                    request=request,
                    objects=[identity],
                    extra={"sensitive": fpic},
                )
                messages.error(
                    request,
                    _("Suspected duplicate user. Finnish Personal Identity Code already exists in the database: ")
                    + fpic,
                )
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

    def _get_identifier_type(self, request: HttpRequest) -> Identifier.Type:
        """
        Get identifier type. Values from the Identifier model choices.
        """
        return Identifier.Type.GOOGLE

    @staticmethod
    def _get_username_suffix() -> str:
        """
        Custom username suffix.
        """
        return settings.ACCOUNT_SUFFIX_GOOGLE

    def _get_meta_unique_identifier(self, request: HttpRequest) -> str:
        """
        Get unique identifier from request.META.
        """
        unique_identifier = request.META.get(settings.OIDC_CLAIM_SUB, "")
        return unique_identifier

    def _get_meta_user_info(self, request: HttpRequest) -> tuple[str, str, str | None, str | None]:
        """
        Get external login parameters from request.META.
        """
        given_names = request.META.get(settings.OIDC_CLAIM_GIVEN_NAME, "")
        surname = request.META.get(settings.OIDC_CLAIM_FAMILY_NAME, "")
        email = request.META.get(settings.OIDC_CLAIM_EMAIL, None)
        preferred_username = request.META.get(settings.OIDC_CLAIM_EMAIL, None)
        return given_names, surname, email, preferred_username


class MicrosoftBackend(LocalBaseBackend):
    """
    Backend for Microsoft authentication.
    """

    def _get_identifier_type(self, request: HttpRequest) -> Identifier.Type:
        """
        Get identifier type. Values from the Identifier model choices.
        """
        return Identifier.Type.MICROSOFT

    @staticmethod
    def _get_username_suffix() -> str:
        """
        Custom username suffix.
        """
        return settings.ACCOUNT_SUFFIX_MICROSOFT

    def _validate_issuer(self, request: HttpRequest) -> bool:
        """
        Validates authentication data issuer.
        """
        issuer = request.META.get(settings.OIDC_MICROSOFT_ISSUER, "")
        if not issuer.startswith("https://login.microsoftonline.com/"):
            return False
        return True

    def _get_meta_unique_identifier(self, request: HttpRequest) -> str:
        """
        Get unique identifier from request.META.
        """
        unique_identifier = request.META.get(settings.OIDC_MICROSOFT_IDENTIFIER, "")
        return unique_identifier

    def _get_meta_user_info(self, request: HttpRequest) -> tuple[str, str, str | None, str | None]:
        """
        Get external login parameters from request.META.
        """
        given_names = request.META.get(settings.OIDC_MICROSOFT_GIVEN_NAME, "")
        surname = request.META.get(settings.OIDC_MICROSOFT_FAMILY_NAME, "")
        email = request.META.get(settings.OIDC_MICROSOFT_EMAIL, None)
        preferred_username = request.META.get(settings.OIDC_MICROSOFT_PREFERRED_USERNAME, None)
        return given_names, surname, email, preferred_username


class EmailSMSBackend(LocalBaseBackend):
    """
    Backend to authenticate with email address and phone number.

    Authenticate only if exactly one address and number is found, they are for the same identity, and tokens match.

    username and password fields are not used, but are included because superclass requires them.
    """

    def authenticate(
        self,
        request: HttpRequest | None,
        username: str | None = None,
        password: str | None = None,
        create_user: bool = False,
        link_identifier: bool = False,
        email_address: str | None = None,
        email_token: str | None = None,
        phone_number: str | None = None,
        phone_token: str | None = None,
        **kwargs: Any,
    ) -> UserType:
        self.check_enabled()
        if not email_address or not email_token or not phone_number or not phone_token:
            raise AuthenticationError(self.error_messages["invalid_parameters"])
        try:
            email_obj = EmailAddress.objects.get(address=email_address, verified=True)
            phone_obj = PhoneNumber.objects.get(number=phone_number, verified=True)
        except (ObjectDoesNotExist, MultipleObjectsReturned) as e:
            raise AuthenticationError(self.error_messages["invalid_email_or_phone"]) from e
        if email_obj.identity.user and email_obj.identity.user == phone_obj.identity.user:
            if Token.objects.validate_email_object_verification_token(
                email_token, email_obj
            ) and Token.objects.validate_phone_object_verification_token(phone_token, phone_obj):
                return email_obj.identity.user
        raise AuthenticationError(self.error_messages["invalid_email_or_phone"])
