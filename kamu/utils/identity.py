"""
Helper functions for the identity
"""

from datetime import date, datetime
from typing import TYPE_CHECKING, Any, Callable

import pycountry
from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.validators import URLValidator
from django.db import IntegrityError, transaction
from django.http import HttpRequest
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _

from kamu.connectors import ApiError
from kamu.connectors.email import send_verification_email
from kamu.connectors.ldap import LDAP_SIZELIMIT_EXCEEDED, ldap_search
from kamu.connectors.sms import SmsConnector
from kamu.models.contract import Contract
from kamu.models.identity import (
    Country,
    EmailAddress,
    Identifier,
    Identity,
    Nationality,
    PhoneNumber,
)
from kamu.models.membership import Membership
from kamu.models.token import TimeLimitError, Token
from kamu.utils.audit import AuditLog
from kamu.validators.identity import validate_fpic

if TYPE_CHECKING:
    from kamu.utils.audit import CategoryTypes

audit_log = AuditLog()


def combine_identities_requirements(
    request: HttpRequest, primary_identity: Identity, secondary_identity: Identity
) -> bool:
    """
    Check if identities can be combined.

    Check that identities are not the same and that primary identity has no contracts.
    """
    if primary_identity == secondary_identity:
        messages.add_message(request, messages.ERROR, _("Cannot combine identity with itself."))
        return False
    error = False
    if secondary_identity.assurance_level > primary_identity.assurance_level:
        messages.add_message(
            request,
            messages.ERROR,
            _("Source identity cannot have higher assurance level than target."),
        )
        error = True
    if primary_identity.uid and secondary_identity.uid:
        messages.add_message(
            request,
            messages.ERROR,
            _("Cannot combine two identities with uid. Please remove uid from the source first."),
        )
        error = True
    if primary_identity.fpic and secondary_identity.fpic:
        messages.add_message(
            request,
            messages.ERROR,
            _(
                "Cannot combine two identities with Finnish personal identity code. Please remove FPIC from the "
                "source first."
            ),
        )
        error = True
    if not primary_identity.user and secondary_identity.user:
        messages.add_message(
            request,
            messages.ERROR,
            _("Source identity is linked to user and target identity is not."),
        )
        error = True
    if (
        hasattr(request.user, "identity")
        and request.user.is_authenticated
        and request.user.identity == secondary_identity
    ):
        messages.add_message(
            request,
            messages.ERROR,
            _("Current user's identity cannot be the source identity."),
        )
        error = True
    return not error


def _combine_identity_attributes(
    request: HttpRequest, primary_identity: Identity, secondary_identity: Identity
) -> None:
    """
    Combine two identities.

    Move all attributes from secondary identity to primary identity.
    """
    combined_attributes = ["given_names", "surname", "uid", "fpic", "date_of_birth"]
    unique_attributes = ["uid", "fpic"]

    def _combine_identity_attribute(attribute: str, has_val: Callable[[str], bool] = bool) -> None:
        """
        Combine an attribute from two identities.

        Copy attribute from secondary identity to primary identity, if primary identity does not have it.
        """
        if not has_val(getattr(primary_identity, attribute)) and has_val(getattr(secondary_identity, attribute)):
            setattr(primary_identity, attribute, getattr(secondary_identity, attribute))
            if attribute in unique_attributes:
                setattr(secondary_identity, attribute, None)
                secondary_identity.save()
            primary_identity.save()
            audit_log.info(
                f"Identity transfer: {attribute} from identity: {secondary_identity.pk}",
                category="identity",
                action="update",
                outcome="success",
                request=request,
                objects=[primary_identity],
                log_to_db=True,
                extra={"secondary_identity": secondary_identity.pk},
            )

    for attr in combined_attributes:
        _combine_identity_attribute(attr)
    _combine_identity_attribute("gender", lambda val: val != Identity.Gender.UNKNOWN)


def _move_objects_to_primary_identity(
    request: HttpRequest,
    cls: type[EmailAddress | PhoneNumber | Contract | Identifier | Membership],
    primary_identity: Identity,
    secondary_identity: Identity,
    log_category: "CategoryTypes",
    allow_integrity_error: bool = True,
) -> None:
    """change the linked identity for all objects of the specified type"""

    for obj in cls.objects.filter(identity=secondary_identity):
        try:
            obj.identity = primary_identity
            obj.save()
            audit_log.info(
                f"Identity transfer: {log_category} from identity: {secondary_identity.pk}",
                category=log_category,
                action="update",
                outcome="success",
                request=request,
                objects=[obj, primary_identity],
                log_to_db=True,
                extra={"secondary_identity": secondary_identity.pk},
            )
        except IntegrityError:
            if not allow_integrity_error:
                raise


def combine_identities(request: HttpRequest, primary_identity: Identity, secondary_identity: Identity) -> None:
    """
    Combine two identities.

    Move all contracts, identifiers and memberships from secondary identity to primary identity.
    """
    _combine_identity_attributes(request, primary_identity, secondary_identity)
    # Move email addresses, skip duplicates (IntegrityError)
    _move_objects_to_primary_identity(
        request=request,
        cls=EmailAddress,
        primary_identity=primary_identity,
        secondary_identity=secondary_identity,
        log_category="email_address",
        allow_integrity_error=True,
    )
    # Move phone numbers, skip duplicates (IntegrityError)
    _move_objects_to_primary_identity(
        request=request,
        cls=PhoneNumber,
        primary_identity=primary_identity,
        secondary_identity=secondary_identity,
        log_category="phone_number",
        allow_integrity_error=True,
    )
    # Move contracts, if contract does not yet exist. (IntegrityError)
    _move_objects_to_primary_identity(
        request=request,
        cls=Contract,
        primary_identity=primary_identity,
        secondary_identity=secondary_identity,
        log_category="contract",
        allow_integrity_error=True,
    )
    # Move identifiers
    _move_objects_to_primary_identity(
        request=request,
        cls=Identifier,
        primary_identity=primary_identity,
        secondary_identity=secondary_identity,
        log_category="identifier",
        allow_integrity_error=False,
    )
    # Move memberships
    _move_objects_to_primary_identity(
        request=request,
        cls=Membership,
        primary_identity=primary_identity,
        secondary_identity=secondary_identity,
        log_category="membership",
        allow_integrity_error=False,
    )
    # Copy kamu_id as identifier to primary identity
    Identifier.objects.create(
        identity=primary_identity,
        type=Identifier.Type.KAMU,
        value=str(secondary_identity.kamu_id),
        created_at=secondary_identity.created_at,
        deactivated_at=timezone.now(),
    )
    # Delete secondary user and identity
    if secondary_identity.user:
        audit_log.info(
            "User removed",
            category="user",
            action="delete",
            request=request,
            objects=[secondary_identity.user],
            log_to_db=True,
        )
        secondary_identity.user.delete()
    audit_log.info(
        "Identity removed",
        category="identity",
        action="delete",
        request=request,
        objects=[secondary_identity],
        log_to_db=True,
    )
    secondary_identity.delete()


def _parse_fpic(user: dict) -> str | None:
    """
    Parse fpic from user.
    """
    if "schacPersonalUniqueID" in user:
        fpic = user["schacPersonalUniqueID"].rsplit(":", 1)[1]
        try:
            validate_fpic(fpic)
            return fpic
        except ValidationError:
            return None
    return None


def _check_existing_identity(user: dict) -> Identity | None:
    """
    Check if identity already exists.
    - uid or fpic
    - Identifier with type eppn or fpic
    """
    try:
        return Identity.objects.get(uid=user["uid"])
    except Identity.DoesNotExist:
        pass
    try:
        return Identifier.objects.get(
            type=Identifier.Type.EPPN,
            value=f"{user['uid']}{settings.LOCAL_EPPN_SUFFIX}",
            deactivated_at=None,
        ).identity
    except Identifier.DoesNotExist:
        pass
    fpic = _parse_fpic(user)
    if fpic:
        try:
            return Identity.objects.get(fpic=fpic)
        except Identity.DoesNotExist:
            pass
        try:
            return Identifier.objects.get(
                type=Identifier.Type.FPIC,
                value=fpic,
                deactivated_at=None,
            ).identity
        except Identifier.DoesNotExist:
            pass
    return None


def get_user_from_ldap(uid: str) -> dict | None:
    """
    Get user from LDAP by uid.
    """
    try:
        ldap_user = ldap_search(
            search_filter="(uid={})",
            search_values=[uid],
            ldap_attributes=[
                "uid",
                "givenName",
                "sn",
                "mail",
                "schacDateOfBirth",
                "preferredLanguage",
                "schacPersonalUniqueID",
            ],
        )
    except LDAP_SIZELIMIT_EXCEEDED:
        return None
    if not ldap_user or len(ldap_user) != 1:
        return None
    return ldap_user[0]


def create_identity_from_ldap(uid: str, request: HttpRequest | None = None) -> Identity | None:
    """
    Checks if identity already exists and if not, tries to create identity from LDAP attributes.

    Use get_or_create to create eppn and fpic identifiers, to avoid duplicates.
    """
    user = get_user_from_ldap(uid)
    if not user:
        return None
    identity = _check_existing_identity(user)
    if identity:
        return identity
    identity = Identity.objects.create(
        uid=user["uid"],
        given_names=user["givenName"],
        given_names_verification=Identity.VerificationMethod.EXTERNAL,
        surname=user["sn"],
        surname_verification=Identity.VerificationMethod.EXTERNAL,
    )
    audit_log.info(
        "Identity created.",
        category="identity",
        action="create",
        outcome="success",
        request=request,
        objects=[identity],
        log_to_db=True,
    )
    if "mail" in user:
        email_object = EmailAddress.objects.create(address=user["mail"], identity=identity)
        audit_log.info(
            f"Email address added to identity {identity}",
            category="email_address",
            action="create",
            outcome="success",
            request=request,
            objects=[email_object, identity],
            log_to_db=True,
        )
    if "schacDateOfBirth" in user:
        identity.date_of_birth = datetime.strptime(user["schacDateOfBirth"], "%Y%m%d").date()
        identity.date_of_birth_verification = Identity.VerificationMethod.EXTERNAL
    if "preferredLanguage" in user and user["preferredLanguage"] in [k for k, v in settings.LANGUAGES]:
        identity.preferred_language = user["preferredLanguage"]
    fpic = _parse_fpic(user)
    if fpic:
        identity.fpic = fpic
        identity.fpic_verification = Identity.VerificationMethod.EXTERNAL
    identity.save()
    identifier, created = Identifier.objects.get_or_create(
        type=Identifier.Type.EPPN,
        value=f"{user['uid']}{settings.LOCAL_EPPN_SUFFIX}",
        identity=identity,
        deactivated_at=None,
    )
    if created:
        audit_log.info(
            f"Linked {identifier.type} identifier to identity {identity}",
            category="identifier",
            action="create",
            outcome="success",
            request=request,
            objects=[identifier, identity],
            log_to_db=True,
        )
    if fpic:
        Identifier.objects.get_or_create(type=Identifier.Type.FPIC, value=fpic, identity=identity, deactivated_at=None)
    return identity


def import_identity(uid: str | None = None, request: HttpRequest | None = None) -> Identity | None:
    """
    Imports and creates identity from external source, if possible.

    Currently importing from LDAP with uid is supported.
    """
    if uid:
        return create_identity_from_ldap(uid, request)
    return None


def create_email_verification_token(request: HttpRequest, email_address: str) -> bool:
    """
    Create and send a verification token.
    """
    try:
        token = Token.objects.create_email_address_verification_token(email_address)
    except TimeLimitError:
        messages.add_message(
            request,
            messages.WARNING,
            _(
                "You tried to send a new code too soon. Please wait one minute before trying again. Please also check "
                "your spam folder."
            ),
        )
        return False
    if send_verification_email(token, email_address=email_address, lang=get_language()):
        messages.add_message(
            request,
            messages.INFO,
            _(
                "The verification code has now been sent and should arrive in your email in a few minutes. If you do "
                "not receive a verification code, please check your spam folder."
            ),
        )
        return True
    else:
        messages.add_message(request, messages.ERROR, _("Failed to send verification code."))
        return False


def create_phone_verification_token(request: HttpRequest, phone_number: str) -> bool:
    """
    Create and send a verification token.
    """
    try:
        token = Token.objects.create_phone_number_verification_token(phone_number)
    except TimeLimitError:
        messages.add_message(
            request, messages.WARNING, _("Tried to send a new code too soon. Please try again in one minute.")
        )
        return False
    try:
        sms_connector = SmsConnector()
        sms_connector.send_sms(
            phone_number, _("Your personal Kamu verification code is: %(token)s") % {"token": token}
        )
    except ApiError:
        messages.add_message(request, messages.ERROR, _("Could not send an SMS message."))
        return False
    messages.add_message(
        request,
        messages.INFO,
        _("The verification code has now been sent and should arrive in your phone in a few minutes."),
    )
    return True


def create_or_verify_email_address(
    request: HttpRequest, identity: Identity, email_address: str = "", email_object: EmailAddress | None = None
) -> EmailAddress | None:
    """
    Set email object verified or create verified email object.
    """
    if email_object and email_object.verified:
        return email_object
    with transaction.atomic():
        if email_object:
            email_object.verified = timezone.now()
            email_object.save()
            audit_log.info(
                "Verified email address",
                category="email_address",
                action="update",
                outcome="success",
                request=request,
                objects=[email_object, email_object.identity],
                log_to_db=True,
            )
        elif email_address:
            email_object = EmailAddress.objects.create(
                address=email_address, identity=identity, verified=timezone.now()
            )
            audit_log.info(
                f"Verified email address added to identity {identity}",
                category="email_address",
                action="create",
                outcome="success",
                request=request,
                objects=[email_object, identity],
                log_to_db=True,
            )
        else:
            raise ValidationError(_("Email address is required."))
        for email_obj in EmailAddress.objects.filter(address=email_object.address, verified__isnull=False).exclude(
            pk=email_object.pk
        ):
            email_obj.verified = None
            email_obj.save()
            audit_log.warning(
                "Removed verification from the email address as the address was verified elsewhere",
                category="email_address",
                action="update",
                outcome="success",
                request=request,
                objects=[email_obj, email_obj.identity],
                log_to_db=True,
            )
        return email_object


def create_or_verify_phone_number(
    request: HttpRequest, identity: Identity, phone_number: str = "", phone_object: PhoneNumber | None = None
) -> PhoneNumber | None:
    """
    Set phone object verified or create verified phone number.
    """
    if phone_object and phone_object.verified:
        return phone_object
    with transaction.atomic():
        if phone_object:
            phone_object.verified = timezone.now()
            phone_object.save()
            audit_log.info(
                "Verified phone number",
                category="phone_number",
                action="update",
                outcome="success",
                request=request,
                objects=[phone_object, phone_object.identity],
                log_to_db=True,
            )
        elif phone_number:
            phone_object = PhoneNumber.objects.create(number=phone_number, identity=identity, verified=timezone.now())
            audit_log.info(
                f"Verified phone number added to identity {identity}",
                category="phone_number",
                action="create",
                outcome="success",
                request=request,
                objects=[phone_object, identity],
                log_to_db=True,
            )
        else:
            raise ValidationError(_("Phone number is required."))
        for phone_obj in PhoneNumber.objects.filter(number=phone_object.number, verified__isnull=False).exclude(
            pk=phone_object.pk
        ):
            phone_obj.verified = None
            phone_obj.save()
            audit_log.warning(
                "Removed verification from the phone number as the number was verified elsewhere",
                category="phone_number",
                action="update",
                outcome="success",
                request=request,
                objects=[phone_obj, phone_obj.identity],
                log_to_db=True,
            )
        return phone_object


def add_nationality(
    request: HttpRequest, identity: Identity, code: str, verification_method: Identity.VerificationMethod
) -> bool:
    """
    Add nationality to identity if not already present or update verification method if higher.
    code: ISO 2-letter or 3-letter country code.
    """
    country_code = ""
    if len(code) == 3:
        country = pycountry.countries.get(alpha_3=code)
        if country:
            country_code = country.alpha_2
    elif len(code) == 2:
        country_code = code.upper()
    try:
        country_obj = Country.objects.get(code=country_code)
    except ObjectDoesNotExist:
        audit_log.warning(
            f"Could not find nationality {code}",
            category="identity",
            action="update",
            outcome="failure",
            request=request,
            objects=[identity],
        )
        return False
    nationality = Nationality.objects.filter(identity=identity, country=country_obj).first()
    if not nationality:
        Nationality.objects.create(identity=identity, country=country_obj, verification_method=verification_method)
        audit_log.info(
            f"Added nationality {country_code} to identity {identity}",
            category="identity",
            action="update",
            outcome="success",
            request=request,
            objects=[identity, nationality],
        )
        return True
    elif nationality.verification_method < verification_method:
        nationality.verification_method = verification_method
        nationality.save()
        audit_log.info(
            f"Updated nationality {country_code} verification level to identity {identity}",
            category="identity",
            action="update",
            outcome="success",
            request=request,
            objects=[identity, nationality],
        )
        return True
    return False


def check_and_update_identity_attribute(
    request: HttpRequest,
    identity: Identity,
    attribute: str,
    new_value: Any,
    verification_method: Identity.VerificationMethod,
) -> bool:
    """
    Check and update identity attribute if it has changed.
    """
    if new_value is None:
        return False
    match attribute:
        case "given_names" | "surname":
            if new_value.isupper():
                new_value = new_value.title()
        case "date_of_birth":
            if isinstance(new_value, str):
                try:
                    new_value = datetime.strptime(new_value, "%Y-%m-%d").date()
                except ValueError:
                    return False
            if not isinstance(new_value, date):
                return False
        case "nationality":
            return add_nationality(request, identity, new_value, verification_method)
        case "gender":
            if new_value and new_value not in ["M", "F"]:
                new_value = "O"
        case "fpic":
            if (
                Identifier.objects.filter(type=Identifier.Type.FPIC, value=new_value)
                .exclude(identity=identity)
                .exists()
            ):
                audit_log.warning(
                    "FPIC already exists in the database",
                    category="identity",
                    action="update",
                    outcome="failure",
                    request=request,
                    objects=[identity],
                    extra={"sensitive": new_value},
                )
                messages.error(
                    request,
                    _("Suspected duplicate user. Finnish personal identity code already exists in the database: ")
                    + new_value,
                )
                return False
    changed = False
    current_value = getattr(identity, attribute, None)
    current_verification_method = getattr(identity, f"{attribute}_verification", None)
    if (
        new_value
        and current_value != new_value
        and (current_verification_method is None or current_verification_method <= verification_method.value)
    ):
        setattr(identity, attribute, new_value)
        changed = True
    if current_verification_method is not None and current_verification_method < verification_method.value:
        setattr(identity, f"{attribute}_verification", verification_method)
        changed = True
    return changed


def update_identity_attributes(
    request: HttpRequest,
    identity: Identity,
    attributes: dict[str, str | date | None],
    verification_method: Identity.VerificationMethod,
) -> None:
    """
    Update identity attributes if they have changed.
    Attributes are provided as a list of tuples (attribute_name, new_value).
    """
    modified = []
    for attribute, value in attributes.items():
        if check_and_update_identity_attribute(request, identity, attribute, value, verification_method):
            modified.append(attribute)
    if modified:
        try:
            identity.save()
        except IntegrityError as e:
            audit_log.warning(
                "FPIC already exists in the database",
                category="identity",
                action="update",
                outcome="failure",
                request=request,
                objects=[identity],
                extra={"sensitive": str(e)},
            )
            return
        audit_log.info(
            f"Updated identity attributes: {', '.join(modified)}",
            category="identity",
            action="update",
            outcome="success",
            request=request,
            objects=[identity],
            log_to_db=True,
        )


def add_account_messages(request: HttpRequest, activable_accounts: list[dict[str, str]], identity: Identity) -> None:
    """
    Add messages for accounts you can activate.
    """
    url_validator = URLValidator(schemes=("http", "https"))

    for account in activable_accounts:
        message = _('You can activate a new user account of type "%(account_type)s".') % {
            "account_type": account.get("name", "")
        }
        if account.get("action") == "create":
            if request.user == identity.user:
                link_text = _("Activate account")
                link = reverse(
                    "account-create", kwargs={"identity_pk": identity.pk, "account_type": account.get("type")}
                )
                message = (
                    f'<p class="fw-bold">{message}</p>' + f'<a href="{link}" class="btn btn-success">{link_text}</a>'
                )
            messages.add_message(request, messages.WARNING, message, extra_tags="safe")
        else:
            action = account.get("action", "")
            try:
                url_validator(action)
            except ValidationError:
                continue
            if request.user == identity.user:
                link_text = _("Continue to external service to activate account")
                link = action
                message = (
                    f'<p class="fw-bold">{message}</p>' + f'<a href="{link}" class="btn btn-success">{link_text}</a>'
                )
            messages.add_message(request, messages.WARNING, message, extra_tags="safe")
