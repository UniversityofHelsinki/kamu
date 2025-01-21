"""
Helper functions for the identity
"""

from datetime import datetime
from typing import TYPE_CHECKING, Callable

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.http import HttpRequest
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from kamu.connectors.ldap import LDAP_SIZELIMIT_EXCEEDED, ldap_search
from kamu.models.contract import Contract
from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.models.membership import Membership
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
                "Cannot combine two identities with Finnish Personal Identity Code. Please remove FPIC from the "
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
                f"Identity transfer: { attribute } from identity: { secondary_identity.pk }",
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
            # the foreign key part here seems to be too hard for static checking
            obj.identity = primary_identity  # type: ignore[assignment]
            obj.save()
            audit_log.info(
                f"Identity transfer: { log_category } from identity: { secondary_identity.pk }",
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
            f"Email address added to identity { identity }",
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
            f"Linked { identifier.type } identifier to identity { identity }",
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
