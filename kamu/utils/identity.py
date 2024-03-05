"""
Helper functions for the identity
"""

from typing import TYPE_CHECKING, Callable

from django.contrib import messages
from django.db import IntegrityError
from django.http import HttpRequest
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from kamu.models.contract import Contract
from kamu.models.identity import EmailAddress, Identifier, Identity, PhoneNumber
from kamu.models.membership import Membership
from kamu.utils.audit import AuditLog

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
