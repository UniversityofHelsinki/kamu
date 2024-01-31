"""
Helper functions for the identity app
"""

from django.contrib import messages
from django.db import IntegrityError
from django.http import HttpRequest
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from base.utils import AuditLog
from identity.models import Contract, EmailAddress, Identifier, Identity, PhoneNumber
from role.models import Membership

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
    assurance_choices = {
        "none": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
    }
    if assurance_choices[secondary_identity.assurance_level] > assurance_choices[primary_identity.assurance_level]:
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
                "Cannot combine two identities with Finnish Personal Identity Code. Please remove FPIC from the source first."
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

    def _combine_identity_attribute(attribute: str) -> None:
        """
        Combine an attribute from two identities.

        Copy attribute from secondary identity to primary identity, if primary identity does not have it.
        """
        if not getattr(primary_identity, attribute) and getattr(secondary_identity, attribute):
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
    if primary_identity.gender == "U" and secondary_identity.gender != "U":
        primary_identity.gender = secondary_identity.gender
        primary_identity.save()
        audit_log.info(
            f"Identity transfer: gender from identity: { secondary_identity.pk }",
            category="identity",
            action="update",
            outcome="success",
            request=request,
            objects=[primary_identity],
            log_to_db=True,
            extra={"secondary_identity": secondary_identity.pk},
        )


def combine_identities(request: HttpRequest, primary_identity: Identity, secondary_identity: Identity) -> None:
    """
    Combine two identities.

    Move all contracts, identifiers and memberships from secondary identity to primary identity.
    """
    _combine_identity_attributes(request, primary_identity, secondary_identity)
    # Move email addresses, skip duplicates (IntegrityError)
    for email in EmailAddress.objects.filter(identity=secondary_identity):
        try:
            email.identity = primary_identity
            email.save()
            audit_log.info(
                f"Identity transfer: email address from identity: { secondary_identity.pk }",
                category="email_address",
                action="update",
                outcome="success",
                request=request,
                objects=[email, primary_identity],
                log_to_db=True,
                extra={"secondary_identity": secondary_identity.pk},
            )
        except IntegrityError:
            pass
    # Move phone numbers, skip duplicates (IntegrityError)
    for phone in PhoneNumber.objects.filter(identity=secondary_identity):
        try:
            phone.identity = primary_identity
            phone.save()
            audit_log.info(
                f"Identity transfer: phone number from identity: { secondary_identity.pk }",
                category="phone_number",
                action="update",
                outcome="success",
                request=request,
                objects=[phone, primary_identity],
                log_to_db=True,
                extra={"secondary_identity": secondary_identity.pk},
            )
        except IntegrityError:
            pass
    # Move contracts, if contract does not yet exist. (IntegrityError)
    for contract in Contract.objects.filter(identity=secondary_identity):
        try:
            contract.identity = primary_identity
            contract.save()
            audit_log.info(
                f"Identity transfer: contract from identity: { secondary_identity.pk }",
                category="contract",
                action="update",
                outcome="success",
                request=request,
                objects=[contract, primary_identity],
                log_to_db=True,
                extra={"secondary_identity": secondary_identity.pk},
            )
        except IntegrityError:
            pass
    # Move identifiers
    for identifier in Identifier.objects.filter(identity=secondary_identity):
        identifier.identity = primary_identity
        identifier.save()
        audit_log.info(
            f"Identity transfer: identifier from identity: { secondary_identity.pk }",
            category="identifier",
            action="update",
            outcome="success",
            request=request,
            objects=[identifier, primary_identity],
            log_to_db=True,
            extra={"secondary_identity": secondary_identity.pk},
        )
    # Move memberships
    for membership in Membership.objects.filter(identity=secondary_identity):
        membership.identity = primary_identity
        membership.save()
        audit_log.info(
            f"Identity transfer: membership from identity: { secondary_identity.pk }",
            category="membership",
            action="update",
            outcome="success",
            request=request,
            objects=[membership, primary_identity],
            log_to_db=True,
            extra={"secondary_identity": secondary_identity.pk},
        )
    # Copy kamu_id as identifier to primary identity
    Identifier.objects.create(
        identity=primary_identity,
        type="kamu",
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
