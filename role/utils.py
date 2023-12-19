from datetime import datetime

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from base.models import Token
from role.models import Membership


def _get_invitation_session_parameters(request) -> tuple[str, datetime]:
    """
    Get invitation session parameters from request.
    """
    if "invitation_code" not in request.session or not request.session["invitation_code"]:
        raise PermissionDenied
    if "invitation_code_time" not in request.session or not request.session["invitation_code_time"]:
        raise PermissionDenied
    invitation_code = request.session["invitation_code"]
    invitation_code_time = request.session["invitation_code_time"]
    try:
        invitation_time = datetime.fromisoformat(invitation_code_time)
    except ValueError:
        raise PermissionDenied
    if not isinstance(invitation_code, str) or len(invitation_code.split(":")) != 2:
        raise PermissionDenied
    return invitation_code, invitation_time


def _get_membership(membership_pk) -> Membership:
    """
    Parse membership from pk value.
    """
    try:
        int(membership_pk)
    except ValueError:
        raise PermissionDenied
    try:
        membership = Membership.objects.get(pk=membership_pk)
    except Membership.DoesNotExist:
        raise PermissionDenied
    return membership


def _remove_session_parameters(request) -> None:
    del request.session["invitation_code"]
    del request.session["invitation_code_time"]


def claim_membership(request, identity) -> int:
    """
    Tries to claim a membership with invitation code.

    Returns membership pk, or -1 if the invitation code has been expired or membership has already been claimed.

    Raises PermissionDenied if the invitation code is missing or invalid.
    """
    invitation_code, invitation_time = _get_invitation_session_parameters(request)
    if (timezone.now() - invitation_time).total_seconds() > getattr(settings, "INVITATION_PROCESS_TIME", 60 * 60):
        messages.add_message(request, messages.WARNING, _("Invitation process has taken too long."))
        _remove_session_parameters(request)
        return -1
    membership_pk, secret = invitation_code.split(":", 1)
    membership = _get_membership(membership_pk)
    if membership.identity:
        messages.add_message(request, messages.WARNING, _("This invitation has already been used."))
        _remove_session_parameters(request)
        return -1
    if membership.expire_date < timezone.now().date():
        messages.add_message(request, messages.WARNING, _("This invitation has expired."))
        _remove_session_parameters(request)
        return -1
    if not Token.objects.validate_invite_token(secret, membership=membership, remove_token=True):
        messages.add_message(request, messages.WARNING, _("Invalid invitation token."))
        raise PermissionDenied
    membership.identity = identity
    messages.add_message(request, messages.INFO, _("Membership created."))
    membership.save()
    _remove_session_parameters(request)
    return membership.pk
