from datetime import datetime, timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.models import AbstractUser, AnonymousUser
from django.contrib.auth.models import User as UserType
from django.core.exceptions import PermissionDenied
from django.db.models import Q, QuerySet
from django.http import HttpRequest
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_stubs_ext import StrOrPromise

from kamu.models.contract import ContractTemplate
from kamu.models.identity import Identity
from kamu.models.membership import Membership
from kamu.models.role import Requirement
from kamu.models.token import Token
from kamu.utils.audit import AuditLog

audit_log = AuditLog()


def _get_base_membership_queryset(user: AbstractUser, include_inviters: bool = False) -> QuerySet[Membership]:
    """
    Filter membership lists based on user role.
    """
    groups = user.groups.all()
    queryset = Membership.objects.all()
    if not user.is_superuser:
        if include_inviters:
            queryset = queryset.filter(
                Q(role__approvers__in=groups) | Q(role__inviters__in=groups) | Q(role__owner=user)
            ).distinct()
        else:
            queryset = queryset.filter(Q(role__approvers__in=groups) | Q(role__owner=user)).distinct()
    return queryset


def get_memberships_requiring_approval(user: AbstractUser, include_inviters: bool = False) -> QuerySet[Membership]:
    """
    Get memberships that require approval and user has approval rights for.
    """
    queryset = _get_base_membership_queryset(user, include_inviters)
    queryset = queryset.filter(
        expire_date__gte=timezone.now().date(),
        approver=None,
        cancelled_at=None,
    )
    return queryset.order_by("start_date").prefetch_related("identity", "role")


def get_expiring_memberships(
    user: AbstractUser, days: int | None = None, include_inviters: bool = False
) -> QuerySet[Membership]:
    """
    Get memberships that are about to end and user has approval rights for.
    """
    queryset = _get_base_membership_queryset(user, include_inviters)
    if not days:
        days = getattr(settings, "EXPIRING_LIMIT_DAYS", 30)
    queryset = queryset.filter(
        cancelled_at=None,
        expire_date__gte=timezone.now().date(),
        expire_date__lte=timezone.now().date() + timedelta(days=days),
    )
    return queryset.order_by("expire_date").prefetch_related("identity", "role")


def add_missing_requirement_messages(
    request: HttpRequest, missing_requirements: QuerySet[Requirement], identity: Identity
) -> None:
    """
    Add messages for missing requirements to the request.
    """

    def _get_link(url_name: str, text: StrOrPromise, kwargs: dict[str, int]) -> str:
        """
        Add link to the message.
        """
        url = reverse(url_name, kwargs=kwargs)
        notification = _(
            "<p>Membership and privileges (e.g., a user account) activate only after the required action is "
            "completed.</p>"
        )
        return f'{notification}<a href="{url}" class="btn btn-success">{text}</a>'

    def _add_contract_message() -> None:
        """
        Add missing contract message to the request. Add link if the user is the identity owner.
        """
        template = (
            ContractTemplate.objects.filter(type=requirement.value, version__gte=requirement.level)
            .order_by("-version")
            .first()
        )
        if not template:
            messages.add_message(
                request,
                messages.ERROR,
                _("Role requires a contract you cannot currently sign."),
            )
        else:
            message = _('Role requires a signed contract: "%(name)s".') % {"name": template.name()}
            if requirement.level:
                message = _('Role requires a signed contract "%(name)s", version %(version)d or higher.') % {
                    "name": template.name(),
                    "version": requirement.level,
                }
            if request.user == identity.user:
                link = _get_link(
                    "contract-sign", _("Review and sign"), {"identity_pk": identity.pk, "template_pk": template.pk}
                )
                message = f'<p class="fw-bold">{message}</p>{link}'
            messages.add_message(request, messages.WARNING, message, extra_tags="safe")

    def _add_attribute_message() -> None:
        """
        Add missing attribute message to the request.

        Add link if the user is the identity owner or has identity change permissions.
        """
        message: StrOrPromise = ""
        if requirement.value == "email_address":
            message = _("Role requires a verified email address.")
            if request.user == identity.user:
                link = _get_link("contact-change", _("Add and verify email address"), {"pk": identity.pk})
                message = f'<p class="fw-bold">{message}</p>{link}'
            messages.add_message(request, messages.WARNING, message, extra_tags="safe")
            return
        if requirement.value == "phone_number":
            message = _("Role requires a verified phone number.")
            if request.user == identity.user:
                link = _get_link("contact-change", _("Add and verify phone number"), {"pk": identity.pk})
                message = f'<p class="fw-bold">{message}</p>{link}'
            messages.add_message(request, messages.WARNING, message, extra_tags="safe")
            return
        field = Identity._meta.get_field(requirement.value)
        if hasattr(field, "verbose_name"):
            name = field.verbose_name.lower()
        else:
            name = requirement.value
        if requirement.level:
            level_text = Identity.get_verification_level_display_by_value(requirement.level)
            message = _(
                'Role requires an attribute "%(name)s" of at least verification level: %(level)d (%(level_text)s).'
            ) % {
                "name": name,
                "level": requirement.level,
                "level_text": level_text,
            }
        else:
            message = _('Role requires an attribute "%(name)s".') % {"name": name}
        if request.user == identity.user or request.user.has_perm("kamu.change_restricted_information"):
            link = _get_link("identity-change", _("Add %(name)s") % {"name": name}, {"pk": identity.pk})
            message = f'<p class="fw-bold">{message}</p>{link}'
        messages.add_message(request, messages.WARNING, message, extra_tags="safe")

    for requirement in missing_requirements:
        if requirement.type == Requirement.Type.ASSURANCE:
            level_text = Identity.get_assurance_level_display_by_value(requirement.level)
            messages.add_message(
                request,
                messages.WARNING,
                _("Role requires higher assurance level: " + str(requirement.level) + " (" + level_text + ")."),
            )
        elif requirement.type == Requirement.Type.CONTRACT:
            _add_contract_message()
        elif requirement.type == Requirement.Type.ATTRIBUTE:
            _add_attribute_message()
        else:
            messages.add_message(
                request,
                messages.ERROR,
                _("Role requires a requirement you cannot currently fulfill: %(name)s.")
                % {"name": requirement.name()},
            )


def get_invitation_session_parameters(request: HttpRequest) -> tuple[str, datetime]:
    """
    Get invitation session parameters from request.

    Raises PermissionDenied if session parameters are missing or have an invalid format. This is used for
    access control.
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


def _get_membership(membership_pk: int | str) -> Membership:
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


def _remove_session_parameters(request: HttpRequest) -> None:
    """
    Remove invitation code and time from session.
    """
    for parameter in ["invitation_code", "invitation_code_time"]:
        try:
            del request.session[parameter]
        except KeyError:
            pass


def claim_membership(request: HttpRequest, identity: Identity) -> int:
    """
    Tries to claim a membership with invitation code.

    Returns membership pk, or -1 if the invitation code has been expired or membership has already been claimed.

    Raises PermissionDenied if the invitation code is missing or invalid.
    """
    invitation_code, invitation_time = get_invitation_session_parameters(request)
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
    audit_log.info(
        f"Membership to role {membership.role.identifier} linked to identity: {identity}",
        category="membership",
        action="link",
        outcome="success",
        request=request,
        objects=[membership, identity, membership.role],
        log_to_db=True,
    )
    return membership.pk


def get_mass_invite_limit(user: UserType | AnonymousUser) -> int:
    """
    Return invite limit for user.
    """
    if not user or not user.is_authenticated:
        return 0
    permission_groups = getattr(settings, "MASS_INVITE_PERMISSION_GROUPS", {})
    user_groups = user.groups.values_list("name", flat=True)
    limit = 0
    for group in user_groups:
        value = permission_groups.get(group, 0)
        if value > limit:
            limit = value
    return limit
