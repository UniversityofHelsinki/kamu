from django.conf import settings
from django.core.mail import send_mail
from django.db.models import QuerySet
from django.http import HttpRequest
from django.template.exceptions import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import translation
from django.utils.translation import gettext_lazy as _

from kamu.models.membership import Membership
from kamu.models.role import Role


def _send_email(subject: str, message: str, recipient_list: list[str], from_email: str | None = None) -> bool:
    """
    Send email using Django's send_email function, returning success as bool.

    Use TOKEN_FROM_EMAIL as default.
    """
    if not from_email:
        from_email = getattr(settings, "TOKEN_FROM_EMAIL", None)
    if send_mail(subject, message, from_email, recipient_list, fail_silently=True):
        return True
    return False


def _get_link_url(request: HttpRequest | None = None, view_name: str = "front-page") -> str | None:
    """
    Get link URL for email messages.

    Use base from the settings if available, otherwise build from request or return None.
    """
    service_link_url = getattr(settings, "SERVICE_LINK_URL", None)
    if service_link_url:
        return service_link_url + reverse(view_name)
    elif request:
        return request.build_absolute_uri(reverse(view_name))
    return None


def send_add_email(membership: Membership) -> bool:
    """
    Send an email notification of the role membership.
    """
    cur_language = translation.get_language()
    if not membership or not membership.identity:
        return False
    address = membership.identity.email_addresses.first()
    if not address:
        return False
    lang = membership.identity.preferred_language
    inviter = membership.inviter.get_full_name() if membership.inviter else None
    try:
        translation.activate(lang)
        subject = render_to_string("email/membership_add_subject.txt")
        message = render_to_string(
            "email/membership_add_message.txt",
            {
                "inviter": inviter,
                "role": membership.role.name(),
            },
        )
    finally:
        translation.activate(cur_language)
    return _send_email(subject, message, recipient_list=[address.address])


def send_notify_approvers_email(membership: Membership, member_list: list[str] | None = None) -> bool:
    """
    Send an email notification to role notification address about the new membership invite requiring approval.
    """
    cur_language = translation.get_language()
    if not membership or not membership.role.notification_email_address:
        return False
    lang = membership.role.notification_language
    inviter = membership.inviter.get_full_name() if membership.inviter else None
    try:
        translation.activate(lang)
        if member_list and len(member_list) > 1:
            member = _("%(number)s new members") % {"number": len(member_list)}
        else:
            member = (
                membership.identity.display_name() if membership.identity else str(membership.invite_email_address)
            )
        subject = render_to_string(
            "email/membership_require_approval_role_subject.txt",
            {
                "role": membership.role.name(),
            },
        )
        message = render_to_string(
            "email/membership_require_approval_role_message.txt",
            {
                "inviter": inviter,
                "member": member,
                "role": membership.role.name(),
            },
        )
    except TemplateDoesNotExist:
        return False
    finally:
        translation.activate(cur_language)
    return _send_email(subject, message, recipient_list=[membership.role.notification_email_address])


def create_invite_message(
    role: Role, inviter: str, token: str, invite_text: str, lang: str = "en", request: HttpRequest | None = None
) -> tuple[str, str]:
    """
    Create an invitation message for the membership.
    """
    cur_language = translation.get_language()
    link_url = _get_link_url(request, "login-invite")
    try:
        translation.activate(lang)
        subject = render_to_string("email/invite_email_subject.txt")
        message = render_to_string(
            "email/invite_email_message.txt",
            {
                "inviter": inviter,
                "role": role.name(),
                "invite_text": invite_text,
                "token": token,
                "link_url": link_url,
            },
        )
    finally:
        translation.activate(cur_language)
    return subject, message


def send_invite_email(
    membership: Membership,
    token: str,
    address: str,
    invite_text: str,
    lang: str = "en",
    request: HttpRequest | None = None,
) -> bool:
    """
    Send a role invite by email.
    """
    inviter = membership.inviter.get_full_name() if membership.inviter else ""
    role = membership.role
    subject, message = create_invite_message(role, inviter, token, invite_text, lang, request)
    return _send_email(subject, message, recipient_list=[address])


def send_verification_email(
    token: str, email_address: str, lang: str = "en", template: str = "verification_email"
) -> bool:
    """
    Send a verification email.
    """

    cur_language = translation.get_language()
    try:
        translation.activate(lang)
        subject = render_to_string(f"email/{template}_subject.txt")
        message = render_to_string(f"email/{template}_message.txt", {"token": token})
    except TemplateDoesNotExist:
        return False
    finally:
        translation.activate(cur_language)
    return _send_email(subject, message, recipient_list=[email_address])


def send_expiration_notification_to_member(membership: Membership, email_address: str, lang: str = "en") -> bool:
    """
    Send a verification email.
    """

    inviter = membership.inviter.get_full_name() if membership.inviter else None
    approver = membership.approver.get_full_name() if membership.approver else None
    cur_language = translation.get_language()
    try:
        translation.activate(lang)
        subject = render_to_string("email/expire_notification_member_subject.txt")
        message = render_to_string(
            "email/expire_notification_member_message.txt",
            {
                "role": membership.role.name(),
                "expire_date": membership.expire_date,
                "inviter": inviter,
                "approver": approver,
            },
        )
    except TemplateDoesNotExist:
        return False
    finally:
        translation.activate(cur_language)
    return _send_email(subject, message, recipient_list=[email_address])


def send_expiration_notification_to_role(
    role: Role, memberships: QuerySet[Membership], email_address: str, lang: str = "en"
) -> bool:
    """
    Send a verification email.
    """

    cur_language = translation.get_language()
    try:
        translation.activate(lang)
        subject = render_to_string("email/expire_notification_role_subject.txt", {"role": role.name()})
        message = render_to_string(
            "email/expire_notification_role_message.txt",
            {"role": role.name(), "number_of_memberships": memberships.count()},
        )
    except TemplateDoesNotExist:
        return False
    finally:
        translation.activate(cur_language)
    return _send_email(subject, message, recipient_list=[email_address])
