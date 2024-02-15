from django.conf import settings
from django.core.mail import send_mail
from django.http import HttpRequest
from django.template.exceptions import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import translation

from kamu.models.role import Membership


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


def send_invite_email(
    membership: Membership, token: str, address: str, lang: str = "en", request: HttpRequest | None = None
) -> bool:
    """
    Send a role invite by email.
    """
    cur_language = translation.get_language()
    link_url = _get_link_url(request, "login-invite")
    inviter = membership.inviter.get_full_name() if membership.inviter else None
    try:
        translation.activate(lang)
        subject = render_to_string("email/invite_email_subject.txt")
        message = render_to_string(
            "email/invite_email_message.txt",
            {
                "inviter": inviter,
                "role": membership.role.name(),
                "token": token,
                "link_url": link_url,
            },
        )
    finally:
        translation.activate(cur_language)
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
        subject = render_to_string(f"email/{ template }_subject.txt")
        message = render_to_string(f"email/{ template }_message.txt", {"token": token})
    except TemplateDoesNotExist:
        return False
    finally:
        translation.activate(cur_language)
    return _send_email(subject, message, recipient_list=[email_address])
